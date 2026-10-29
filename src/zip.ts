import type { SourceFile } from './scanner'
import { MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_COMPRESSION_RATIO, MAX_EXTRACTED_BYTES, MAX_SOURCE_FILE_BYTES, formatMegabytes } from './limits'

const MAX_BYTES = MAX_ARCHIVE_BYTES
const MAX_ENTRIES = MAX_ARCHIVE_ENTRIES
const MAX_OUTPUT = MAX_EXTRACTED_BYTES
const MAX_FILE = MAX_SOURCE_FILE_BYTES
const MAX_RATIO = MAX_COMPRESSION_RATIO
const MAX_SKIPPED_DETAILS = 500
const READ_CHUNK = 64 * 1024
const IGNORED = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache',
  '.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
  '.tox', '.turbo', '.nuxt', '.svelte-kit', '.parcel-cache', 'target', 'out',
])
const TEXT = /\.(?:[cm]?js|jsx|[cm]?ts|tsx|py|rb|go|java|kt|kts|php|rs|c|h|cc|cpp|hpp|cs|swift|dart|scala|sh|bash|zsh|ps1|sql|json|json5|jsonc|ya?ml|toml|ini|conf|config|env|properties|gradle|groovy|xml|html?|css|scss|sass|less|vue|svelte|astro|graphql|gql|prisma|tf|tfvars|md|txt|lock|pem)$/i
const SPECIAL = /^(?:\.env(?:\..+)?|\.nvmrc|\.node-version|\.python-version|\.ruby-version|\.tool-versions|Dockerfile(?:\..+)?|Containerfile|Procfile|Gemfile|Pipfile|go\.mod|go\.sum|\.npmrc|\.yarnrc(?:\.yml)?)$/i
export const isSupportedText = (path: string) => TEXT.test(path) || SPECIAL.test(path.split('/').pop() ?? '')
export const isIgnoredPath = (path: string) => path.split('/').some((segment) => IGNORED.has(segment.toLowerCase()))

type Entry = { path: string; directory: boolean; method: number; size: number; compressed: number; crc: number; start: number; end: number; offset: number }
export type ZipReadOptions = { collect?: boolean; onFile?: (file: SourceFile) => void }
export type ZipProgress = (phase: string, progress?: number) => void
export type ZipReadResult = { files: SourceFile[]; skipped: string[]; skippedCount: number; entryCount: number }
type ByteSource = { size: number; read: (start: number, length: number) => Promise<Uint8Array<ArrayBuffer>> }

const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  return value >>> 0
})
function updateCrc(crc: number, bytes: Uint8Array) {
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 255] ^ (crc >>> 8)
  return crc
}
const checksum = (bytes: Uint8Array) => (updateCrc(-1, bytes) ^ -1) >>> 0
const malformed = (details: string): never => { throw new Error(`The archive could not be opened: ${details}`) }
function decode(bytes: Uint8Array): string {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes) }
  catch { return malformed('only valid UTF-8 ZIP filenames are supported.') }
}
function safePath(raw: string): string {
  const path = raw.replaceAll('\\', '/')
  const segments = path.replace(/\/$/, '').split('/')
  if (!path || path.startsWith('/') || /[:\x00-\x1f\x7f]/.test(path) || segments.some((part) => !part || part === '.' || part === '..' || /[. ]$/.test(part))) {
    throw new Error(`Unsafe archive path rejected: ${JSON.stringify(raw)}`)
  }
  return path
}

function blobSource(blob: Blob): ByteSource {
  return {
    size: blob.size,
    async read(start, length) {
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0 || start + length > blob.size) {
        return malformed('invalid archive read bounds.')
      }
      return new Uint8Array(await blob.slice(start, start + length).arrayBuffer())
    },
  }
}

function reader(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const require = (offset: number, length: number, limit = bytes.length) => {
    if (offset < 0 || length < 0 || offset + length > limit) malformed('truncated or overlapping ZIP records.')
  }
  return {
    require,
    u16: (offset: number) => { require(offset, 2); return view.getUint16(offset, true) },
    u32: (offset: number) => { require(offset, 4); return view.getUint32(offset, true) },
  }
}

// Parse the original central AND local records before constructing any inflater.
// The archive is read through bounded Blob slices so a 100 MB ZIP does not have
// to be duplicated in memory as one contiguous JavaScript buffer.
// ZIP layout: PKWARE APPNOTE 6.3.10, sections 4.3.7, 4.3.9, 4.3.12 and 4.3.16.
async function preflight(source: ByteSource): Promise<Entry[]> {
  if (source.size < 22) malformed('missing ZIP end record.')
  const tailLength = Math.min(source.size, 65_557)
  const tail = await source.read(source.size - tailLength, tailLength)
  const t = reader(tail)
  let eocdLocal = -1
  for (let offset = tail.length - 22; offset >= 0; offset--) {
    if (t.u32(offset) === 0x06054b50 && offset + 22 + t.u16(offset + 20) === tail.length) { eocdLocal = offset; break }
  }
  if (eocdLocal < 0) malformed('missing ZIP end record.')
  if (t.u16(eocdLocal + 4) || t.u16(eocdLocal + 6) || t.u16(eocdLocal + 8) !== t.u16(eocdLocal + 10)) malformed('multi-disk ZIPs are unsupported.')
  const count = t.u16(eocdLocal + 10)
  const directorySize = t.u32(eocdLocal + 12)
  const directoryStart = t.u32(eocdLocal + 16)
  if (count === 0xffff || directorySize === 0xffffffff || directoryStart === 0xffffffff) malformed('ZIP64 archives are unsupported.')
  if (count > MAX_ENTRIES) throw new Error(`This archive contains more than ${MAX_ENTRIES.toLocaleString('en-US')} files or directory entries.`)
  const eocd = source.size - tailLength + eocdLocal
  if (directoryStart + directorySize !== eocd) malformed('invalid central directory bounds; ZIP64 and self-extracting archives are unsupported.')

  const directory = await source.read(directoryStart, directorySize)
  const d = reader(directory)
  const extra = (buffer: Uint8Array, start: number, length: number, name: Uint8Array, path: string) => {
    const { require, u16, u32 } = reader(buffer)
    const end = start + length
    require(start, length)
    while (start < end) {
      require(start, 4, end)
      const id = u16(start), size = u16(start + 2)
      start += 4
      require(start, size, end)
      if (id === 1) malformed('ZIP64 entries are unsupported.')
      if (id === 0x7075) {
        if (size < 5 || buffer[start] !== 1 || u32(start + 1) !== checksum(name)) malformed('invalid Unicode path metadata.')
        const alternative = safePath(decode(buffer.subarray(start + 5, start + size)))
        if (alternative !== path) malformed('ambiguous Unicode path metadata.')
      }
      start += size
    }
  }

  const entries: Entry[] = []
  const names = new Set<string>()
  let cursor = 0, total = 0
  while (cursor < directory.length) {
    if (entries.length >= MAX_ENTRIES) throw new Error(`This archive contains more than ${MAX_ENTRIES.toLocaleString('en-US')} files or directory entries.`)
    d.require(cursor, 46, directory.length)
    if (d.u32(cursor) !== 0x02014b50) malformed('invalid central directory record.')
    const flags = d.u16(cursor + 8), method = d.u16(cursor + 10)
    if (flags & ~0x080e) malformed('encrypted or unsupported ZIP flags.')
    if (method !== 0 && method !== 8) malformed(`unsupported compression method ${method}.`)
    const crc = d.u32(cursor + 16), compressed = d.u32(cursor + 20), size = d.u32(cursor + 24)
    const nameLength = d.u16(cursor + 28), extraLength = d.u16(cursor + 30), commentLength = d.u16(cursor + 32)
    const offset = d.u32(cursor + 42)
    if (compressed === 0xffffffff || size === 0xffffffff || offset === 0xffffffff) malformed('ZIP64 entries are unsupported.')
    if (d.u16(cursor + 34)) malformed('multi-disk entries are unsupported.')
    d.require(cursor + 46, nameLength + extraLength + commentLength, directory.length)
    const name = directory.subarray(cursor + 46, cursor + 46 + nameLength)
    const path = safePath(decode(name))
    const key = path.replace(/\/$/, '').normalize('NFC').toLowerCase()
    if (names.has(key)) malformed(`duplicate or ambiguous archive path: ${path}`)
    names.add(key)
    extra(directory, cursor + 46 + nameLength, extraLength, name, path)
    const attributes = d.u32(cursor + 38), kind = (attributes >>> 16) & 0xf000
    if (kind && kind !== 0x8000 && kind !== 0x4000) malformed(`symlinks and special files are unsupported: ${path}`)
    const directoryEntry = path.endsWith('/')
    if ((kind === 0x4000 || (attributes & 0x10)) && !directoryEntry) malformed(`ambiguous directory path: ${path}`)
    if (directoryEntry && (size || compressed)) malformed(`directory contains file data: ${path}`)
    total += size
    if (total > MAX_OUTPUT) throw new Error(`The archive expands beyond the ${formatMegabytes(MAX_OUTPUT)} safety limit.`)
    if (isSupportedText(path) && size > MAX_FILE) throw new Error(`Source file is larger than the ${formatMegabytes(MAX_FILE)} per-file limit: ${path}`)
    if (size > Math.max(compressed, 1) * MAX_RATIO) throw new Error(`Archive compression ratio is unsafe for: ${path}`)
    if (method === 0 && size !== compressed) malformed(`stored size mismatch: ${path}`)

    if (offset < 0 || offset + 30 > directoryStart) malformed(`invalid local header bounds: ${path}`)
    const header = await source.read(offset, 30)
    const h = reader(header)
    if (h.u32(0) !== 0x04034b50 || h.u16(6) !== flags || h.u16(8) !== method) malformed(`local header mismatch: ${path}`)
    const localNameLength = h.u16(26), localExtraLength = h.u16(28)
    if (offset + 30 + localNameLength + localExtraLength > directoryStart) malformed(`invalid local header bounds: ${path}`)
    const localTail = await source.read(offset + 30, localNameLength + localExtraLength)
    const localName = localTail.subarray(0, localNameLength)
    safePath(decode(localName))
    if (localName.length !== name.length || localName.some((byte, index) => byte !== name[index])) malformed(`local filename mismatch: ${path}`)
    extra(localTail, localNameLength, localExtraLength, localName, path)
    const descriptor = Boolean(flags & 8)
    for (const [local, central] of [[h.u32(14), crc], [h.u32(18), compressed], [h.u32(22), size]]) {
      if (local !== central && !(descriptor && local === 0)) malformed(`local size or CRC mismatch: ${path}`)
    }
    const start = offset + 30 + localNameLength + localExtraLength
    if (start + compressed > directoryStart) malformed(`invalid compressed data bounds: ${path}`)
    let end = start + compressed
    if (descriptor) {
      if (end + 12 > directoryStart) malformed(`invalid data descriptor: ${path}`)
      const descriptorBytes = await source.read(end, Math.min(16, directoryStart - end))
      const v = reader(descriptorBytes)
      let position = 0
      if (v.u32(0) === 0x08074b50) position = 4
      v.require(position, 12)
      if (v.u32(position) !== crc || v.u32(position + 4) !== compressed || v.u32(position + 8) !== size) malformed(`invalid data descriptor: ${path}`)
      end += position + 12
    }
    entries.push({ path, directory: directoryEntry, method, size, compressed, crc, start, end, offset })
    cursor += 46 + nameLength + extraLength + commentLength
  }
  if (cursor !== directory.length || entries.length !== count) malformed('central directory entry count mismatch.')
  let end = 0
  for (const entry of [...entries].sort((a, b) => a.offset - b.offset)) {
    if (entry.offset !== end) malformed('overlapping, unlisted, or prefixed local records.')
    end = entry.end
  }
  if (end !== directoryStart) malformed('unlisted local records or trailing data.')
  const fileNames = new Set(entries.filter((entry) => !entry.directory).map((entry) => entry.path.normalize('NFC').toLowerCase()))
  for (const entry of entries) {
    const parts = entry.path.split('/')
    for (let index = 1; index < parts.length; index++) {
      if (fileNames.has(parts.slice(0, index).join('/').normalize('NFC').toLowerCase())) malformed(`file/directory path collision: ${entry.path}`)
    }
  }
  return entries
}

async function extract(source: ByteSource, entry: Entry, budget: { bytes: number }, onBytes?: (bytes: number) => void): Promise<string> {
  let position = entry.start
  // Bounded compressed chunks limit inflater work/allocation even when sizes
  // lie. Backpressure prevents feeding a whole compressed bomb before output
  // checks, while Blob slices avoid retaining the complete archive in memory.
  const input = new ReadableStream<Uint8Array<ArrayBuffer>>({
    async pull(controller) {
      if (position >= entry.start + entry.compressed) { controller.close(); return }
      const end = Math.min(position + READ_CHUNK, entry.start + entry.compressed)
      const chunk = await source.read(position, end - position)
      if (!chunk.byteLength) throw new Error('The archive ended before the declared compressed entry size.')
      position = end
      onBytes?.(chunk.byteLength)
      controller.enqueue(chunk)
    },
  }, { highWaterMark: 0 })
  let stream = input
  if (entry.method === 8) {
    try { stream = input.pipeThrough(new DecompressionStream('deflate-raw')) }
    catch { throw new Error('This runtime does not support bounded deflate-raw ZIP decompression.') }
  }
  const reader = stream.getReader()
  const chunks: Uint8Array[] = []
  let size = 0, crc = -1
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      size += value.byteLength
      budget.bytes += value.byteLength
      if (size > MAX_FILE || budget.bytes > MAX_OUTPUT || size > entry.size || size > Math.max(entry.compressed, 1) * MAX_RATIO) {
        throw new Error(`Actual streamed output exceeds the ZIP safety limit or declared size: ${entry.path}`)
      }
      crc = updateCrc(crc, value)
      chunks.push(value)
    }
    if (size !== entry.size || ((crc ^ -1) >>> 0) !== entry.crc) throw new Error(`ZIP size or CRC integrity check failed: ${entry.path}`)
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally { reader.releaseLock() }
  const output = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length }
  return new TextDecoder('utf-8', { fatal: true }).decode(output)
}

export async function readSourceZip(file: File, onProgress?: ZipProgress, options: ZipReadOptions = {}): Promise<ZipReadResult> {
  onProgress?.('Validating archive headers and safety limits', 2)
  if (file.size > MAX_BYTES) throw new Error(`This archive is larger than the ${formatMegabytes(MAX_BYTES)} limit.`)
  if (!file.name.toLowerCase().endsWith('.zip')) throw new Error('Upload a .zip archive containing source code.')
  const source = blobSource(file)
  if (source.size > MAX_BYTES) throw new Error(`This archive is larger than the ${formatMegabytes(MAX_BYTES)} limit.`)
  onProgress?.('Reading the ZIP central directory', 5)
  const entries = await preflight(source)
  const files: SourceFile[] = [], skipped: string[] = []
  let skippedCount = 0, processed = 0, reported = -1
  const skip = (detail: string) => {
    skippedCount += 1
    if (skipped.length < MAX_SKIPPED_DETAILS) skipped.push(detail)
  }
  const eligible = entries.filter((entry) => !entry.directory && !isIgnoredPath(entry.path) && isSupportedText(entry.path))
  const extractable = eligible.reduce((sum, entry) => sum + entry.compressed, 0)
  const progress = () => {
    const value = extractable > 0 ? 10 + Math.floor((processed / extractable) * 65) : 75
    if (value !== reported) { reported = value; onProgress?.('Extracting supported text with streamed byte and CRC checks', value) }
  }
  const budget = { bytes: 0 }
  onProgress?.('Extracting supported text with streamed byte and CRC checks', 10)
  for (const entry of entries) {
    if (entry.directory) continue
    if (isIgnoredPath(entry.path)) {
      skip(`${entry.path}: ignored dependency/build/cache directory; content and CRC not inspected.`)
      continue
    }
    if (!isSupportedText(entry.path)) {
      skip(`${entry.path}: unsupported file type; content and CRC not inspected.`)
      continue
    }
    let content: string
    try { content = await extract(source, entry, budget, (bytes) => { processed += bytes; progress() }) }
    catch (error) {
      if (error instanceof TypeError && /encoded data|encoding/i.test(error.message)) {
        skip(`${entry.path}: non-UTF-8 text is unsupported.`)
        continue
      }
      throw new Error(`Archive extraction failed for ${entry.path}: ${error instanceof Error ? error.message : 'invalid compressed data'}`)
    }
    if (content.includes('\0')) { skip(`${entry.path}: binary content is unsupported.`); continue }
    const sourceFile = { path: entry.path, content }
    if (options.collect !== false) files.push(sourceFile)
    options.onFile?.(sourceFile)
  }
  if (skippedCount > skipped.length) skipped.push(`${skippedCount - skipped.length} additional skipped entries were omitted from this list to bound the result size.`)
  onProgress?.('Archive extraction complete', 78)
  return { files, skipped, skippedCount, entryCount: entries.length }
}
