import type { SourceFile } from './scanner'

const MAX_BYTES = 10 * 1024 * 1024
const MAX_ENTRIES = 350
const MAX_OUTPUT = 25 * 1024 * 1024
const MAX_FILE = 1_000_000
const MAX_RATIO = 1_000
const IGNORED = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache'])
const TEXT = /\.(?:[cm]?js|jsx|[cm]?ts|tsx|py|rb|go|java|php|json|ya?ml|env|sql|md|txt|toml|ini|conf|html|css|lock|xml|gradle|properties|sh)$/i
const SPECIAL = /^(?:\.env(?:\..+)?|\.nvmrc|\.node-version|\.python-version|\.ruby-version|\.tool-versions|Dockerfile(?:\..+)?|Containerfile|Procfile|Gemfile|Pipfile|go\.mod|go\.sum|\.npmrc|\.yarnrc(?:\.yml)?)$/i
export const isSupportedText = (path: string) => TEXT.test(path) || SPECIAL.test(path.split('/').pop() ?? '')

type Entry = { path: string; directory: boolean; method: number; size: number; compressed: number; crc: number; start: number; end: number; offset: number }
export type ZipReadResult = { files: SourceFile[]; skipped: string[]; entryCount: number }

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

// Parse the original central AND local records before constructing any inflater.
// ZIP layout: PKWARE APPNOTE 6.3.10, sections 4.3.7, 4.3.9, 4.3.12 and 4.3.16.
function preflight(bytes: Uint8Array): Entry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const requireBytes = (offset: number, length: number, limit = bytes.length) => {
    if (offset < 0 || length < 0 || offset + length > limit) malformed('truncated or overlapping ZIP records.')
  }
  const u16 = (offset: number) => { requireBytes(offset, 2); return view.getUint16(offset, true) }
  const u32 = (offset: number) => { requireBytes(offset, 4); return view.getUint32(offset, true) }
  let eocd = -1
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65_557); offset--) {
    if (u32(offset) === 0x06054b50 && offset + 22 + u16(offset + 20) === bytes.length) { eocd = offset; break }
  }
  if (eocd < 0) malformed('missing ZIP end record.')
  if (u16(eocd + 4) || u16(eocd + 6) || u16(eocd + 8) !== u16(eocd + 10)) malformed('multi-disk ZIPs are unsupported.')
  const count = u16(eocd + 10)
  const directorySize = u32(eocd + 12)
  const directoryStart = u32(eocd + 16)
  if (count === 0xffff || directorySize === 0xffffffff || directoryStart === 0xffffffff) malformed('ZIP64 archives are unsupported.')
  if (count > MAX_ENTRIES) throw new Error(`This archive contains more than ${MAX_ENTRIES} files or directory entries.`)
  if (directoryStart + directorySize !== eocd) malformed('invalid central directory bounds; ZIP64 and self-extracting archives are unsupported.')

  const extra = (start: number, length: number, name: Uint8Array, path: string) => {
    const end = start + length
    requireBytes(start, length)
    while (start < end) {
      requireBytes(start, 4, end)
      const id = u16(start), size = u16(start + 2)
      start += 4
      requireBytes(start, size, end)
      if (id === 1) malformed('ZIP64 entries are unsupported.')
      if (id === 0x7075) {
        if (size < 5 || bytes[start] !== 1 || u32(start + 1) !== checksum(name)) malformed('invalid Unicode path metadata.')
        const alternative = safePath(decode(bytes.subarray(start + 5, start + size)))
        if (alternative !== path) malformed('ambiguous Unicode path metadata.')
      }
      start += size
    }
  }

  const entries: Entry[] = []
  const names = new Set<string>()
  let cursor = directoryStart, total = 0
  while (cursor < eocd) {
    if (entries.length >= MAX_ENTRIES) throw new Error(`This archive contains more than ${MAX_ENTRIES} files or directory entries.`)
    requireBytes(cursor, 46, eocd)
    if (u32(cursor) !== 0x02014b50) malformed('invalid central directory record.')
    const flags = u16(cursor + 8), method = u16(cursor + 10)
    if (flags & ~0x080e) malformed('encrypted or unsupported ZIP flags.')
    if (method !== 0 && method !== 8) malformed(`unsupported compression method ${method}.`)
    const crc = u32(cursor + 16), compressed = u32(cursor + 20), size = u32(cursor + 24)
    const nameLength = u16(cursor + 28), extraLength = u16(cursor + 30), commentLength = u16(cursor + 32)
    const offset = u32(cursor + 42)
    if (compressed === 0xffffffff || size === 0xffffffff || offset === 0xffffffff) malformed('ZIP64 entries are unsupported.')
    if (u16(cursor + 34)) malformed('multi-disk entries are unsupported.')
    requireBytes(cursor + 46, nameLength + extraLength + commentLength, eocd)
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameLength)
    const path = safePath(decode(name))
    const key = path.replace(/\/$/, '').normalize('NFC').toLowerCase()
    if (names.has(key)) malformed(`duplicate or ambiguous archive path: ${path}`)
    names.add(key)
    extra(cursor + 46 + nameLength, extraLength, name, path)
    const attributes = u32(cursor + 38), kind = (attributes >>> 16) & 0xf000
    if (kind && kind !== 0x8000 && kind !== 0x4000) malformed(`symlinks and special files are unsupported: ${path}`)
    const directory = path.endsWith('/')
    if ((kind === 0x4000 || (attributes & 0x10)) && !directory) malformed(`ambiguous directory path: ${path}`)
    if (directory && (size || compressed)) malformed(`directory contains file data: ${path}`)
    total += size
    if (total > MAX_OUTPUT) throw new Error('The archive expands beyond the 25 MB safety limit.')
    if (isSupportedText(path) && size > MAX_FILE) throw new Error(`Source file is larger than the 1 MB per-file limit: ${path}`)
    if (size > Math.max(compressed, 1) * MAX_RATIO) throw new Error(`Archive compression ratio is unsafe for: ${path}`)
    if (method === 0 && size !== compressed) malformed(`stored size mismatch: ${path}`)

    requireBytes(offset, 30, directoryStart)
    if (u32(offset) !== 0x04034b50 || u16(offset + 6) !== flags || u16(offset + 8) !== method) malformed(`local header mismatch: ${path}`)
    const localNameLength = u16(offset + 26), localExtraLength = u16(offset + 28)
    const start = offset + 30 + localNameLength + localExtraLength
    requireBytes(offset + 30, localNameLength + localExtraLength, directoryStart)
    const localName = bytes.subarray(offset + 30, offset + 30 + localNameLength)
    safePath(decode(localName))
    if (localName.length !== name.length || localName.some((byte, index) => byte !== name[index])) malformed(`local filename mismatch: ${path}`)
    extra(offset + 30 + localNameLength, localExtraLength, localName, path)
    const descriptor = Boolean(flags & 8)
    for (const [local, central] of [[u32(offset + 14), crc], [u32(offset + 18), compressed], [u32(offset + 22), size]]) {
      if (local !== central && !(descriptor && local === 0)) malformed(`local size or CRC mismatch: ${path}`)
    }
    requireBytes(start, compressed, directoryStart)
    let end = start + compressed
    if (descriptor) {
      requireBytes(end, 12, directoryStart)
      if (u32(end) === 0x08074b50) end += 4
      requireBytes(end, 12, directoryStart)
      if (u32(end) !== crc || u32(end + 4) !== compressed || u32(end + 8) !== size) malformed(`invalid data descriptor: ${path}`)
      end += 12
    }
    entries.push({ path, directory, method, size, compressed, crc, start, end, offset })
    cursor += 46 + nameLength + extraLength + commentLength
  }
  if (cursor !== eocd || entries.length !== count) malformed('central directory entry count mismatch.')
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

async function extract(bytes: Uint8Array<ArrayBuffer>, entry: Entry, budget: { bytes: number }): Promise<string> {
  let position = entry.start
  // A small compressed chunk bounds inflater work/allocation even when sizes lie.
  // Backpressure prevents feeding the whole compressed bomb before output checks.
  const input = new ReadableStream<Uint8Array<ArrayBuffer>>({
    pull(controller) {
      if (position >= entry.start + entry.compressed) { controller.close(); return }
      const end = Math.min(position + 256, entry.start + entry.compressed)
      controller.enqueue(bytes.subarray(position, end))
      position = end
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

export async function readSourceZip(file: File, onProgress?: (phase: string) => void): Promise<ZipReadResult> {
  onProgress?.('Validating archive headers and safety limits')
  if (file.size > MAX_BYTES) throw new Error('This archive is larger than the 10 MB limit.')
  if (!file.name.toLowerCase().endsWith('.zip')) throw new Error('Upload a .zip archive containing source code.')
  const bytes = new Uint8Array(await file.arrayBuffer())
  if (bytes.length > MAX_BYTES) throw new Error('This archive is larger than the 10 MB limit.')
  const entries = preflight(bytes)
  const files: SourceFile[] = [], skipped: string[] = []
  const budget = { bytes: 0 }
  onProgress?.('Extracting supported text with streamed byte and CRC checks')
  for (const entry of entries) {
    if (entry.directory) continue
    if (entry.path.split('/').some((segment) => IGNORED.has(segment.toLowerCase()))) {
      skipped.push(`${entry.path}: ignored dependency/build/cache directory; content and CRC not inspected.`)
      continue
    }
    if (!isSupportedText(entry.path)) {
      skipped.push(`${entry.path}: unsupported file type; content and CRC not inspected.`)
      continue
    }
    let content: string
    try { content = await extract(bytes, entry, budget) }
    catch (error) {
      if (error instanceof TypeError && /encoded data|encoding/i.test(error.message)) {
        skipped.push(`${entry.path}: non-UTF-8 text is unsupported.`)
        continue
      }
      throw new Error(`Archive extraction failed for ${entry.path}: ${error instanceof Error ? error.message : 'invalid compressed data'}`)
    }
    if (content.includes('\0')) { skipped.push(`${entry.path}: binary content is unsupported.`); continue }
    files.push({ path: entry.path, content })
  }
  return { files, skipped, entryCount: entries.length }
}
