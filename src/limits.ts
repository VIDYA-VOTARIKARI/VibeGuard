export const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
export const MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
export const MAX_ARCHIVE_ENTRIES = 50_000
export const MAX_SOURCE_FILE_BYTES = 10 * 1024 * 1024
export const MAX_COMPRESSION_RATIO = 1_000

export const formatMegabytes = (bytes: number) => `${Math.round(bytes / (1024 * 1024))} MB`

export function formatFileSize(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / 1024).toFixed(1)} KB`
}
