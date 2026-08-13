import { bigIntToBytes, bytesToBigInt } from '@railgun-reloaded/bytes'

/**
 * Little-endian / big-endian integer conversions, Buffer-free for browser and
 * React Native. Big-endian and length-fixed conversions come from
 * `@railgun-reloaded/bytes`; little-endian variants reverse the byte order.
 */

/**
 * Decode little-endian bytes into a bigint.
 * @param bytes Little-endian byte array.
 * @returns The decoded integer.
 */
const leBufferToBigInt = (bytes: Uint8Array): bigint => bytesToBigInt(bytes.toReversed())

/**
 * Encode a bigint as little-endian bytes of a fixed length.
 * @param value Integer to encode.
 * @param size Output byte length.
 * @returns The little-endian encoding.
 */
const leBigIntToBuffer = (value: bigint, size: number): Uint8Array => bigIntToBytes(value, size).toReversed()

/**
 * Encode a non-negative bigint as minimal-length big-endian bytes.
 *
 * `@railgun-reloaded/bytes` only offers fixed-length encoding, so the
 * minimal-length form is computed here to preserve the existing wire layout.
 * @param value Non-negative integer to encode.
 * @returns The big-endian encoding (at least one byte).
 */
const bigIntToBuffer = (value: bigint): Uint8Array => {
  let hex = value.toString(16)
  if (hex.length % 2 === 1) hex = '0' + hex
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export { leBufferToBigInt, leBigIntToBuffer, bigIntToBuffer }
