/* eslint-disable jsdoc/require-jsdoc */
import { blake512 } from '@noble/hashes/blake1.js'
import { randomBytes } from '@noble/hashes/utils.js'
import type { Point } from '@zk-kit/baby-jubjub'
import { Base8, Fr as FrValue, mulPointEscalar, order, r, subOrder } from '@zk-kit/baby-jubjub'

import { leBigIntToBuffer, leBufferToBigInt } from './bytes.js'

type FrType = typeof FrValue

/** Simple affine point representation used by utility helpers. */
type AffinePoint = {
  x: bigint;
  y: bigint;
}

/**
 * Core Baby Jubjub arithmetic and serialization helpers used by the higher-level
 * EDDSA, FROST, and DKG implementations.
 */
class RailJubCurvePoint {
  public readonly curveOrder = order
  public readonly generator = Base8
  public readonly Fr: FrType = FrValue
  public readonly order = subOrder
  public readonly identity: Point<bigint> = [0n, 1n]
  public readonly fieldPrime = r
  blake512 = blake512

  // RFC 8032 compliant point compression
  // Encodes point as y-coordinate with sign bit for x in bit 255
  private pointCompress (P: Point<bigint>): bigint {
    const x = P[0]
    const y = P[1]

    // Set bit 255 to the sign (least significant bit) of x
    const sign = x & 1n
    const encoded = y | (sign << 255n)

    return encoded
  }

  // RFC 8032 compliant point decompression
  // Recovers point from y-coordinate and x sign bit
  private pointDecompress (s: bigint): Point<bigint> | null {
    // Extract sign bit from bit 255
    const sign = (s >> 255n) & 1n
    // Mask out the sign bit to get y
    const y = s & ((1n << 255n) - 1n)

    // Recover x from y and sign
    const x = this.recoverX(y, sign)
    if (x === null) return null

    return [x, y]
  }

  // Recover x-coordinate from y-coordinate and sign bit
  // Baby Jubjub curve equation: ax² + y² = 1 + dx²y²
  // where a = 168700, d = 168696
  private recoverX (y: bigint, sign: bigint): bigint | null {
    const a = 168700n
    const d = 168696n

    // const p = this.fieldPrime
    // Compute x² from curve equation
    // x² = (y² - 1) / (dy² - a)
    const y2 = this.modP(y * y)
    const u = this.modP(y2 - 1n)
    const v = this.modP(d * y2 - a)

    const vInv = this.modPInv(v)
    if (vInv === null) return null

    const x2 = this.modP(u * vInv)

    // Compute square root
    let x = this.modPSqrt(x2)
    if (x === null) return null

    // Choose the square root with the correct sign
    if ((x & 1n) !== sign) {
      x = this.modP(-x)
    }

    return x
  }

  // Modular arithmetic in the field
  private modP (x: bigint): bigint {
    const r = x % this.fieldPrime
    return r < 0n ? r + this.fieldPrime : r
  }

  // Modular inverse in the field
  private modPInv (a: bigint): bigint | null {
    let t = 0n; let newT = 1n
    let r = this.fieldPrime
    let newR = this.modP(a)

    while (newR !== 0n) {
      const q = r / newR
      ;[t, newT] = [newT, t - q * newT]
      ;[r, newR] = [newR, r - q * newR]
    }

    if (r !== 1n) return null
    if (t < 0n) t += this.fieldPrime
    return t
  }

  // Modular square root using Tonelli-Shanks or direct formula
  // For Baby Jubjub, p ≡ 1 (mod 4), so we use Tonelli-Shanks
  private modPSqrt (n: bigint): bigint | null {
    const p = this.fieldPrime

    // Check if n is a quadratic residue
    const ls = this.legendreSymbol(n, p)
    if (ls !== 1n) return null

    // For p ≡ 5 (mod 8), we can use a direct formula
    // Check if p ≡ 3 (mod 4) for simpler case
    if (p % 4n === 3n) {
      const exp = (p + 1n) / 4n
      return this.modPPow(n, exp)
    }

    // Otherwise use Tonelli-Shanks algorithm
    return this.tonelliShanks(n, p)
  }

  // Legendre symbol computation
  private legendreSymbol (a: bigint, p: bigint): bigint {
    const ls = this.modPPow(a, (p - 1n) / 2n)
    return ls === p - 1n ? -1n : ls
  }

  // Modular exponentiation
  private modPPow (base: bigint, exp: bigint): bigint {
    let result = 1n
    base = this.modP(base)

    while (exp > 0n) {
      if (exp % 2n === 1n) {
        result = this.modP(result * base)
      }
      exp = exp / 2n
      base = this.modP(base * base)
    }

    return result
  }

  // Tonelli-Shanks algorithm for computing square roots mod p
  private tonelliShanks (n: bigint, p: bigint): bigint | null {
    // Find Q and S such that p - 1 = Q * 2^S with Q odd
    let Q = p - 1n
    let S = 0n
    while (Q % 2n === 0n) {
      Q = Q / 2n
      S += 1n
    }

    // Find a quadratic non-residue z
    let z = 2n
    while (this.legendreSymbol(z, p) !== -1n) {
      z += 1n
    }

    let M = S
    let c = this.modPPow(z, Q)
    let t = this.modPPow(n, Q)
    let R = this.modPPow(n, (Q + 1n) / 2n)

    while (true) {
      if (t === 0n) return 0n
      if (t === 1n) return R

      // Find the least i such that t^(2^i) = 1
      let i = 1n
      let temp = this.modP(t * t)
      while (temp !== 1n && i < M) {
        temp = this.modP(temp * temp)
        i += 1n
      }

      const exp = M - i - 1n
      const b = this.modPPow(c, 1n << exp)
      M = i
      c = this.modP(b * b)
      t = this.modP(t * c)
      R = this.modP(R * b)
    }
  }

  // appendix D.(1, 2)
  rejectionSampling () {
    while (true) {
      const bytes = randomBytes(32)
      bytes[31]! &= 0x1f // Clear top 3 bits
      try {
        return this.DeserializeScalar(bytes)
      } catch {
        // retry on failure - this implements rejection sampling
        continue
      }
    }
  }

  wideBytes () {
    const nBytes = 48
    const R = 1n << BigInt(nBytes * 8)
    const limit = R - (R % this.order)
    while (true) {
      const bytes = randomBytes(nBytes)
      const x = leBufferToBigInt(bytes)
      if (x < limit) return x % this.order
    }
  }

  /**
   * Returns the subgroup order used by the FROST and DKG primitives.
   * @returns The Baby Jubjub subgroup order.
   */
  Order () {
    return this.order
  }

  /**
   * Returns the additive identity for the Baby Jubjub subgroup.
   * @returns The affine identity point.
   */
  Identity (): Point<bigint> {
    return this.identity
  }

  /**
   * Samples a scalar uniformly from the subgroup order.
   * @param rejectionSampling When `true`, uses rejection sampling to avoid bias.
   * @returns A uniformly sampled scalar.
   */
  RandomScalar (rejectionSampling = true): bigint {
    // RFC 9591: Scalars must be uniformly sampled in [0, order-1]
    // Use rejection sampling by default to avoid modulo reduction bias.
    return rejectionSampling ? this.rejectionSampling() : this.wideBytes()
  }

  /**
   * Multiplies the subgroup generator by a scalar.
   * @param k Scalar multiplier.
   * @returns The resulting affine point.
   */
  ScalarBaseMult (k: bigint): Point<bigint> {
    return mulPointEscalar(this.generator, this.modOrder(k))
  }

  /**
   * Multiplies an affine point by a scalar.
   * @param A Affine point.
   * @param k Scalar multiplier.
   * @returns The resulting affine point.
   */
  ScalarMult (A: Point<bigint>, k: bigint): Point<bigint> {
    return mulPointEscalar(A, this.modOrder(k))
  }

  /**
   * Serializes an affine subgroup point using RFC 8032-style compression.
   * @param A Affine point to serialize.
   * @returns The compressed 32-byte point encoding.
   */
  SerializeElement (A: Point<bigint>): Uint8Array {
    if (this.pointsEqual(A, this.identity)) throw new Error('SerializeElement: input is group identity')

    // Use RFC 8032 compliant compression
    const packed = this.pointCompress(A)
    const bytes = leBigIntToBuffer(packed, 32)

    return bytes
  }

  /**
   * Deserializes a compressed point and verifies subgroup membership.
   * @param buf Compressed point bytes.
   * @returns The decoded affine point.
   */
  DeserializeElement (buf: Uint8Array): Point<bigint> {
    if (buf.length !== 32) throw new Error('DeserializeElement: invalid length')

    // Use RFC 8032 compliant decompression
    const encoded = leBufferToBigInt(buf)
    const P = this.pointDecompress(encoded)

    if (P === null) throw new Error('DeserializeElement: invalid point encoding')
    if (this.pointsEqual(P, this.identity)) throw new Error('DeserializeElement: point is identity')

    const check = mulPointEscalar(P, this.order)
    if (!this.pointsEqual(check, this.identity)) throw new Error('DeserializeElement: not in prime-order subgroup')

    return P
  }

  /**
   * Serializes a scalar into the canonical 32-byte form expected by the repo.
   * @param s Scalar to serialize.
   * @returns The serialized scalar bytes.
   */
  SerializeScalar (s: bigint): Uint8Array {
    if (s < 0n || s >= this.order) throw new Error('SerializeScalar: scalar out of range')
    const out = this.toBytes(s)
    // top three bits MUST be zero
    out[31]! &= 0x1f
    return out
  }

  /**
   * Deserializes a scalar from the canonical 32-byte form.
   * @param buf Serialized scalar bytes.
   * @returns The decoded scalar.
   */
  DeserializeScalar (buf: Uint8Array): bigint {
    if (buf.length !== 32) throw new Error('DeserializeScalar: invalid length')
    // top three bits must be zero
    if ((buf[31]! & 0xe0) !== 0) throw new Error('DeserializeScalar: top bits non-zero')
    const s = this.fromBytes(buf)
    if (s < 0n || s >= this.order) throw new Error('DeserializeScalar: scalar out of range')
    return s
  }

  /**
   * Compares two affine points for coordinate equality.
   * @param a First affine point.
   * @param b Second affine point.
   * @returns `true` when both coordinates match.
   */
  pointsEqual = (a: Point<bigint>, b: Point<bigint>) => {
    return a[0] === b[0] && a[1] === b[1]
  }

  /**
   * Converts a scalar into the repo's canonical 32-byte little-endian form.
   * @param a Scalar to encode.
   * @returns Encoded bytes.
   */
  toBytes (a: bigint) {
    return leBigIntToBuffer(a, 32)
  }

  /**
   * Decodes a scalar from the repo's canonical 32-byte little-endian form.
   * @param a Encoded bytes.
   * @returns The decoded scalar.
   */
  fromBytes (a: Uint8Array) {
    return leBufferToBigInt(a)
  }

  /**
   * Reduces a bigint modulo the full curve order.
   * @param x Value to reduce.
   * @returns The reduced scalar.
   */
  modCurveOrder (x: bigint) {
    const r = x % this.curveOrder
    return r < 0n ? r + this.curveOrder : r
  }

  /**
   * Reduces a bigint modulo the prime-order subgroup.
   * @param x Value to reduce.
   * @returns The reduced scalar.
   */
  modOrder (x: bigint) {
    const r = x % this.order
    return r < 0n ? r + this.order : r
  }

  /**
   * Computes a multiplicative inverse in the subgroup field.
   * @param a Scalar to invert.
   * @returns The multiplicative inverse modulo the subgroup order.
   */
  invModOrder (a: bigint): bigint {
    let t = 0n; let newT = 1n
    let r = this.order; let newR = this.modOrder(a)
    while (newR !== 0n) {
      const q = r / newR
      ;[t, newT] = [newT, t - q * newT]
      ;[r, newR] = [newR, r - q * newR]
    }
    if (r !== 1n) throw new Error('inverse does not exist')
    if (t < 0n) t += this.order
    return t
  }

  /**
   * Applies EdDSA bit pruning to a 32-byte buffer.
   * @param buff Input bytes.
   * @returns The pruned buffer.
   */
  pruneBuffer (buff: Uint8Array) {
    const out = new Uint8Array(buff)
    out[0]! &= 0xf8
    out[31]! &= 0x7f
    out[31]! |= 0x40
    return out
  }

  /**
   * Derives the Baby Jubjub secret scalar for the provided private key.
   * @param prv Private key bytes.
   * @returns The derived subgroup scalar divided by the cofactor.
   */
  prvToSubScalar (prv: Uint8Array): bigint {
    const h64 = this.blake512(prv)
    const pr = this.pruneBuffer(h64)
    const s = leBufferToBigInt(pr.subarray(0, 32))
    return s >> 3n
  }

  /**
   * Maps an Edwards point into Montgomery coordinates when the mapping exists.
   * @param ed Edwards affine point.
   * @param ed.x Edwards x-coordinate.
   * @param ed.y Edwards y-coordinate.
   * @returns The mapped Montgomery coordinates.
   */
  toMontgomery (ed: { x: bigint; y: bigint }) {
    const { x, y } = ed
    if (x === 0n) throw new Error('toMontgomery: x = 0 maps to v undefined')
    const denU = this.modP(1n - y)
    if (denU === 0n) throw new Error('toMontgomery: y = 1 (identity) not mappable')

    const u = this.modP(this.modP(1n + y) * this.modPInv(denU)!)
    const v = this.modP(u * this.modP(x))
    return { u, v }
  }
}
export type { AffinePoint }
export { RailJubCurvePoint }
