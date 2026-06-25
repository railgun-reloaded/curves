import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js'
import { bytesToBigInt } from '@railgun-reloaded/bytes'
import type { Point } from '@zk-kit/baby-jubjub'
import { Base8, addPoint, inCurve, mulPointEscalar, packPoint as packBabyPoint, subOrder, unpackPoint as unpackBabyPoint } from '@zk-kit/baby-jubjub'
import { poseidon5 } from 'poseidon-lite'

import { leBigIntToBuffer, leBufferToBigInt } from '../bytes.js'
import { RailJubCurvePoint } from '../curve.js'

type SignatureHex = {
  R8: [string, string],
  S: string
}

type Signature = SignatureHex | {
  R8: [bigint, bigint];
  S: bigint;
}

/** Baby Jubjub EDDSA-Poseidon, built on the prime-order subgroup primitives. */
class EddsaPoseidon extends RailJubCurvePoint {
  /**
   * Derive the secret subgroup scalar from a private key.
   * @param prv Private key bytes.
   * @returns The cofactor-divided secret scalar.
   */
  private secretScalar (prv: Uint8Array): bigint {
    const pruned = this.pruneBuffer(this.blake512(prv).slice(0, 32))
    return leBufferToBigInt(pruned) >> 3n
  }

  /**
   * Derives the Baby Jubjub public key for a 32-byte private key.
   * @param prv Private key bytes.
   * @returns The affine Baby Jubjub public key.
   */
  prv2pub (prv: Uint8Array): [bigint, bigint] {
    return mulPointEscalar(Base8, this.secretScalar(prv)) as [bigint, bigint]
  }

  /**
   * Signs an arbitrary message byte array using EDDSA-Poseidon.
   * @param prv Private key bytes.
   * @param msg Message bytes to sign.
   * @returns The generated signature.
   */
  signPoseidon (prv: Uint8Array, msg: Uint8Array): { R8: [bigint, bigint]; S: bigint } {
    const message = bytesToBigInt(msg)
    const hash = this.blake512(prv)
    const s = leBufferToBigInt(this.pruneBuffer(hash.slice(0, 32)))
    const a = mulPointEscalar(Base8, s >> 3n)

    const rBytes = this.blake512(concatBytes(hash.slice(32, 64), leBigIntToBuffer(message, 32)))
    const r = leBufferToBigInt(rBytes) % subOrder
    const r8 = mulPointEscalar(Base8, r) as [bigint, bigint]

    const hm = poseidon5([r8[0], r8[1], a[0], a[1], message])
    const S = (r + hm * s) % subOrder

    return { R8: r8, S }
  }

  /**
   * Verifies an EDDSA-Poseidon signature.
   * @param msg Message bytes that were signed.
   * @param sig Signature to verify.
   * @param A Public key.
   * @returns `true` when the signature is valid.
   */
  verifyPoseidon (msg: Uint8Array, sig: Signature, A: Point<bigint> | Point<string>): boolean {
    const r8: [bigint, bigint] = [BigInt(sig.R8[0]), BigInt(sig.R8[1])]
    const S = BigInt(sig.S)
    const pub: [bigint, bigint] = [BigInt(A[0]), BigInt(A[1])]

    if (!inCurve(r8) || !inCurve(pub) || S >= subOrder) return false

    const message = bytesToBigInt(msg)
    const hm = poseidon5([r8[0], r8[1], pub[0], pub[1], message])

    const pLeft = mulPointEscalar(Base8, S)
    const pRight = addPoint(r8, mulPointEscalar(pub, hm * 8n))

    return pLeft[0] === pRight[0] && pLeft[1] === pRight[1]
  }

  /**
   * Packs an affine Baby Jubjub point into its compressed form.
   * @param point Affine point to pack.
   * @returns Compressed point bytes.
   */
  packPoint (point: Point<bigint>): Uint8Array {
    const packed = packBabyPoint(point)
    return hexToBytes(packed.toString(16).padStart(64, '0'))
  }

  /**
   * Unpacks a compressed Baby Jubjub public key.
   * @param bytesIn Compressed point bytes.
   * @returns The unpacked affine point or `null` if invalid.
   */
  unpackPoint (bytesIn: Uint8Array): Point<bigint> | null {
    const formatted = BigInt('0x' + bytesToHex(bytesIn).padStart(64, '0'))
    return unpackBabyPoint(formatted)
  }
}

const eddsaBuild = new EddsaPoseidon()

export type { Signature, SignatureHex }
export { EddsaPoseidon, eddsaBuild }
