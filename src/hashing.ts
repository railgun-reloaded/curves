/* eslint-disable jsdoc/require-jsdoc */

import { blake2b } from '@noble/hashes/blake2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import type { Point } from '@zk-kit/baby-jubjub'
import { poseidon5 } from 'poseidon-lite'

import { leBigIntToBuffer, leBufferToBigInt } from './bytes.js'

type HashFn = (m: Uint8Array) => Uint8Array
// TODO: to modularize this hasher, we can add more hash functions here
function blake2BWrapper (m: Uint8Array) {
  return blake2b(m, { dkLen: 64 })
}

/**
 * Domain-separated hash helpers used by the FROST and DKG implementations.
 *
 * The tag names follow the RFC 9591-style domains used throughout this repo.
 */
class RFC9591Hasher {
  public readonly contextString: string
  private readonly hashFn: HashFn
  private readonly order: bigint

  /**
   * Creates a hasher bound to a context string and scalar field order.
   * @param contextString Domain-separation prefix for all hashes.
   * @param order Scalar field order used for modular reduction.
   * @param hashFn Optional override for the base hash function.
   */
  constructor (contextString: string, order: bigint, hashFn?: HashFn) {
    this.contextString = contextString
    this.hashFn = hashFn ?? blake2BWrapper
    this.order = order
  }

  /**
   * Reduces a bigint into the configured scalar field.
   * @param x Value to reduce.
   * @returns The reduced field element.
   */
  mod (x: bigint) {
    const r = x % this.order
    return r < 0n ? r + this.order : r
  }

  /**
   * Applies the configured base hash function.
   * @param m Input bytes.
   * @returns The hash digest bytes.
   */
  Hash (m: Uint8Array): Uint8Array {
    return this.hashFn(m)
  }

  /**
   * Applies a context-prefixed domain tag before hashing.
   * @param tag Domain-separation tag.
   * @param input Input bytes.
   * @returns The hash digest bytes.
   */
  taggedHash (tag: string, input: any) {
    const encoder = new TextEncoder()
    const prefixBuf = encoder.encode(this.contextString)
    const tagBuf = encoder.encode(tag)
    const inputBuf: Uint8Array = input instanceof Uint8Array ? input : new Uint8Array(input)
    const combined = concatBytes(prefixBuf, tagBuf, inputBuf)
    return this.Hash(combined)
  }

  /**
   * Hashes arbitrary bytes and reduces the result into the scalar field.
   * @param tag Domain-separation tag.
   * @param input Input bytes.
   * @returns The reduced scalar.
   */
  deriveHashed (tag: string, input: Uint8Array): bigint {
    const digest = this.taggedHash(tag, input)
    const kLE = leBigIntToBuffer(leBufferToBigInt(digest), 64)
    return this.mod(leBufferToBigInt(kLE))
  }

  /**
   * Computes the FROST binding-factor hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H1 (m: Uint8Array): bigint {
    return this.deriveHashed('rho', m)
  }

  /**
   * Computes the challenge used by signature verification.
   * @param R8 Group commitment point.
   * @param A Group public key.
   * @param msgHash Message hash scalar.
   * @returns The derived scalar challenge.
   */
  H2 (R8: Point<bigint>, A: Point<bigint>, msgHash: bigint): bigint {
    return this.mod(poseidon5([...R8, ...A, msgHash]))
  }

  /**
   * Computes the deterministic nonce derivation hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H3 (m: Uint8Array): bigint {
    return this.deriveHashed('nonce', m)
  }

  /**
   * Computes the message-domain hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H4 (m: Uint8Array): bigint {
    return this.deriveHashed('msg', m)
  }

  /**
   * Computes the commitment-list digest hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H5 (m: Uint8Array): bigint {
    return this.deriveHashed('com', m)
  }

  /**
   * Computes the coefficient-domain hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H6 (m: Uint8Array): bigint {
    return this.deriveHashed('coeff', m)
  }

  /**
   * Computes the viewing-key derivation hash.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H7 (m: Uint8Array): bigint {
    return this.deriveHashed('view', m)
  }
}

export type { HashFn }
export { RFC9591Hasher }
