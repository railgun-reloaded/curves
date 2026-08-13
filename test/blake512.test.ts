import assert from 'node:assert'
import { describe, it } from 'node:test'

import { blake512 } from '@noble/hashes/blake1.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

import { subOrder } from '../src/babyjubjub.js'
import { RFC9591Hasher } from '../src/hashing.js'

const hasher = new RFC9591Hasher('FROST-EDBABYJUJUB-BLAKE512-v1', subOrder)

/**
 * Known-answer vectors for BLAKE-512, the original BLAKE (SHA-3 finalist).
 *
 * These pin the base hash behind every H1-H6 domain to the function the
 * ciphersuite string names. Without them, swapping in any other 64-byte digest
 * leaves the whole suite green, because the FROST and DKG tests only check
 * algebraic properties.
 */
const VECTORS: Array<{ label: string, input: Uint8Array, digest: string }> = [
  {
    label: 'the empty message',
    input: new Uint8Array(0),
    digest: 'a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8'
  },
  {
    label: 'a single zero byte',
    input: new Uint8Array(1),
    digest: '97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3'
  },
  {
    label: '144 zero bytes, spanning two blocks',
    input: new Uint8Array(144),
    digest: '313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde'
  },
  {
    label: 'abc',
    input: new TextEncoder().encode('abc'),
    digest: '14266c7c704a3b58fb421ee69fd005fcc6eeff742136be67435df995b7c986e7cbde4dbde135e7689c354d2bc5b8d260536c554b4f84c118e61efc576fed7cd3'
  }
]

describe('RFC9591Hasher base hash', () => {
  for (const { label, input, digest } of VECTORS) {
    it(`hashes ${label} to the BLAKE-512 known answer`, () => {
      assert.equal(bytesToHex(hasher.Hash(input)), digest)
    })
  }

  it('is BLAKE-512 and not BLAKE2b', () => {
    const input = new TextEncoder().encode('abc')
    assert.equal(bytesToHex(hasher.Hash(input)), bytesToHex(blake512(input)))
    assert.notEqual(bytesToHex(hasher.Hash(input)), bytesToHex(blake2b(input, { dkLen: 64 })))
  })

  it('agrees with the hash used for EdDSA-Poseidon key derivation', () => {
    // curve.ts exposes the same function as `blake512`; FROST and EdDSA must
    // not drift onto different base hashes.
    const input = new TextEncoder().encode('shared base hash')
    assert.equal(bytesToHex(hasher.Hash(input)), bytesToHex(blake512(input)))
  })

  it('accepts an injected hash function', () => {
    const constant = new Uint8Array(64).fill(7)
    const custom = new RFC9591Hasher('FROST-EDBABYJUJUB-BLAKE512-v1', subOrder, () => constant)
    assert.deepStrictEqual(Array.from(custom.Hash(new Uint8Array([1, 2, 3]))), Array.from(constant))
  })
})
