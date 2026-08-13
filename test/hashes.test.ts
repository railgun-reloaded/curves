import assert from 'node:assert'
import { describe, it } from 'node:test'

import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'

import { subOrder } from '../src/babyjubjub.js'
import { RFC9591Hasher } from '../src/hashing.js'

/**
 * Encode bytes as a lowercase hex string.
 * @param buffer Bytes to encode.
 * @returns The hex string.
 */
function toHex (buffer: Uint8Array) {
  return Buffer.from(buffer).toString('hex')
}

// Provided 32-byte input
const INPUT_HEX = '103056215bc7e90f9bbf1a4b4371b4484649a8ef98098c3326f9cb582673068a'
const INPUT = hexToBytes(INPUT_HEX)

// Expected vectors, regenerated under BLAKE-512 (see test/blake512.test.ts
// for the digest-level vectors that pin the hash itself).
const VECTORS = {
  H1: {
    rawHex: 'db60748bfe364a66d8a534c9aae75ed21681ee98b2646e28a2348b851d4e1f0e6954f75d5146d5d99ae79f8a1c4a6af4ba056df0c4eee0032db0e67b42bf277b',
    modDec: 1678949461854840229640339098254152788517688981803963206851042767735562726141n,
    modHex: '0x3b64070b4bfe54a871407503712f1918062d4a26284774df303393d973c6afd'
  },
  H3: {
    rawHex: '5bbb9d21a860ca973b78cef0056a4c57c354ea0705e28136f447a736a75dd72b7f9e504a3f359a5840f3ace159ecc012d95a18f9ee94f0799462221675d22ff1',
    modDec: 1213950929864348775292835996094940120861297402490820397600529732903868101565n,
    modHex: '0x2af12668e8e162c9b3aa0ab3acea87d9542420ee5f0e5420671392dcd64f3bd'
  },
  H4: {
    rawHex: '2316e8d9a9db62b6c37b1d8d77a354b0335561c2a893ac5b2c7b08af4a5d978c761a64400ccf50bb9349baec2c29904da4e0dda54c564ff98cecb03da9bcb323',
    modDec: 1252599766121406257733049228675028233963257259286401030830052074095697611857n,
    modHex: '0x2c4f243918758686fd1a27d4572d6cb888aaadb0914a1ebac92f9c326064c51'
  },
  H5: {
    rawHex: '53626e59d4f3f1aed62ead01bc0205e9c039b98fe1d30dabae22c37e8250e6a433d652c6c2958aa68bf7de931af787887a8d1c65fdb48cc10a3ffc53c760b9af',
    modDec: 2053056783151336678290556986299662488575879129835563357194705989096511257949n,
    modHex: '0x489fd2c7a4e21b7ae996096535f467ae251a13ab1cde88781ae06fe1ac23d5d'
  }
} as const

describe('RFC9591 H1 H3 H4 H5 test vectors', () => {
  it('Match expectations', () => {
    // Generate random 32 bytes input

    const hasher = new RFC9591Hasher('FROST-EDBABYJUJUB-BLAKE512-v1', subOrder)

    const funcs = [hasher.H1.bind(hasher), hasher.H3.bind(hasher), hasher.H4.bind(hasher), hasher.H5.bind(hasher)]
    const names: ('H1' | 'H3' | 'H4' | 'H5')[] = ['H1', 'H3', 'H4', 'H5']
    const tags = ['rho', 'nonce', 'msg', 'com']
    const results: bigint[] = []

    const randomVector = false
    const randomInput = randomVector ? randomBytes(32) : INPUT
    console.log('Random 32-byte input:')
    console.log('  Hex:', toHex(randomInput))
    console.log('  Decimal:', BigInt('0x' + toHex(randomInput)).toString())
    console.log()

    funcs.forEach((fn, idx) => {
      const name = names[idx]!
      const tag = tags[idx]!
      console.log(`${name} (tag: '${tag}'):`)
      const expected = VECTORS[name]
      const raw = hasher.taggedHash(tag, randomInput)
      assert.equal(bytesToHex(raw), expected.rawHex, 'invalid BLAKE-512 result.')
      console.log('  Raw hash (64 bytes):', toHex(raw))
      const result = fn(randomInput)
      assert.equal(result.toString(), expected.modDec, 'invalid result')
      assert.equal(`0x${result.toString(16)}`, expected.modHex, 'invalid result')
      results.push(result)
      console.log('  Modulo subOrder:', result.toString())
      console.log('  Hex:', '0x' + result.toString(16))
      console.log()
    })

    // Verify that different tags produce different results
    console.log('=== Verification ===')
    console.log('All hash results are different:',
      results[0] !== results[2] &&
      results[0] !== results[3] &&
      results[0] !== results[4] &&
      results[2] !== results[3] &&
      results[2] !== results[4] &&
      results[3] !== results[4]
        ? '✓ PASS'
        : '✗ FAIL'
    )

    // Test with same tag twice to verify consistency
    const h1Again = hasher.H1(randomInput)
    console.log('H1 is deterministic:', results[0] === h1Again ? '✓ PASS' : '✗ FAIL')
  })
})
