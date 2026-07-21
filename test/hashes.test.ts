import assert from 'node:assert'
import { describe, it } from 'node:test'

import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { subOrder } from '@zk-kit/baby-jubjub'

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

// Expected vectors from the prompt
const VECTORS = {
  H1: {
    rawHex: '517822754585151647635ec2224ab27d6a83e6629ebf3d36b1ad419eb400b9e50352423edec008d7e08fe9fddc571f592ff82da660a02a2c3d5dbac8426a079d',
    modDec: 1011714033864805916802867513617709433878078050615495686330311857274316592610n,
    modHex: '0x23c9c1f2be6312c1cf47ab103220a6d50059f50020dbda92a158e5266eb15e2'
  },
  H3: {
    rawHex: 'bcdd17d7d0d207a7fb860509ee09546dfca51454b0b591c547626e565272a1f60c0b37e46b18794793318ebd49c430349b2e467c0862d5bc9ebf4a868069f35f',
    modDec: 2247655552097648134964227634858129138190003209803194921068384139971060600961n,
    modHex: '0x4f820c1fc138c5e2dc3c7a16230acb75f8d13da98b23f952f561d3715489081'
  },
  H4: {
    rawHex: '39c1201c3014ba6032db564c77835ecc98a5e8f55ce10b904edba4293a00ad2fd792e0ed2b54e2621e7ed71c79e16a4e0d41e427f3240759b88e2a2f04df196e',
    modDec: 2658467010355774823620755361084890962955677056727848814744952892684839397019n,
    modHex: '0x5e0a395dcb3661341ee884396c6ce17c33f63a7c6ccf95e8849429da84ba69b'
  },
  H5: {
    rawHex: '6146fffab891f131e3062a315b15f1973c549d98a56f9670c8912699aa5f177cca177e364308d02a298c15401f4bbe7f6ed0263be81b6597856f13ae89509d9a',
    modDec: 1548104687198327700120789144102730872945653177570532681524096721970790712817n,
    modHex: '0x36c323a46d1ebb644d126e0ae5f6ca61ad35252b8c7b8707fe6ae2df344c5f1'
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
      assert.equal(bytesToHex(raw), expected.rawHex, 'invalid blake512 result.')
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
