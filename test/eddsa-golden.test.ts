import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { bytesToHex } from '@noble/hashes/utils.js'

import { eddsaBuild } from '../src/eddsa/index.js'

// Fixed reference vector pinning the Baby Jubjub EDDSA-Poseidon byte layout
// (circomlibjs-compatible scheme: BLAKE-512 key derivation, Poseidon challenge,
// cofactored verification). Derivation, signing, and point packing must remain
// byte-for-byte identical to these values so existing keys and signatures stay
// valid.
const VECTOR = {
  privateKey: new Uint8Array(32).fill(7),
  message: new TextEncoder().encode('PoseidonTestMessage'),
  pubX: 14422859473778768188622151430526693594403470008420308922992775064941455773685n,
  pubY: 7592518773672929099542717438998516546396504563265155469693554058278098107299n,
  r8x: 14353990228593219380822437644623156221987748771418636659133193946852704254964n,
  r8y: 17472976644804169434403985302010715966325385948593163831383517408360893554414n,
  s: 2310345491245508883694491568443625421504013838848525116015997234705324887224n,
  packedHex: '90c9369d585d49c6cfc1dd90927327b755779f0c810d17e1f91d7b6de2bafba3',
} as const

describe('EddsaPoseidon golden vector', () => {
  const eddsa = eddsaBuild

  it('prv2pub matches the reference public key', () => {
    const pub = eddsa.prv2pub(VECTOR.privateKey)
    assert.equal(pub[0], VECTOR.pubX, 'public key x')
    assert.equal(pub[1], VECTOR.pubY, 'public key y')
  })

  it('signPoseidon matches the reference signature', () => {
    const sig = eddsa.signPoseidon(VECTOR.privateKey, VECTOR.message)
    assert.equal(sig.R8[0], VECTOR.r8x, 'signature R8x')
    assert.equal(sig.R8[1], VECTOR.r8y, 'signature R8y')
    assert.equal(sig.S, VECTOR.s, 'signature S')
  })

  it('packPoint matches the reference compressed encoding', () => {
    const packed = eddsa.packPoint([VECTOR.pubX, VECTOR.pubY])
    assert.equal(bytesToHex(packed), VECTOR.packedHex)
  })

  it('verifyPoseidon accepts the reference signature', () => {
    const verified = eddsa.verifyPoseidon(
      VECTOR.message,
      { R8: [VECTOR.r8x, VECTOR.r8y], S: VECTOR.s },
      [VECTOR.pubX, VECTOR.pubY]
    )
    assert.equal(verified, true)
  })
})
