import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'

import { randomBytes } from '@noble/hashes/utils.js'

import { eddsaBuild } from '../src/eddsa/index.js'
import { decodeMultisigKey, decodeShareableKey, getShareableMultisigKey, getShareableViewingKey } from '../src/index.js'

/**
 * Generates a random 32-byte key for test fixtures.
 * @returns 32 random bytes.
 */
function randomKey (): Uint8Array {
  const k = randomBytes(32)
  return k
}

describe('EddsaPoseidon (production tests)', () => {
  const eddsa = eddsaBuild
  // const BabyJubPoint = eddsa.Point

  let prv: Uint8Array
  let pub: [bigint, bigint]
  let msg: Uint8Array
  const subOrder = eddsa.order

  before(() => {
    prv = new Uint8Array(32).fill(7)
    pub = eddsa.prv2pub(prv)
    msg = new TextEncoder().encode('PoseidonTestMessage')
  })

  it('pruneBuffer clamps bits as per EdDSA spec', () => {
    const raw = new Uint8Array(32).fill(0xff)
    const pruned = eddsa.pruneBuffer(raw)
    assert.equal(pruned.length, 32)
    assert.equal(pruned[0]! & 0x07, 0)
    assert.equal(pruned[31]! & 0x80, 0)
    assert.equal(pruned[31]! & 0x40, 0x40)
  })

  it('different keys produce different pubkeys', () => {
    const prv1 = randomKey(); const prv2 = randomKey()
    const pub1 = eddsa.prv2pub(prv1)
    const pub2 = eddsa.prv2pub(prv2)
    assert.notDeepEqual(pub1, pub2)
  })

  it('should properly pack and unpack Point', () => {
    const privateKey = new Uint8Array([
      176, 149, 143, 139, 194, 134, 174, 8, 50, 250, 131, 176, 27, 113, 154, 34, 90, 7, 206, 123,
      134, 31, 243, 17, 50, 63, 34, 22, 103, 179, 189, 80,
    ])

    // const privateKey = new Uint8Array(Buffer.from('efc6f552f6797c74aa967c7583fc4680c3dd5df64618b6fdc25eeef045a34c03', 'hex'))
    const pubkey = [
      15684838006997671713939066069845237677934334329285343229142447933587909549584n,
      11878614856120328179849762231924033298788609151532558727282528569229552954628n,
    ] as [bigint, bigint]
    const packed = eddsa.packPoint(pubkey)
    const unpacked = eddsa.unpackPoint(packed)

    assert.deepStrictEqual(unpacked, pubkey, 'invalid packing')

    const expectedShareable = '82a57670726976d94062303935386638626332383661653038333266613833623031623731396132323561303763653762383631666633313133323366323231363637623362643530a473707562d94030346164336335393738653064646561373030613336393932313861333461616336663736303437646661656131323966643530313464636338306534333961'
    const shareable = getShareableViewingKey(pubkey, privateKey)

    const sessionId = 'giraffe-exclude-tree-cross'
    const symmetricKey = '0xce4b39db21f9311e84b73e6f3a66b2ff1e98c62c642a8ec7ea34ceb9210725ff'
    const participantId = 1

    const multisigInfo = {
      vpriv: privateKey,
      spub: pubkey,
      sid: sessionId,
      sk: symmetricKey,
      pid: participantId
    }
    const multisig = getShareableMultisigKey(pubkey, privateKey, sessionId, symmetricKey, participantId)
    const decoded = decodeShareableKey(multisig)
    const decodedMultisig = decodeMultisigKey(multisig)
    console.log('multisig', multisig)
    console.log('matchdecoded', multisigInfo)
    console.log('decodedMultisig', decodedMultisig)
    console.log('decoded', decoded)

    assert.equal(shareable, expectedShareable)
  })

  describe('toBytes / fromBytes ', () => {
    it('roundtrips via toBytes/fromBytes', () => {
      const a = 12345n
      const bytes = eddsa.toBytes(a)
      const back = eddsa.fromBytes(bytes)
      assert.equal(back, a)
    })
  })

  describe('signing & verification', () => {
    it('produces valid signature with S < subOrder', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      assert.ok(typeof sig.S === 'bigint')
      assert.ok(sig.S >= 0n && sig.S < subOrder, 'S must be in [0,subOrder)')
    })

    it('verifyPoseidon returns true for valid signature', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const verified = eddsa.verifyPoseidon(msg, sig, pub)
      assert.equal(verified, true)
    })

    it('verifyPoseidon returns false for wrong message', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const badMsg = new TextEncoder().encode('tampered')
      assert.equal(eddsa.verifyPoseidon(badMsg, sig, pub), false)
    })

    it('verifyPoseidon returns false for wrong public key', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const wrongPub = eddsa.prv2pub(new Uint8Array(32).fill(8))
      assert.equal(
        eddsa.verifyPoseidon(msg, sig, wrongPub),
        false
      )
    })

    it('signing is deterministic for fixed key+message', () => {
      const sig1 = eddsa.signPoseidon(prv, msg)
      const sig2 = eddsa.signPoseidon(prv, msg)
      assert.deepEqual(sig1, sig2)
    })
  })

  describe('edge cases & rejection', () => {
    it('rejects signature with S >= subOrder', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const badSig = { R8: sig.R8, S: subOrder } // intentionally invalid
      assert.equal(
        eddsa.verifyPoseidon(msg, badSig, pub),
        false
      )
    })

    it('returns false for forged R8 not in subgroup', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const forgedR8 = [sig.R8[0], (sig.R8[1] + 1n) % eddsa.fieldPrime] as [bigint, bigint]
      assert.equal(
        eddsa.verifyPoseidon(msg, { R8: forgedR8, S: sig.S }, pub),
        false
      )
    })
  })
})
