import assert from 'node:assert'
import { describe, it } from 'node:test'

import { encode as msgpackEncode } from '@msgpack/msgpack'
import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToHex } from '@railgun-reloaded/bytes'

import {
  decodeMultisigKey,
  decodeShareableKey,
  eddsaBuild,
  getPublicSpendingKey,
  getPublicViewingKey,
  getShareableMultisigKey,
  getShareableViewingKey,
  poseidonHex,
  signEDDSA,
  verifyEDDSA,
} from '../src/index.js'

/**
 * Encode an arbitrary value as the hex-encoded msgpack payload the decoders expect.
 * @param obj Value to encode.
 * @returns The hex-encoded msgpack representation.
 */
const hexPayload = (obj: unknown) => bytesToHex(msgpackEncode(obj))

// A real spending public key + 32-byte viewing key to drive round-trip tests.
const spendingPrivate = randomBytes(32)
const spendingPublic = getPublicSpendingKey(spendingPrivate)
const viewingPrivate = randomBytes(32)

describe('shareable key decoding rejects malformed input', () => {
  it('rejects non-hex strings', () => {
    assert.throws(() => decodeShareableKey('nothex!!'), /expected hex string/)
  })

  it('rejects empty hex', () => {
    assert.throws(() => decodeShareableKey(''), /empty hex string/)
  })

  it('rejects a payload that is not an object', () => {
    assert.throws(() => decodeShareableKey(hexPayload(5)), /Invalid shareable key payload/)
  })

  it('rejects a payload missing vpriv/spub', () => {
    assert.throws(() => decodeShareableKey(hexPayload({ vpriv: '00' })), /Invalid shareable key payload/)
  })

  it('rejects a non-string session id', () => {
    assert.throws(() => decodeShareableKey(hexPayload({ vpriv: '00', spub: '00', sid: 5 })), /session id/)
  })

  it('rejects a non-positive participant id', () => {
    assert.throws(() => decodeShareableKey(hexPayload({ vpriv: '00', spub: '00', pid: 0 })), /participant id/)
  })

  it('rejects a non-integer participant id', () => {
    assert.throws(() => decodeShareableKey(hexPayload({ vpriv: '00', spub: '00', pid: 1.5 })), /participant id/)
  })
})

describe('shareable viewing key round-trip', () => {
  it('encodes and decodes a viewing key payload', () => {
    const encoded = getShareableViewingKey(spendingPublic, viewingPrivate)
    const decoded = decodeShareableKey(encoded)
    assert.equal(typeof decoded.vpriv, 'string')
    assert.equal(typeof decoded.spub, 'string')
    assert.equal(decoded.pid, undefined)
  })

  it('also accepts a 0x-prefixed payload', () => {
    const encoded = getShareableViewingKey(spendingPublic, viewingPrivate)
    assert.doesNotThrow(() => decodeShareableKey('0x' + encoded))
  })

  it('rejects a viewing key that is not 32 bytes', () => {
    assert.throws(() => getShareableViewingKey(spendingPublic, new Uint8Array(31)), /viewing private key length/)
  })
})

describe('multisig key round-trip and validation', () => {
  it('encodes and decodes a multisig payload, recovering the spending key', () => {
    const encoded = getShareableMultisigKey(spendingPublic, viewingPrivate, 'session-1', '0xdeadbeef', 3)
    const decoded = decodeMultisigKey(encoded)
    assert.equal(decoded.pid, 3)
    assert.equal(decoded.sid, 'session-1')
    assert.equal(decoded.sk, '0xdeadbeef')
    assert.equal(decoded.vpriv.length, 32)
    assert.ok(eddsaBuild.pointsEqual(decoded.spub, spendingPublic), 'spending key did not round-trip')
  })

  it('rejects an empty session id', () => {
    assert.throws(() => getShareableMultisigKey(spendingPublic, viewingPrivate, '', '0xab', 1), /Invalid sessionID/)
  })

  it('rejects a non-positive participant id', () => {
    assert.throws(() => getShareableMultisigKey(spendingPublic, viewingPrivate, 'session-1', '0xab', 0), /Invalid participantId/)
  })

  it('decodeMultisigKey rejects a viewing-only payload (no sid/sk/pid)', () => {
    const viewingOnly = getShareableViewingKey(spendingPublic, viewingPrivate)
    assert.throws(() => decodeMultisigKey(viewingOnly), /Invalid multisig shareable key payload/)
  })
})

describe('key helper input validation', () => {
  it('getPublicSpendingKey rejects a wrong-length key', () => {
    assert.throws(() => getPublicSpendingKey(new Uint8Array(31)), /private key length/)
  })

  it('getPublicViewingKey rejects a wrong-length key', async () => {
    await assert.rejects(getPublicViewingKey(new Uint8Array(31)), /private viewing key length/)
  })

  it('signEDDSA rejects a wrong-length key', () => {
    assert.throws(() => signEDDSA(new Uint8Array(31), 1n), /private key length/)
  })

  it('poseidonHex rejects an un-parsable input', () => {
    assert.throws(() => poseidonHex(['not-a-bigint']), /Invalid Poseidon input/)
  })
})

describe('signEDDSA / verifyEDDSA round-trip', () => {
  it('verifies a valid signature and rejects a tampered message', () => {
    const sig = signEDDSA(spendingPrivate, 42n)
    assert.equal(verifyEDDSA(42n, sig, spendingPublic), true)
    assert.equal(verifyEDDSA(43n, sig, spendingPublic), false)
  })
})
