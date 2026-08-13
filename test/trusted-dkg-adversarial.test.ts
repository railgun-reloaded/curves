import assert from 'node:assert'
import { describe, it } from 'node:test'

import { randomBytes } from '@noble/hashes/utils.js'

import { addPoint } from '../src/babyjubjub.js'
import { TrustedDKG } from '../src/frost/trusted-dkg.js'

const dkg = new TrustedDKG()
const keygen = dkg.trustedDealerKeygen(0x11n, 5, 3)
const commitments = keygen.vssCommitment // length 3, valid subgroup commitments

// A valid curve point with x != 0 that is NOT in the prime-order subgroup.
const nonSubgroup = addPoint(dkg.ScalarBaseMult(5n), [0n, dkg.fieldPrime - 1n])

describe('assertSortedConsecutiveIds', () => {
  it('rejects an empty list', () => {
    assert.throws(() => TrustedDKG.assertSortedConsecutiveIds([]), /empty recipient id list/)
  })

  it('rejects non-integer, non-positive, and unsorted/duplicate ids', () => {
    assert.throws(() => TrustedDKG.assertSortedConsecutiveIds([1.5]), /strictly increasing/)
    assert.throws(() => TrustedDKG.assertSortedConsecutiveIds([0]), /strictly increasing/)
    assert.throws(() => TrustedDKG.assertSortedConsecutiveIds([2, 1]), /strictly increasing/)
    assert.throws(() => TrustedDKG.assertSortedConsecutiveIds([1, 1]), /strictly increasing/)
  })

  it('accepts strictly-increasing non-consecutive ids', () => {
    assert.doesNotThrow(() => TrustedDKG.assertSortedConsecutiveIds([1, 3, 5]))
  })
})

describe('combineGroupPubkeyFromCommitments', () => {
  it('rejects an empty dealer set', () => {
    assert.throws(() => dkg.combineGroupPubkeyFromCommitments([]), /no dealer commitments/)
  })

  it('rejects a dealer with no commitments', () => {
    assert.throws(() => dkg.combineGroupPubkeyFromCommitments([[]]), /dealer missing commitments/)
  })

  it('rejects a degree mismatch across dealers', () => {
    assert.throws(
      () => dkg.combineGroupPubkeyFromCommitments([commitments, commitments.slice(0, 2)]),
      /degree mismatch/
    )
  })

  it('rejects a constant term outside the subgroup', () => {
    assert.throws(() => dkg.combineGroupPubkeyFromCommitments([[nonSubgroup]]), /C0 not in subgroup/)
  })
})

describe('verifyAllCommitmentsSubgroup', () => {
  it('returns true for valid commitments and false otherwise', () => {
    assert.equal(dkg.verifyAllCommitmentsSubgroup([commitments]), true)
    assert.equal(dkg.verifyAllCommitmentsSubgroup([[nonSubgroup]]), false)
    assert.equal(dkg.verifyAllCommitmentsSubgroup([]), false)
  })
})

describe('finalizeParticipant guards', () => {
  it('rejects a bad participant id', () => {
    assert.throws(() => dkg.finalizeParticipant(0, [{ dealerId: 1, s_ki: 5n }], [commitments]), /bad participantId/)
  })

  it('rejects a dealer/share count mismatch', () => {
    assert.throws(
      () => dkg.finalizeParticipant(1, [{ dealerId: 1, s_ki: 5n }], [commitments, commitments]),
      /dealer\/share count mismatch/
    )
  })
})

describe('encrypted share transport (AES-GCM + AAD)', () => {
  const key = randomBytes(32)
  const shares = { 1: 12345n }
  const keyById = { 1: key }
  const allCommitments = [commitments]

  it('round-trips an encrypted share', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    const out = dkg.decryptShareAESGCMWithAAD(enc[1]!, key, 1, allCommitments)
    assert.equal(out, 12345n)
  })

  it('rejects encryption with a wrong-length key', () => {
    assert.throws(() => dkg.encryptSharesAESGCMWithAAD(shares, { 1: randomBytes(16) }, allCommitments), /bad AES key/)
  })

  it('rejects decryption with the wrong key', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(enc[1]!, randomBytes(32), 1, allCommitments))
  })

  it('rejects decryption under a different commitment set (AAD mismatch)', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    const otherCommitments = [dkg.vssCommit([0x99n, 0x88n, 0x77n])]
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(enc[1]!, key, 1, otherCommitments))
  })

  it('rejects a tampered ciphertext', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    const tampered = { nonce: enc[1]!.nonce, ciphertext: Uint8Array.from(enc[1]!.ciphertext) }
    tampered.ciphertext[0]! ^= 0x01
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(tampered, key, 1, allCommitments))
  })

  it('rejects a bad key length on decrypt', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(enc[1]!, randomBytes(31), 1, allCommitments), /bad AES key length/)
  })

  it('rejects a bad participant id on decrypt', () => {
    const enc = dkg.encryptSharesAESGCMWithAAD(shares, keyById, allCommitments)
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(enc[1]!, key, 0, allCommitments), /bad participant id/)
  })

  it('rejects a ciphertext too short to contain the auth tag', () => {
    const short = { nonce: randomBytes(12), ciphertext: new Uint8Array(8) }
    assert.throws(() => dkg.decryptShareAESGCMWithAAD(short, key, 1, allCommitments), /bad ciphertext/)
  })
})

describe('TrustedDKG deriveInterpolatingValue identifier validation', () => {
  it('rejects identifier 0, the evaluation point of the shared secret', () => {
    assert.throws(() => dkg.deriveInterpolatingValue([0n, 1n, 2n], 0n), /invalid parameters/)
  })

  it('rejects a signer set containing a non-positive identifier', () => {
    assert.throws(() => dkg.deriveInterpolatingValue([0n, 1n, 2n], 1n), /invalid parameters/)
    assert.throws(() => dkg.deriveInterpolatingValue([-1n, 1n, 2n], 1n), /invalid parameters/)
  })

  it('still rejects an identifier absent from the signer set', () => {
    assert.throws(() => dkg.deriveInterpolatingValue([1n, 2n, 3n], 9n), /invalid parameters/)
  })

  it('accepts a valid positive identifier', () => {
    assert.doesNotThrow(() => dkg.deriveInterpolatingValue([1n, 2n, 3n], 2n))
  })
})
