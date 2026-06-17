import assert from 'node:assert'
import { describe, it } from 'node:test'

import type { Point } from '../src/index.js'
import { bigIntToBuffer, eddsaBuild } from '../src/index.js'
import { DKGManager } from '../src/manager/dkg.js'
import { FROSTSigningManager } from '../src/manager/signing.js'

describe('DKGManager e2e flow test', () => {
  it('should run trusted keygen and get expected group publickey', () => {
    const dkgManager = new DKGManager('test-participant-1')
    const secret = BigInt(0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn)

    const keys = dkgManager.runTrustedKeygen(secret, 5, 3)
    const expectedGroupPK = [
      '0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6',
      '0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd'
    ]
    assert.deepStrictEqual(keys.groupPublicKey, expectedGroupPK, 'derived group PK does not match.')

    const secrets = [
      0x11n,
      0x22n,
      0x33n,
      0x44n,
      0x55n,
    ]
    const dealers: DKGManager[] = []
    const dealerShares: Record<number, Record<number, bigint>> = {}

    const announcements: Uint8Array[] = []
    secrets.forEach(() => {
      const dealer = new DKGManager('test-participant-1')
      dealers.push(dealer)
      const announce = dealer.getAnnouncement()
      announcements.push(announce.pubKey)
    })

    // create roster
    const roster: Record<number, Uint8Array> = {}
    announcements.forEach((a, idx) => {
      roster[idx + 1] = a
    })

    // Each dealer runs commitment round and publishes commitments and shares
    const commitmentsByDealer: Record<number, ReturnType<DKGManager['commitmentRound']>['commitments']> = {}
    dealers.forEach((dealer, idx) => {
      dealer.assignRoster(roster)
      const { commitments: comms, shares } = dealer.commitmentRound(secrets[idx]!, 5, 3)
      commitmentsByDealer[idx + 1] = comms
      dealerShares[idx + 1] = shares
    })

    // Distribute commitments to every dealer
    dealers.forEach((_dealer) => {
      for (const idStr in commitmentsByDealer) {
        const id = Number(idStr)
        _dealer.addParticipantCommitments(id, commitmentsByDealer[id]!)
      }
    })

    // Each dealer encrypts their shares using the full commitments set
    const encryptedShares: Record<number, ReturnType<DKGManager['getEncryptedShares']>> = {}
    dealers.forEach((dealer, idx) => {
      encryptedShares[idx + 1] = dealer.getEncryptedShares()
    })

    // Distribute encrypted shares to each recipient
    dealers.forEach((dealer) => {
      for (const idStr in encryptedShares) {
        const id = Number(idStr)
        dealer.addEncryptedShares(id, encryptedShares[id]!)
      }
    })

    // Finalize: each dealer should be able to decrypt, combine and produce their share
    const results = dealers.map((dealer) => dealer.finalize())
    results.forEach((done, idx) => {
      assert.ok(done.share.skShare !== 0n)
      assert.ok(done.share.skShareDiv8 !== 0n)
      assert.strictEqual(done.share.id, idx + 1)
    })
    // All should derive the same group public key and viewing key
    const refPK = results[0]!.PKGroup
    const refVK = Buffer.from(results[0]!.viewingPrivateKey)
    results.forEach((r) => {
      assert.deepStrictEqual(r.PKGroup, refPK)
      assert.equal(Buffer.compare(Buffer.from(r.viewingPrivateKey), refVK), 0)
    })
  })

  it('trusted method: keygen -> signing end-to-end (3-of-5)', () => {
    const threshold = 3
    const n = 5

    const dkgManager = new DKGManager('test-participant-1')
    const secret = BigInt(0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn)

    const { groupPublicKey, shares, } = dkgManager.runTrustedKeygen(secret, n, threshold)

    const groupPK = groupPublicKey.map(p => BigInt(p)) as Point<bigint>
    const expectedGroupPK = [
      '0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6',
      '0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd'
    ]
    assert.deepStrictEqual(groupPublicKey, expectedGroupPK, 'derived group PK does not match.')

    const subset = shares.slice(0, threshold)

    // build signing managers
    const signers: FROSTSigningManager[] = []
    for (const f of subset) {
      const sm = new FROSTSigningManager(groupPK, threshold)
      sm.addSigner({ id: f.identifier, skShare: BigInt(f.skShare) })
      signers.push(sm)
    }

    // round 1 exchange
    for (const sm of signers) {
      sm.round1()
      const c = sm.exportRound1()
      for (const s of c) for (const sm2 of signers) if (!sm2.hasId(s.identifier)) sm2.addRemoteSigner(s)
    }

    // round 2
    const msg = 42069n
    const partials: { identifier: number, partial: bigint }[][] = []
    for (const sm of signers) partials.push(sm.sign(msg))
    for (const sm of signers) for (const p of partials) sm.receivePartials(p)

    const sig = signers[0]!.finalize(msg)
    const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(msg), sig, groupPK)
    assert.strictEqual(ok, true, 'coordinator-less flow signing verification failed')
  })

  it('coordinator-less flow: finalize -> signing end-to-end (3-of-5)', () => {
    const threshold = 3
    const secrets = [0x11n, 0x22n, 0x33n, 0x44n, 0x55n]
    const dealers: DKGManager[] = []

    // announcements and roster
    const announcements: Uint8Array[] = []
    for (let i = 0; i < secrets.length; i++) {
      const d = new DKGManager('test-participant-1')
      dealers.push(d)
      announcements.push(d.getAnnouncement().pubKey)
    }
    const roster: Record<number, Uint8Array> = {}
    announcements.forEach((a, idx) => { roster[idx + 1] = a })

    // commitment rounds and distribution
    const commitmentsByDealer: Record<number, ReturnType<DKGManager['commitmentRound']>['commitments']> = {}
    dealers.forEach((dealer, idx) => {
      dealer.assignRoster(roster)
      const { commitments: comms } = dealer.commitmentRound(secrets[idx]!, secrets.length, threshold)
      commitmentsByDealer[idx + 1] = comms
    })
    dealers.forEach((dealer) => {
      for (const idStr in commitmentsByDealer) {
        const id = Number(idStr)
        dealer.addParticipantCommitments(id, commitmentsByDealer[id]!)
      }
    })

    // encrypt shares and distribute
    const encryptedByDealerId: Record<number, ReturnType<DKGManager['getEncryptedShares']>> = {}
    dealers.forEach((dealer, idx) => { encryptedByDealerId[idx + 1] = dealer.getEncryptedShares() })
    dealers.forEach((dealer) => {
      for (const idStr in encryptedByDealerId) dealer.addEncryptedShares(Number(idStr), encryptedByDealerId[Number(idStr)]!)
    })

    // finalize and take first 3 signers
    const finalized = dealers.map((d) => d.finalize())
    const groupPublicKey = finalized[0]!.PKGroup
    const subset = finalized.slice(0, threshold)

    // build signing managers
    const signers: FROSTSigningManager[] = []
    for (const f of subset) {
      const sm = new FROSTSigningManager(groupPublicKey, threshold)
      sm.addSigner({ id: f.share.id, skShare: f.share.skShare })
      signers.push(sm)
    }

    // round 1 exchange
    for (const sm of signers) {
      sm.round1()
      const c = sm.exportRound1()
      for (const s of c) for (const sm2 of signers) if (!sm2.hasId(s.identifier)) sm2.addRemoteSigner(s)
    }

    // round 2
    const msg = 42069n
    const partials: { identifier: number, partial: bigint }[][] = []
    for (const sm of signers) partials.push(sm.sign(msg))
    for (const sm of signers) for (const p of partials) sm.receivePartials(p)

    const sig = signers[0]!.finalize(msg)
    const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(msg), sig, groupPublicKey)
    assert.strictEqual(ok, true, 'coordinator-less flow signing verification failed')
  })

  it('coordinator-less flow: rejects an off-polynomial share during finalize', () => {
    const threshold = 3
    const secrets = [0x11n, 0x22n, 0x33n, 0x44n, 0x55n]
    const dealers: DKGManager[] = []

    const announcements: Uint8Array[] = []
    for (let i = 0; i < secrets.length; i++) {
      const d = new DKGManager('test-participant-1')
      dealers.push(d)
      announcements.push(d.getAnnouncement().pubKey)
    }
    const roster: Record<number, Uint8Array> = {}
    announcements.forEach((a, idx) => { roster[idx + 1] = a })

    const commitmentsByDealer: Record<number, ReturnType<DKGManager['commitmentRound']>['commitments']> = {}
    dealers.forEach((dealer, idx) => {
      dealer.assignRoster(roster)
      const { commitments: comms } = dealer.commitmentRound(secrets[idx]!, secrets.length, threshold)
      commitmentsByDealer[idx + 1] = comms
    })
    dealers.forEach((dealer) => {
      for (const idStr in commitmentsByDealer) {
        const id = Number(idStr)
        dealer.addParticipantCommitments(id, commitmentsByDealer[id]!)
      }
    })

    const encryptedByDealerId: Record<number, ReturnType<DKGManager['getEncryptedShares']>> = {}
    dealers.forEach((dealer, idx) => { encryptedByDealerId[idx + 1] = dealer.getEncryptedShares() })

    // Forge dealer 2's share to participant 1: encrypt an off-polynomial scalar
    // under the SAME commitment set (so the AES-GCM AAD digest still matches and
    // we exercise the Feldman check, not the AEAD tag). The honest ECDH key is
    // shared, so we read it from the victim (participant 1 == dealers[0]).
    const victim = dealers[0]!
    const ordered = Object.keys(commitmentsByDealer).map(Number).sort((a, b) => a - b)
      .map((id) => commitmentsByDealer[id]!)
    const sharedKey1to2 = victim.keysByID[2]!
    const forged = victim.dkg.encryptSharesAESGCMWithAAD(
      { 1: 12345n }, // arbitrary scalar, not on dealer 2's polynomial
      { 1: sharedKey1to2 },
      ordered
    )
    encryptedByDealerId[2]![1] = forged[1]!

    dealers.forEach((dealer) => {
      for (const idStr in encryptedByDealerId) dealer.addEncryptedShares(Number(idStr), encryptedByDealerId[Number(idStr)]!)
    })

    assert.throws(
      () => victim.finalize(),
      /invalid share from dealer 2: failed Feldman verification/,
      'finalize must reject a share inconsistent with the dealer commitments'
    )
  })
})
