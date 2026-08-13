import assert from 'node:assert'
import { describe, it } from 'node:test'

import { DKGManager } from '../src/manager/dkg.js'
import { FROSTSigningManager } from '../src/manager/signing.js'

describe('DKGManager input + flow guards', () => {
  it('runTrustedKeygen validates share/threshold params', () => {
    const m = new DKGManager('p')
    assert.throws(() => m.runTrustedKeygen(1n, 3, 5), /threshold cannot exceed/)
    assert.throws(() => m.runTrustedKeygen(1n, 0, 1), /desiredShares must be a positive integer/)
    assert.throws(() => m.runTrustedKeygen(1n, 5, 0), /threshold must be a positive integer/)
  })

  it('assignRoster validates roster shape and self-membership', () => {
    const m = new DKGManager('p')
    assert.throws(() => m.assignRoster({}), /empty roster/)
    assert.throws(() => m.assignRoster({ 1: new Uint8Array(31) }), /bad roster pubkey/)
    const other = new DKGManager('q')
    assert.throws(() => m.assignRoster({ 1: other.getAnnouncement().pubKey }), /not present in roster/)
  })

  it('rejects out-of-order flow transitions', () => {
    const m = new DKGManager('p')
    assert.throws(() => m.commitmentRound(1n, 5, 3), /missing participant identifier/)
    assert.throws(() => m.getEncryptedShares(), /invalid state/)
    assert.throws(() => m.finalize(), /missing participant identifier/)
  })

  it('rejects re-assigning the roster', () => {
    const m = new DKGManager('p')
    const roster = { 1: m.getAnnouncement().pubKey }
    m.assignRoster(roster)
    assert.throws(() => m.assignRoster(roster), /invalid state/)
  })
})

describe('FROSTSigningManager flow guards', () => {
  const dkg = new DKGManager('p')
  const trusted = dkg.runTrustedKeygen(0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn, 5, 3)
  const pk = trusted.groupPublicKey.map((c: string) => BigInt(c)) as [bigint, bigint]
  const shares = trusted.shares

  /**
   * Build a signing manager seeded with the share at the given roster index.
   * @param i Index into the dealt shares.
   * @returns A signing manager holding that share.
   */
  const mkSigner = (i: number) => {
    const sm = new FROSTSigningManager(pk, 3)
    sm.addSigner({ id: shares[i]!.identifier, skShare: BigInt(shares[i]!.skShare) })
    return sm
  }

  it('sign throws when commitments are below threshold', () => {
    const sm = mkSigner(0)
    sm.round1()
    assert.throws(() => sm.sign(42069n), /Insufficient commitments/)
  })

  it('finalize throws when partials are missing', () => {
    const signers = [mkSigner(0), mkSigner(1), mkSigner(2)]
    for (const s of signers) {
      s.round1()
      for (const c of s.exportRound1()) for (const p of signers) if (!p.hasId(c.identifier)) p.addRemoteSigner(c)
    }
    assert.throws(() => signers[0]!.finalize(42069n), /Missing partials/)
  })

  it('addRemoteSigner ignores duplicate identifiers', () => {
    const a = mkSigner(0)
    const b = mkSigner(1)
    a.round1()
    b.round1()
    const [cb] = b.exportRound1()
    a.addRemoteSigner(cb!)
    a.addRemoteSigner(cb!)
    assert.equal(a.remoteSigners.length, 1)
  })

  it('addSigner rejects non-positive and non-integer identifiers', () => {
    // Identifier 0 is the evaluation point of the shared secret itself, so it
    // can never be a participant id.
    const sm = new FROSTSigningManager(pk, 3)
    assert.throws(() => sm.addSigner({ id: 0, skShare: 5n }), /must be positive integers/)
    assert.throws(() => sm.addSigner({ id: -1, skShare: 5n }), /must be positive integers/)
    assert.throws(() => sm.addSigner({ id: 1.5, skShare: 5n }), /must be positive integers/)
    assert.equal(sm.signers.length, 0)
  })

  it('addRemoteSigner rejects a peer announcing identifier 0', () => {
    const a = mkSigner(0)
    const b = mkSigner(1)
    a.round1()
    b.round1()
    const [cb] = b.exportRound1()
    const forged = { ...cb!, identifier: 0n }
    assert.throws(() => a.addRemoteSigner(forged), /must be positive integers/)
    assert.equal(a.remoteSigners.length, 0)
  })

  it('round1 discards partials received before this node committed', () => {
    // receivePartials() has no ordering guard, so a partial can arrive before
    // round1(). Such a partial cannot have been computed against a commitment
    // list containing ours, so a fresh round must not aggregate it.
    const a = mkSigner(0)
    a.receivePartials([{ identifier: 2, partial: 123456789n }])
    assert.equal(a.partialsById.size, 1)
    a.round1()
    assert.equal(a.partialsById.size, 0)
  })

  it('getEncryptedShares names the self-commitment case instead of stalling', () => {
    // commitmentRound() does not self-add. A caller written against the older
    // self-adding behaviour would otherwise sit at commitments-created waiting
    // on its own id with no indication why.
    const secrets = [0x11n, 0x22n, 0x33n]
    const dealers = secrets.map(() => new DKGManager('p'))
    const roster: Record<number, Uint8Array> = {}
    dealers.forEach((d, i) => { roster[i + 1] = d.getAnnouncement().pubKey })
    dealers.forEach(d => d.assignRoster(roster))
    const comms: Record<number, ReturnType<DKGManager['commitmentRound']>['commitments']> = {}
    dealers.forEach((d, i) => { comms[i + 1] = d.commitmentRound(secrets[i]!, 3, 2).commitments })
    // old caller pattern: feed in only the OTHER dealers' commitments
    dealers.forEach((d, i) => {
      for (const idStr of Object.keys(comms)) {
        const id = Number(idStr)
        if (id !== i + 1) d.addParticipantCommitments(id, comms[id]!)
      }
    })
    assert.deepStrictEqual(dealers[0]!.progress().awaitingCommitments, [1])
    assert.throws(() => dealers[0]!.getEncryptedShares(), /awaiting this participant's own commitments/)
  })
})
