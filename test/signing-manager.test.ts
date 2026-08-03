import assert from 'node:assert'
import { describe, it } from 'node:test'

import { subOrder } from '@zk-kit/baby-jubjub'

import { eddsaBuild } from '../src/index.js'
import { FROSTSigningManager } from '../src/manager/signing.js'

/**
 * Reduce a value into the BabyJubJub subgroup order.
 * @param x Value to reduce.
 * @returns The reduced scalar.
 */
function mod (x: bigint) {
  const r = x % subOrder
  return r < 0n ? r + subOrder : r
}

const multiSigVector = [
  {
    id: 1,
    share: {
      id: 1,
      skShare: mod(BigInt('0x1d4260025e6e520d8daab9c1f9923b0c94c6ee643f051ff2526517535133804') * 8n),
      skShareDiv8: BigInt('0x1d4260025e6e520d8daab9c1f9923b0c94c6ee643f051ff2526517535133804')
    },
    PKGroup: [
      BigInt('0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6'),
      BigInt('0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd')
    ]
  },
  {
    id: 2,
    share: {
      id: 2,
      skShare: mod(BigInt('0x1d85f8d8e472e07cf9fb432c0debae008ff241ea77f69c1d8403ffb36343cf0') * 8n),
      skShareDiv8: BigInt('0x1d85f8d8e472e07cf9fb432c0debae008ff241ea77f69c1d8403ffb36343cf0')
    },
    PKGroup: [
      BigInt('0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6'),
      BigInt('0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd')
    ]
  },
  {
    id: 3,
    share: {
      id: 3,
      skShare: mod(BigInt('0x442308b78d3cf348e735520c35d77dfb70167d82e334d911afbd7f02497c653') * 8n),
      skShareDiv8: BigInt('0x442308b78d3cf348e735520c35d77dfb70167d82e334d911afbd7f02497c653')
    },
    PKGroup: [
      BigInt('0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6'),
      BigInt('0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd')
    ]
  }
]

describe('BabyFrost Signing Manager', () => {
  it('should run e2e signing manager flow', () => {
    const signers = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }

    const message = 12345n
    const commitments = []
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      commitments.push(c)
      for (const s of c) {
        for (const s2 of signers) {
          if (!s2.hasId(s.identifier)) {
            s2.addRemoteSigner(s)
          }
        }
      }
    }
    const partials = []
    for (const signer of signers) {
      partials.push(signer.sign(message))
    }
    for (const signer of signers) {
      for (const p of partials) {
        signer.receivePartials(p)
      }
    }
    const sig = signers[0]!.finalize(message)
    const ok = eddsaBuild.verifyPoseidon(signers[0]!.frost.toBytes(message).toReversed(), sig, signers[0]!.groupPublicKey)
    assert(ok, 'validation failed')
  })

  it('exposes participant/partials helper methods', () => {
    // create managers for each participant
    const signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }

    const message = 12345n

    // round 1 and exchange commitments
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) {
        for (const s2 of signers) {
          if (!s2.hasId(s.identifier)) {
            s2.addRemoteSigner(s)
          }
        }
      }
    }

    // helpers should reflect all participants and no partials yet
    for (const signer of signers) {
      assert.deepStrictEqual(signer.expectedParticipantIds(), [1, 2, 3])
      assert.deepStrictEqual(signer.getMissingPartials(), [1, 2, 3])
      assert.equal(signer.readyToFinalize(), false)
      // cannot finalize yet
      assert.throws(() => signer.finalize(message))
    }

    // produce and exchange partials
    const partials: { identifier: number, partial: bigint }[][] = []
    for (const signer of signers) {
      partials.push(signer.sign(message))
    }
    for (const signer of signers) {
      for (const p of partials) signer.receivePartials(p)
      assert.deepStrictEqual(signer.getMissingPartials(), [])
      assert.equal(signer.readyToFinalize(), true)
    }

    // reset and ensure state is cleared
    for (const signer of signers) {
      signer.resetRoundState()
      assert.throws(() => signer.expectedParticipantIds())
      assert.throws(() => signer.finalize(message))
    }
  })

  it('finalize rejects a corrupted remote partial', () => {
    const signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }
    const message = 12345n
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) for (const s2 of signers) if (!s2.hasId(s.identifier)) s2.addRemoteSigner(s)
    }
    const partials = signers.map(s => s.sign(message))
    for (const signer of signers) for (const p of partials) signer.receivePartials(p)

    // Corrupt a remote partial held by signer 0 (local id = 1, so id 2 is remote
    // and cannot be caught by the local-share verification). The aggregate
    // self-check must reject it instead of returning an invalid signature.
    signers[0]!.partialsById.set(2, 123456789n)
    assert.throws(() => signers[0]!.finalize(message), /Aggregate signature failed verification/)
  })

  it('resetRoundState clears partials so they cannot carry into a new round', () => {
    const signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }
    const message = 12345n
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) for (const s2 of signers) if (!s2.hasId(s.identifier)) s2.addRemoteSigner(s)
    }
    const partials = signers.map(s => s.sign(message))
    for (const signer of signers) for (const p of partials) signer.receivePartials(p)
    assert.equal(signers[0]!.readyToFinalize(), true)

    // resetRoundState() drops stale partials so they cannot be aggregated
    // against freshly generated nonces in a subsequent round.
    signers[0]!.resetRoundState()
    assert.equal(signers[0]!.partialsById.size, 0)

    // A fresh round + re-exchange has commitments but no partials yet.
    signers[0]!.round1()
    for (const signer of signers) {
      const c = signer.exportRound1()
      for (const s of c) if (!signers[0]!.hasId(s.identifier)) signers[0]!.addRemoteSigner(s)
    }
    assert.equal(signers[0]!.readyToFinalize(), false)
  })

  it('readyToFinalize requires every participant when the set exceeds threshold', () => {
    // 3 participants commit but threshold is only 2. The commitment list (and
    // thus the Lagrange interpolation) spans all 3, so finalize needs all 3
    // partials. readyToFinalize must not report ready at merely `threshold`.
    const signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 2)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }
    const message = 12345n
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) for (const s2 of signers) if (!s2.hasId(s.identifier)) s2.addRemoteSigner(s)
    }
    const partials = signers.map(s => s.sign(message))

    const target = signers[0]!
    // Deliver only 2 of 3 partials (threshold-many) — must NOT be ready.
    target.receivePartials(partials[0]!)
    target.receivePartials(partials[1]!)
    assert.equal(target.readyToFinalize(), false, 'threshold-many partials is not enough when set > threshold')
    assert.throws(() => target.finalize(message), /Missing partials/)

    // Deliver the last partial — now the full set is present.
    target.receivePartials(partials[2]!)
    assert.equal(target.readyToFinalize(), true)
    const sig = target.finalize(message)
    const ok = eddsaBuild.verifyPoseidon(target.frost.toBytes(message).toReversed(), sig, target.groupPublicKey)
    assert(ok, 'aggregate over full participant set must verify')
  })

  it('round1 rejects re-committing a session without reset', () => {
    const v = multiSigVector[0]!
    const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    signer.addSigner({ id: v.id, skShare: v.share.skShare })

    signer.round1()
    // A second round1() would regenerate local nonces while peers still hold the
    // previous commitments; the session must reject it.
    assert.throws(() => signer.round1(), /already committed/)

    // reset() (here via the flat wrapper) is the documented restart path.
    signer.resetRoundState()
    assert.doesNotThrow(() => signer.round1())
  })

  it('addSigner rejects a duplicate identifier', () => {
    const v = multiSigVector[0]!
    const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    signer.addSigner({ id: v.id, skShare: v.share.skShare })
    assert.throws(() => signer.addSigner({ id: v.id, skShare: v.share.skShare }), /already added/)
  })

  it('finalize rejects a message different from the one signed', () => {
    const signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) for (const s2 of signers) if (!s2.hasId(s.identifier)) s2.addRemoteSigner(s)
    }
    const partials = signers.map(s => s.sign(12345n))
    for (const signer of signers) for (const p of partials) signer.receivePartials(p)
    assert.throws(() => signers[0]!.finalize(99999n), /does not match the message signed/)
  })

  it('drives two concurrent sessions on one manager without interference', () => {
    // Each participant runs sessions 'A' and 'B' on a single manager, signing
    // two different messages. The sessions must not leak state into each other.
    const managers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const m = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      m.addSigner({ id: v.id, skShare: v.share.skShare })
      managers.push(m)
    }

    /**
     * Drive one full signing session end-to-end on every manager.
     * @param sessionId Session identifier to run on each manager.
     * @param message Message scalar to sign in this session.
     * @returns The verified aggregate signature.
     */
    const runSession = (sessionId: string, message: bigint) => {
      const sessions = managers.map(m => m.startSession(sessionId))
      for (let i = 0; i < sessions.length; i++) {
        sessions[i]!.round1()
        const c = sessions[i]!.exportRound1()
        for (const cm of c) {
          for (let j = 0; j < sessions.length; j++) {
            if (!managers[j]!.hasId(cm.identifier)) sessions[j]!.addRemoteSigner(cm)
          }
        }
      }
      const partials = sessions.map(s => s.sign(message))
      for (const s of sessions) for (const p of partials) s.receivePartials(p)
      const sig = sessions[0]!.finalize(message)
      const ok = eddsaBuild.verifyPoseidon(managers[0]!.frost.toBytes(message).toReversed(), sig, managers[0]!.groupPublicKey)
      assert(ok, `session ${sessionId} signature must verify`)
      return sig
    }

    const sigA = runSession('A', 11111n)
    const sigB = runSession('B', 22222n)
    // Distinct messages must yield distinct aggregate signatures.
    assert.notDeepStrictEqual(sigA, sigB)
    // Both sessions remain independently retrievable on each manager.
    for (const m of managers) {
      assert.ok(m.hasSession('A') && m.hasSession('B'))
    }
  })

  it('survives a mid-round snapshot/restore mid signing flow', () => {
    let signers: FROSTSigningManager[] = []
    for (const v of multiSigVector) {
      const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
      signer.addSigner({ id: v.id, skShare: v.share.skShare })
      signers.push(signer)
    }
    const message = 12345n

    // round 1 + commitment exchange
    for (const signer of signers) {
      signer.round1()
      const c = signer.exportRound1()
      for (const s of c) for (const s2 of signers) if (!s2.hasId(s.identifier)) s2.addRemoteSigner(s)
    }

    // Snapshot after commitments are exchanged but before any partials, then
    // rebuild from the parsed JSON — simulating a process restart mid-flow. The
    // restored managers must keep the SAME local nonces, or the partials they
    // produce won't match the commitments their peers already hold.
    signers = signers.map((s) => FROSTSigningManager.fromMidRoundJSON(JSON.parse(JSON.stringify(s.toMidRoundJSON()))))

    // round 2 continues on the restored managers
    const partials = signers.map((s) => s.sign(message))
    for (const signer of signers) for (const p of partials) signer.receivePartials(p)

    const sig = signers[0]!.finalize(message)
    const ok = eddsaBuild.verifyPoseidon(signers[0]!.frost.toBytes(message).toReversed(), sig, signers[0]!.groupPublicKey)
    assert(ok, 'signature from restored managers must verify')

    // a restored session reports its collected partials and stays finalizable
    const reloaded = FROSTSigningManager.fromMidRoundJSON(JSON.parse(JSON.stringify(signers[0]!.toMidRoundJSON())))
    assert.equal(reloaded.readyToFinalize(), true)
  })

  it('the default snapshot carries no nonces and drops committed sessions', () => {
    const v = multiSigVector[0]!
    const m = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    m.addSigner({ id: v.id, skShare: v.share.skShare })
    m.startSession('pending')          // uncommitted: safe to carry
    m.startSession('live').round1()    // committed: holds live nonces

    const safe = JSON.parse(JSON.stringify(m))
    assert.equal(safe.kind, 'safe')
    assert.deepStrictEqual(safe.omittedSessions, ['live'])
    assert.deepStrictEqual(safe.sessions.map((x: { id: string }) => x.id), ['pending'])
    // no nonce material may appear anywhere in a safe payload
    assert.equal(JSON.stringify(safe).includes('hidingNonce"'), false)
    assert.equal(safe.sessions.every((x: { localBindings: unknown[] }) => x.localBindings.length === 0), true)
  })

  it('the mid-round snapshot keeps committed sessions and their nonces', () => {
    const v = multiSigVector[0]!
    const m = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    m.addSigner({ id: v.id, skShare: v.share.skShare })
    m.startSession('live').round1()

    const mid = JSON.parse(JSON.stringify(m.toMidRoundJSON()))
    assert.equal(mid.kind, 'mid-round')
    assert.deepStrictEqual(mid.sessions.map((x: { id: string }) => x.id), ['live'])
    assert.ok(mid.sessions[0].localBindings[0].nonces.hidingNonce)
  })

  it('the two restore paths refuse each other\'s snapshots', () => {
    const v = multiSigVector[0]!
    const m = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    m.addSigner({ id: v.id, skShare: v.share.skShare })
    m.startSession('live').round1()

    // a nonce-bearing payload must not restore through the safe entry point
    assert.throws(() => FROSTSigningManager.fromJSON(m.toMidRoundJSON()), /mid-round snapshot and carries live nonces/)
    // and the single-use entry point must not be fed a safe payload
    assert.throws(() => FROSTSigningManager.fromMidRoundJSON(m.toJSON()), /expected a mid-round snapshot/)
  })
})
