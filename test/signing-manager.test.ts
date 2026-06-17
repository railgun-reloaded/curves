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

  it('round1 clears partials collected for a previous round', () => {
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

    // Re-running round1 must drop stale partials so they cannot be aggregated
    // against the freshly generated nonces.
    signers[0]!.round1()
    assert.equal(signers[0]!.partialsById.size, 0)
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

  it('sign rejects a second round1 without resetRoundState (stale local nonces)', () => {
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

    // Start a fresh round on signer 0 but forget to resetRoundState(): its local
    // nonces are regenerated while the remote commitments are now a round behind.
    signers[0]!.round1()
    assert.throws(() => signers[0]!.sign(message), /without resetRoundState/)

    // The documented recovery path clears the round and re-exchanges.
    signers[0]!.resetRoundState()
    signers[0]!.round1()
    for (const signer of signers) {
      const c = signer.exportRound1()
      for (const s of c) if (!signers[0]!.hasId(s.identifier)) signers[0]!.addRemoteSigner(s)
    }
    assert.doesNotThrow(() => signers[0]!.sign(message))
  })

  it('addSigner rejects a duplicate identifier', () => {
    const v = multiSigVector[0]!
    const signer = new FROSTSigningManager(v.PKGroup as [bigint, bigint], 3)
    signer.addSigner({ id: v.id, skShare: v.share.skShare })
    assert.throws(() => signer.addSigner({ id: v.id, skShare: v.share.skShare }), /already added/)
  })
})
