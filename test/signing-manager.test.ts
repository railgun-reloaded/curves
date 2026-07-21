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
})
