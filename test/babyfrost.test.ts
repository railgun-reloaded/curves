import assert from 'node:assert'
import { describe, it } from 'node:test'

import { subOrder } from '@zk-kit/baby-jubjub'

import BabyFROST from '../src/frost/babyfrost.js'
import type { Commitment, Point } from '../src/index.js'
import { eddsaBuild, poseidonHex } from '../src/index.js'

// can skip the mod purely for tests, it passes without.
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

describe('BabyFrost RFC9591 spec implementation', () => {
  it('should properly compute signature', () => {
    const frost = new BabyFROST()
    const subset = [
      multiSigVector[0],
      multiSigVector[1],
      multiSigVector[2]
    ]
    const groupPublicKey = multiSigVector[0]!.PKGroup as Point<bigint>

    const msgHash = BigInt('0x' + poseidonHex(['0x' + 12345n.toString(16)], true))

    // round 1 commitment
    const p1 = frost.commit(subset[0]!.share.skShare, BigInt(subset[0]!.id))
    const p2 = frost.commit(subset[1]!.share.skShare, BigInt(subset[1]!.id))
    const p3 = frost.commit(subset[2]!.share.skShare, BigInt(subset[2]!.id))

    const commitmentList: Commitment[] = [p1, p2, p3].map((a) => {
      return { ...a.commitments }
    })

    const s1 = frost.sign(
      p1.commitments.identifier,
      subset[0]!.share.skShare,
      groupPublicKey,
      p1.nonces,
      msgHash,
      commitmentList
    )

    const s2 = frost.sign(
      p2.commitments.identifier,
      subset[1]!.share.skShare,
      groupPublicKey,
      p2.nonces,
      msgHash,
      commitmentList
    )

    const s3 = frost.sign(
      p3.commitments.identifier,
      subset[2]!.share.skShare,
      groupPublicKey,
      p3.nonces,
      msgHash,
      commitmentList
    )

    const verifications = [
      {
        commitments: p1.commitments,
        share: subset[0]!.share.skShare,
        partial: s1
      },
      {
        commitments: p2.commitments,
        share: subset[1]!.share.skShare,
        partial: s2
      },
      {
        commitments: p3.commitments,
        share: subset[2]!.share.skShare,
        partial: s3
      },
    ]

    for (const v of verifications) {
      const verified = frost.verifySignatureShare(
        v.commitments.identifier,
        v.share,
        v.commitments,
        v.partial,
        commitmentList,
        groupPublicKey,
        msgHash
      )
      assert(verified, `participant ${v.commitments.identifier} provided a share that failed verification`)
    }
    const sig = frost.aggregate(commitmentList, msgHash, groupPublicKey, [s1, s2, s3])
    const ok = eddsaBuild.verifyPoseidon(frost.toBytes(msgHash).toReversed(), sig, groupPublicKey)
    assert(ok, 'validation failed')
  })
})

describe('BabyFROST deriveInterpolatingValue identifier validation', () => {
  const f = new BabyFROST()

  it('rejects identifier 0, the evaluation point of the shared secret', () => {
    assert.throws(() => f.deriveInterpolatingValue([0n, 1n, 2n], 0n), /invalid parameters/)
  })

  it('rejects a signer set containing a non-positive identifier', () => {
    assert.throws(() => f.deriveInterpolatingValue([0n, 1n, 2n], 1n), /invalid parameters/)
    assert.throws(() => f.deriveInterpolatingValue([-1n, 1n, 2n], 1n), /invalid parameters/)
  })

  it('still rejects an identifier absent from the signer set', () => {
    assert.throws(() => f.deriveInterpolatingValue([1n, 2n, 3n], 9n), /invalid parameters/)
  })

  it('accepts a valid positive identifier', () => {
    assert.doesNotThrow(() => f.deriveInterpolatingValue([1n, 2n, 3n], 2n))
  })
})
