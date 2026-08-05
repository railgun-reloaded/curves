import assert from 'node:assert'
import { describe, it } from 'node:test'

import type { Point } from '@zk-kit/baby-jubjub'
import { addPoint, inCurve, subOrder } from '@zk-kit/baby-jubjub'

import { BabyFROST } from '../src/frost/index.js'
import type { Commitment } from '../src/frost/types.js'
import { FROSTSigningManager } from '../src/manager/signing.js'

const frost = new BabyFROST()

/**
 * Reduce a value into the BabyJubJub subgroup order.
 * @param x Value to reduce.
 * @returns The reduced scalar.
 */
const mod = (x: bigint) => {
  const r = x % subOrder
  return r < 0n ? r + subOrder : r
}

const PK_GROUP: Point<bigint> = [
  BigInt('0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6'),
  BigInt('0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefd')
]
const SK_SHARE = mod(BigInt('0x1d4260025e6e520d8daab9c1f9923b0c94c6ee643f051ff2526517535133804') * 8n)

/** An honest, well-formed commitment point. */
const VALID = frost.ScalarBaseMult(7n)

/** A point of order two: on the curve, outside the prime-order subgroup. */
const ORDER_TWO: Point<bigint> = [0n, frost.fieldPrime - 1n]

/** On the curve, but with a cofactor component the subgroup test must catch. */
const NON_SUBGROUP = addPoint(VALID, ORDER_TWO)

/** Not a curve point at all. */
const OFF_CURVE: Point<bigint> = [12345n, 67890n]

/** The group identity, which encodes a zero nonce commitment. */
const IDENTITY: Point<bigint> = [0n, 1n]

const BAD_POINTS: Array<[string, Point<bigint>, RegExp]> = [
  ['an off-curve point', OFF_CURVE, /not on the curve/],
  ['a point of order two', ORDER_TWO, /not in the prime-order subgroup/],
  ['a point with a cofactor component', NON_SUBGROUP, /not in the prime-order subgroup/],
  ['the identity', IDENTITY, /identity/]
]

/**
 * Builds a round-1 commitment carrying the given point in both slots.
 * @param P Point to place in both nonce commitment slots.
 * @param identifier Participant identifier.
 * @returns The commitment.
 */
const commitmentWith = (P: Point<bigint>, identifier = 2n): Commitment => ({
  identifier,
  hidingNonceCommitment: P,
  bindingNonceCommitment: P
})

describe('nonce commitment point validation', () => {
  it('sanity-checks the fixtures', () => {
    assert.equal(inCurve(VALID), true)
    assert.equal(inCurve(NON_SUBGROUP), true, 'the cofactor fixture must be on the curve')
    assert.equal(inCurve(OFF_CURVE), false)
  })

  describe('BabyFROST.encodeGroupCommitmentList', () => {
    it('accepts an honest commitment', () => {
      assert.doesNotThrow(() => frost.encodeGroupCommitmentList([commitmentWith(VALID)]))
    })

    for (const [label, P, message] of BAD_POINTS) {
      it(`rejects ${label}`, () => {
        assert.throws(() => frost.encodeGroupCommitmentList([commitmentWith(P)]), message)
      })
    }

    it('rejects a bad binding nonce even when the hiding nonce is honest', () => {
      const mixed: Commitment = {
        identifier: 2n,
        hidingNonceCommitment: VALID,
        bindingNonceCommitment: OFF_CURVE
      }
      assert.throws(() => frost.encodeGroupCommitmentList([mixed]), /binding nonce/)
    })
  })

  describe('SigningSession.addRemoteSigner', () => {
    /**
     * Builds a manager holding one local signer.
     * @returns The manager.
     */
    const manager = () => {
      const m = new FROSTSigningManager(PK_GROUP, 2)
      m.addSigner({ id: 1, skShare: SK_SHARE })
      m.round1()
      return m
    }

    it('accepts an honest peer commitment', () => {
      assert.doesNotThrow(() => manager().addRemoteSigner(commitmentWith(VALID)))
    })

    for (const [label, P, message] of BAD_POINTS) {
      it(`rejects ${label} at ingestion`, () => {
        assert.throws(() => manager().addRemoteSigner(commitmentWith(P)), message)
      })
    }

    it('names the offending peer', () => {
      assert.throws(() => manager().addRemoteSigner(commitmentWith(OFF_CURVE, 5n)), /commitment 5/)
    })

    it('leaves the session usable after a rejected peer', () => {
      const m = manager()
      assert.throws(() => m.addRemoteSigner(commitmentWith(OFF_CURVE, 5n)))
      assert.doesNotThrow(() => m.addRemoteSigner(commitmentWith(VALID, 2n)))
    })
  })

  describe('snapshot restore', () => {
    it('rejects a tampered commitment point in a snapshot', () => {
      const m = new FROSTSigningManager(PK_GROUP, 2)
      m.addSigner({ id: 1, skShare: SK_SHARE })
      m.round1()
      m.addRemoteSigner(commitmentWith(VALID, 2n))

      // A committed session only survives the single-use mid-round snapshot; the
      // safe form drops it, so tamper with the form that actually carries the
      // peer commitments.
      const snap = JSON.parse(JSON.stringify(m.toMidRoundJSON())) as any
      const remotes = snap.sessions[0].remoteSigners
      assert.ok(Array.isArray(remotes) && remotes.length > 0, 'expected a remote signer in the snapshot')
      remotes[0].hidingNonceCommitment = [
        '0x' + OFF_CURVE[0].toString(16),
        '0x' + OFF_CURVE[1].toString(16)
      ]

      assert.throws(() => FROSTSigningManager.fromMidRoundJSON(snap), /not on the curve/)
    })
  })
})
