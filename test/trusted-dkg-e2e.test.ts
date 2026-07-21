/* eslint-disable camelcase */
import assert from 'node:assert'
import { describe, it } from 'node:test'

import type { Point } from '@zk-kit/baby-jubjub'

import { eddsaBuild } from '../src/eddsa/index.js'
import { BabyFROST, TrustedDKG } from '../src/frost/index.js'
// import { BabyFROST } from '../src/frost/babyfrost.js'
import type { Commitment } from '../src/frost/types.js'
import { poseidonHex } from '../src/index.js'

describe('TrustedDKG', () => {
  const dkg = new TrustedDKG()

  describe('Test Vector Validation', () => {
    it('should match FROST test vectors for 3-of-5 threshold scheme', () => {
      const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn
      const a1 = 0x57ea51a2f5712861d3e3125c7b81f081b19c40b04894abf76d35429f2eef8a3n
      const a2 = 0x439109f6f2946257f8c508718b4a86e0cc73e1cae22dd0b7b8a20a59331d5b4n

      const expectedShares = [
        0x1d4260025e6e520d8daab9c1f9923b0c94c6ee643f051ff2526517535133804n, // Participant 1
        0x1d85f8d8e472e07cf9fb432c0debae008ff241ea77f69c1d8403ffb36343cf0n, // Participant 2
        0x442308b78d3cf348e735520c35d77dfb70167d82e334d911afbd7f02497c653n, // Participant 3
        0x3050f2b896694a1de4b85af56e52fa428144c5a9eeb0f6285e68177c71cad3cn, // Participant 4
        0x42d853c1c25b254f6324e954ba60d390776bf5e32c79d408072d46e56e4189cn  // Participant 5
      ]

      const expectedPubKeys = [
        [
          0x2ebc885681e45848f34ee1050a827eca10e8fb24cbb64a091901d96911480cc2n,
          0x482f7210ba3665fbe23bc0eab393f7266a36008186bb7c6781b1017612e49b4n
        ],
        [
          0x26dd7c7370505a2496012e97bae1a23e9439661f90c0f15aac26ed1cd606535fn,
          0x2a770f7fc5a26df9427cde7456ba495a2b2eb89c6a1be3273d9d982d5417bd01n
        ],
        [
          0x1136b9efcaf9dc8b3b20bf463151645d49a2b33be95a4a36c3833e7a66453e65n,
          0x28146163f1cf5182296a46ed9523b521e37f8eb312ac3d209f4d0a629b474445n
        ],
        [
          0x1a78e7b5302f95764b22448764ca2ecac418116b52332882d77868f2db086c33n,
          0x178597d7aea8a7e82b223cb8a0626d776a217caf7f1988bfa775d73d49e26f0bn
        ],
        [
          0x2d91b9147ee0817f26f33eb7b759b4702577e429f80097aa07c7deb69dd6f562n,
          0x71e39bb200f3b4c3e6c54134c5c1382590dbdf8500303525f3b585647cbe8edn
        ],
        [
          0x190260ab0b8674b7b20c22d37d9838cd5194d348745c7d4eba69feb1a5bfc749n,
          0x1c51721613b027faee6b242b213d8f534578c115d70746347d5590e10e2ce7f8n
        ]
      ]

      const expectedGroupPK = {
        x: 0x1e0762d6610a0b47f3b5e3f23f5f748fde5abb8843f33cf084c0dabd8dc813e6n,
        y: 0xb82b739e78dda57e75ac680ef689df1158fe3eed8095c6d4bd1b2c7c166eefdn
      }

      const coefficients = [a1, a2]
      const { secretKeyShares, coefficients: coeffs } = dkg.secretShareShard(secret, coefficients, 5)

      assert.strictEqual(coeffs[0], secret, 'First coefficient should be the secret')
      assert.strictEqual(coeffs[1], a1, 'Second coefficient should match a1')
      assert.strictEqual(coeffs[2], a2, 'Third coefficient should match a2')

      for (let i = 0; i < 5; i++) {
        const share = secretKeyShares[i]!
        assert.strictEqual(share.x_i, i + 1, `Participant ${i + 1} x-coordinate should be ${i + 1}`)
        assert.strictEqual(share.y_i, expectedShares[i], `Participant ${i + 1} secret share should match test vector`)
      }

      const vssCommitment = dkg.vssCommit(coeffs)

      for (let i = 1; i <= 5; i++) {
        const participantKey = secretKeyShares[i - 1]!
        const share = {
          i: BigInt(participantKey.x_i),
          sk_i: participantKey.y_i
        }
        const isValid = dkg.vssVerify(share, vssCommitment, 3)
        assert.strictEqual(isValid, true, `Participant ${i} share should be valid`)
      }

      const groupInfo = dkg.deriveGroupInfo(5, 3, vssCommitment)
      groupInfo.participantPublicKeys.forEach((p, idx) => {
        console.log(`Participant ${idx + 1}:`)
        console.log(`   Secret share:    0x${secretKeyShares[idx]!.y_i.toString(16)!}`)
        console.log(`   pubKey.x:        0x${p[0].toString(16)!}`)
        console.log(`   pubKey.y:        0x${p[1].toString(16)!}`)
        assert.equal(p[0], expectedPubKeys[idx]![0], 'Participant public key x-coordinate should match')
        assert.equal(p[1], expectedPubKeys[idx]![1], 'Participant public key y-coordinate should match')
      })
      assert.strictEqual(groupInfo.PK![0], expectedGroupPK.x, 'Group public key x-coordinate should match')
      assert.strictEqual(groupInfo.PK![1], expectedGroupPK.y, 'Group public key y-coordinate should match')

      const directGroupPK = dkg.ScalarBaseMult(secret)
      assert(dkg.pointsEqual(groupInfo.PK!, directGroupPK), 'Group PK should equal secret * Base')
    })

    it('should correctly evaluate polynomial with test vector coefficients', () => {
      const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn
      const a1 = 0x57ea51a2f5712861d3e3125c7b81f081b19c40b04894abf76d35429f2eef8a3n
      const a2 = 0x439109f6f2946257f8c508718b4a86e0cc73e1cae22dd0b7b8a20a59331d5b4n

      const coefficients = [secret, a1, a2]

      const p1 = dkg.polynomialEvaluate(1n, coefficients)

      assert.strictEqual(p1, 0x1d4260025e6e520d8daab9c1f9923b0c94c6ee643f051ff2526517535133804n)

      const p2 = dkg.polynomialEvaluate(2n, coefficients)
      assert.strictEqual(p2, 0x1d85f8d8e472e07cf9fb432c0debae008ff241ea77f69c1d8403ffb36343cf0n)

      const p3 = dkg.polynomialEvaluate(3n, coefficients)
      assert.strictEqual(p3, 0x442308b78d3cf348e735520c35d77dfb70167d82e334d911afbd7f02497c653n)

      const p0 = dkg.polynomialEvaluate(0n, coefficients)
      assert.strictEqual(p0, secret, 'Polynomial at x=0 should equal the secret')
    })
  })
})

describe('TrustedDKG end-to-end', () => {
  const dkg = new TrustedDKG()

  it('3-of-5 flow: dealer keygen -> Feldman verify -> finalize -> secret reconstruction', () => {
    const threshold = 3
    const n = 5

    // 1) Trusted dealer keygen (deterministic secret for reproducibility)
    const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn
    const { participantPrivateKeys: shares, coefficients, vssCommitment } = dkg.trustedDealerKeygen(secret, n, threshold)
    assert.equal(coefficients[0], secret, 'constant term must equal secret')
    assert.equal(vssCommitment.length, threshold, 'commitments length = threshold')

    // 2) Feldman verification for each participant share
    const finalized: Array<{ id: number; skShareDiv8: bigint; skShare: bigint }> = []
    for (let i = 0; i < n; i++) {
      const { x_i, y_i } = shares[i]!
      const ok = dkg.vssVerify({ i: BigInt(x_i), sk_i: y_i }, vssCommitment, threshold)
      assert.strictEqual(ok, true, `vssVerify failed for id ${x_i}`)
      // coordinator-less finalize for this single-dealer case
      const res = dkg.finalizeParticipant(x_i, [{ dealerId: 1, s_ki: y_i }], [vssCommitment])
      finalized.push({ id: x_i, skShareDiv8: res.share.skShareDiv8, skShare: res.share.skShare })
    }

    // 3) Derive group info and cross-check with direct Base*secret
    const group = dkg.deriveGroupInfo(n, threshold, vssCommitment)
    const directPK = dkg.ScalarBaseMult(secret)
    assert.strictEqual(dkg.pointsEqual(group.PK!, directPK), true, 'group PK mismatch')

    // 4) Coordinator-less finalize per participant using “single dealer” view
    // Build input in the multi-dealer shape: one dealer with our commitments, per-participant s_ki
    const allCommitments: Point<bigint>[][] = [vssCommitment]
    for (let i = 0; i < n; i++) {
      const { x_i, y_i } = shares[i]!
      const res = dkg.finalizeParticipant(x_i, [{ dealerId: 1, s_ki: y_i }], allCommitments)
      // skShareDiv8 equals underlying s_i
      assert.equal(res.share.skShareDiv8, y_i)
      assert.strictEqual(dkg.pointsEqual(res.PKGroup, group.PK!), true, 'finalized PKGroup mismatch')
    }

    // 5) Reconstruct secret from any threshold subset (ids 1,2,3)
    const subsetShares = shares.slice(0, threshold).map(({ x_i, y_i }) => ({ id: x_i, s_i: y_i }))
    const rec = dkg.reconstructConstantFromShares(subsetShares)
    assert.equal(rec, secret, 'reconstructed secret should equal original')

    // 6) Negative: Feldman verify should fail for tampered share
    const bad = dkg.modOrder(shares[0]!.y_i + 1n)
    const okBad1 = dkg.vssVerify({ i: BigInt(shares[0]!.x_i), sk_i: bad }, vssCommitment, threshold)
    assert.strictEqual(okBad1, false)
    // 7) Perform a FROST signing round with 3 participants; verify aggregate with EDDSA-Poseidon
    const frost = new BabyFROST()
    const groupPublicKey = group.PK!
    const subset = finalized.slice(0, threshold)
    const msgHash = BigInt('0x' + poseidonHex(['0x' + 12345n.toString(16)], true))
    const p1 = frost.commit(subset[0]!.skShare, BigInt(subset[0]!.id))
    const p2 = frost.commit(subset[1]!.skShare, BigInt(subset[1]!.id))
    const p3 = frost.commit(subset[2]!.skShare, BigInt(subset[2]!.id))
    const commitmentList: Commitment[] = [p1, p2, p3].map((a) => ({ ...a.commitments }))
    const s1 = frost.sign(p1.commitments.identifier, subset[0]!.skShare, groupPublicKey, p1.nonces, msgHash, commitmentList)
    const s2 = frost.sign(p2.commitments.identifier, subset[1]!.skShare, groupPublicKey, p2.nonces, msgHash, commitmentList)
    const s3 = frost.sign(p3.commitments.identifier, subset[2]!.skShare, groupPublicKey, p3.nonces, msgHash, commitmentList)
    const sig = frost.aggregate(commitmentList, msgHash, groupPublicKey, [s1, s2, s3])
    const okAgg = eddsaBuild.verifyPoseidon(frost.toBytes(msgHash).toReversed(), sig, groupPublicKey)
    assert.strictEqual(okAgg, true, 'FROST aggregate failed verification')
  })

  it('3-of-5 flow: FROST aggregate verifies for a non-contiguous signer subset {1,2,4}', () => {
    const threshold = 3
    const n = 5
    const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn
    const { participantPrivateKeys: shares, vssCommitment } = dkg.trustedDealerKeygen(secret, n, threshold)

    // Finalize every participant's signing share (single-dealer view).
    const finalized: Array<{ id: number; skShare: bigint }> = []
    for (let i = 0; i < n; i++) {
      const { x_i, y_i } = shares[i]!
      const res = dkg.finalizeParticipant(x_i, [{ dealerId: 1, s_ki: y_i }], [vssCommitment])
      finalized.push({ id: x_i, skShare: res.share.skShare })
    }

    const group = dkg.deriveGroupInfo(n, threshold, vssCommitment)
    const groupPublicKey = group.PK!

    // Sign with a non-contiguous threshold subset: participants 1, 2, and 4.
    // Their Lagrange interpolation values at zero are non-integers (λ_1 = 8/3),
    // so a truncating integer division would compute the wrong scalar and the
    // aggregate signature would fail to verify. Contiguous subsets like {1,2,3}
    // happen to yield integer coefficients and hide the bug.
    const frost = new BabyFROST()
    const subset = [finalized[0]!, finalized[1]!, finalized[3]!]
    assert.deepStrictEqual(subset.map((s) => s.id), [1, 2, 4], 'signing subset must be non-contiguous')

    const msgHash = BigInt('0x' + poseidonHex(['0x' + 12345n.toString(16)], true))
    const parts = subset.map((s) => frost.commit(s.skShare, BigInt(s.id)))
    const commitmentList: Commitment[] = parts.map((a) => ({ ...a.commitments }))
    const sigShares = subset.map((s, i) =>
      frost.sign(parts[i]!.commitments.identifier, s.skShare, groupPublicKey, parts[i]!.nonces, msgHash, commitmentList)
    )
    const sig = frost.aggregate(commitmentList, msgHash, groupPublicKey, sigShares)
    const okAgg = eddsaBuild.verifyPoseidon(frost.toBytes(msgHash).toReversed(), sig, groupPublicKey)
    assert.strictEqual(okAgg, true, 'FROST aggregate over non-contiguous subset {1,2,4} failed verification')
  })
})

describe('TrustedDKG coordinator-less end-to-end', () => {
  const dkg = new TrustedDKG()

  it('multi-dealer 3-of-5: per-dealer shares -> finalize -> reconstruct', () => {
    const threshold = 3
    const ids = [1, 2, 3, 4, 5]

    const dealers: Array<{ id: number; coeffs: bigint[] }> = [
      { id: 1, coeffs: dkg.trustedDealerKeygen(0x11n, 5, threshold).coefficients },
      { id: 2, coeffs: dkg.trustedDealerKeygen(0x22n, 5, threshold).coefficients },
      { id: 3, coeffs: dkg.trustedDealerKeygen(0x33n, 5, threshold).coefficients },
      { id: 4, coeffs: dkg.trustedDealerKeygen(0x44n, 5, threshold).coefficients },
      { id: 5, coeffs: dkg.trustedDealerKeygen(0x55n, 5, threshold).coefficients },
    ]

    // Commitments and per-dealer shares
    const commitmentsByDealer: Record<number, Point<bigint>[]> = {}
    const sharesByDealer: Record<number, Record<number, bigint>> = {}
    for (const d of dealers) {
      const C = dkg.vssCommit(d.coeffs)
      assert.equal(C.length, threshold, 'each dealer must produce t commitments')
      commitmentsByDealer[d.id] = C
      sharesByDealer[d.id] = dkg.computeSharesForIds(d.coeffs, ids)
    }

    // Aggregate commitments for group PK
    const allDealerCommitments = dealers.map(d => commitmentsByDealer[d.id]!)
    assert.strictEqual(dkg.verifyAllCommitmentsSubgroup(allDealerCommitments), true, 'commitments not in subgroup')
    const PKGroup = dkg.combineGroupPubkeyFromCommitments(allDealerCommitments)

    // Check group PK equals Base*(sum of dealers' a0)
    const a0_total = dealers.reduce((acc, d) => dkg.modOrder(acc + dkg.modOrder(d.coeffs[0]!)), 0n)
    const PKDirect = dkg.ScalarBaseMult(a0_total)
    assert.strictEqual(dkg.pointsEqual(PKGroup, PKDirect), true, 'group PK does not match sum of a0')

    // Feldman verify each per-dealer share, then finalize per participant by summing s_{k}(i)
    const finalized: Array<{ id: number; skShare: bigint }> = []
    for (const id of ids) {
      const s_ki_byDealer = dealers.map(d => ({ dealerId: d.id, s_ki: sharesByDealer[d.id]![id]! }))
      // verify each dealer share for this participant id
      for (const d of dealers) {
        const ok = dkg.vssVerify({ i: BigInt(id), sk_i: sharesByDealer[d.id]![id]! }, commitmentsByDealer[d.id]!, threshold)
        assert.strictEqual(ok, true, `Feldman verify failed for dealer ${d.id}, id ${id}`)
      }
      const res = dkg.finalizeParticipant(id, s_ki_byDealer, allDealerCommitments)
      const expectedDiv8 = s_ki_byDealer.reduce((acc, s) => dkg.modOrder(acc + dkg.modOrder(s.s_ki)), 0n)
      assert.equal(res.share.skShareDiv8, expectedDiv8, 'finalized share mismatch')
      assert.strictEqual(dkg.pointsEqual(res.PKGroup, PKGroup), true, 'PKGroup mismatch in finalization')
      finalized.push({ id, skShare: res.share.skShare })
    }

    // Reconstruct total a0 from aggregated shares of any 3 participants (e.g., ids 1,2,5)
    const recIds = [1, 2, 5]
    const aggregatedShares = recIds.map((id) => ({
      id,
      s_i: dealers.reduce((acc, d) => dkg.modOrder(acc + dkg.modOrder(sharesByDealer[d.id]![id]!)), 0n)
    }))
    const rec = dkg.reconstructConstantFromShares(aggregatedShares)
    assert.equal(rec, a0_total, 'reconstructed total a0 should equal sum of dealer a0')

    // FROST signing with 3 finalized participants; verify aggregate
    const frost = new BabyFROST()
    const groupPublicKey = PKGroup
    const signingSubset = finalized.slice(0, threshold)
    const msgHash = BigInt('0x' + poseidonHex(['0x' + 99999n.toString(16)], true))
    const p1 = frost.commit(signingSubset[0]!.skShare, BigInt(signingSubset[0]!.id))
    const p2 = frost.commit(signingSubset[1]!.skShare, BigInt(signingSubset[1]!.id))
    const p3 = frost.commit(signingSubset[2]!.skShare, BigInt(signingSubset[2]!.id))
    const commitmentList: Commitment[] = [p1, p2, p3].map((a) => ({ ...a.commitments }))
    const s1 = frost.sign(p1.commitments.identifier, signingSubset[0]!.skShare, groupPublicKey, p1.nonces, msgHash, commitmentList)
    const s2 = frost.sign(p2.commitments.identifier, signingSubset[1]!.skShare, groupPublicKey, p2.nonces, msgHash, commitmentList)
    const s3 = frost.sign(p3.commitments.identifier, signingSubset[2]!.skShare, groupPublicKey, p3.nonces, msgHash, commitmentList)
    const sig = frost.aggregate(commitmentList, msgHash, groupPublicKey, [s1, s2, s3])
    const okAgg = eddsaBuild.verifyPoseidon(frost.toBytes(msgHash).toReversed(), sig, groupPublicKey)
    assert.strictEqual(okAgg, true, 'FROST aggregate failed verification')
  })
})

describe('TrustedDKG coordinator-less extensions', () => {
  const dkg = new TrustedDKG()

  // fixed dealer coefficients for determinism (include constant term a0 first)
  const dealer1Coeffs = [
    0x11n, // a0
    0x22n, // a1
    0x33n, // a2 (threshold = 3)
  ]
  const dealer2Coeffs = [
    0x55n,
    0x66n,
    0x77n,
  ]

  it('computeSharesForIds matches polynomialEvaluate()', () => {
    const ids = [1, 2, 4]
    const shares = dkg.computeSharesForIds(dealer1Coeffs, ids)
    for (const id of ids) {
      const p = dkg.polynomialEvaluate(BigInt(id), dealer1Coeffs)
      assert.equal(shares[id], p, `share mismatch for id ${id}`)
    }
  })

  it('vssVerify succeeds for valid shares and fails for tampered', () => {
    const commitments = dkg.vssCommit(dealer1Coeffs)
    const ids = [1, 2, 3]
    const shares = dkg.computeSharesForIds(dealer1Coeffs, ids)
    for (const id of ids) {
      const ok = dkg.vssVerify({ i: BigInt(id), sk_i: shares[id]! }, commitments, commitments.length)
      assert.strictEqual(ok, true, `Feldman verify failed for id ${id}`)
      const bad = dkg.vssVerify({ i: BigInt(id), sk_i: dkg.modOrder(shares[id]! + 1n) }, commitments, commitments.length)
      assert.strictEqual(bad, false, `Feldman verify should fail for tampered share id ${id}`)
    }
  })

  it('combineGroupPubkeyFromCommitments equals Base*(sum of a0)', () => {
    const c1 = dkg.vssCommit(dealer1Coeffs)
    const c2 = dkg.vssCommit(dealer2Coeffs)
    const group = dkg.combineGroupPubkeyFromCommitments([c1, c2])
    const sumA0 = dkg.modOrder(dealer1Coeffs[0]! + dealer2Coeffs[0]!)
    const direct = dkg.ScalarBaseMult(sumA0)
    assert.strictEqual(dkg.pointsEqual(group, direct), true, 'group PK mismatch with a0 sum')
  })

  it('verifyAllCommitmentsSubgroup returns true for valid commitments', () => {
    const c1 = dkg.vssCommit(dealer1Coeffs)
    const c2 = dkg.vssCommit(dealer2Coeffs)
    const ok = dkg.verifyAllCommitmentsSubgroup([c1, c2])
    assert.strictEqual(ok, true)
  })

  it('finalizeParticipant aggregates s_ki and derives PKGroup', () => {
    const c1 = dkg.vssCommit(dealer1Coeffs)
    const c2 = dkg.vssCommit(dealer2Coeffs)
    const allComm = [c1, c2]
    const id = 2
    const s1 = dkg.polynomialEvaluate(BigInt(id), dealer1Coeffs)
    const s2 = dkg.polynomialEvaluate(BigInt(id), dealer2Coeffs)
    const res = dkg.finalizeParticipant(id, [
      { dealerId: 1, s_ki: s1 },
      { dealerId: 2, s_ki: s2 },
    ], allComm)
    const expectedDiv8 = dkg.modOrder(s1 + s2)
    assert.equal(res.share.skShareDiv8, expectedDiv8, 'skShareDiv8 should be sum of dealer shares')
    assert.equal(res.share.skShare, dkg.modOrder(8n * expectedDiv8), 'skShare should be x8 mod L')
    const group = dkg.combineGroupPubkeyFromCommitments(allComm)
    assert.strictEqual(dkg.pointsEqual(res.PKGroup, group), true, 'PKGroup mismatch')
  })

  it('assertSortedConsecutiveIds: accepts non-consecutive, rejects invalid/unsorted', () => {
    // non-consecutive is allowed
    assert.doesNotThrow(() => dkg.computeSharesForIds(dealer1Coeffs, [1, 3]))
    // unsorted must throw
    assert.throws(() => dkg.computeSharesForIds(dealer1Coeffs, [3, 1]), /strictly increasing positive integers/i)
    // invalid must throw
    assert.throws(() => dkg.computeSharesForIds(dealer1Coeffs, [0, 2]), /strictly increasing positive integers/i)
  })

  it('Lagrange basis sums to 1 and reconstructs constant term', () => {
    // simple linear polynomial a0 + a1*x
    const a0 = 0x1234n
    const a1 = 0x9n
    const coeffs = [a0, a1]
    const ids = [1n, 3n]
    const shares = ids.map((id) => ({ id: Number(id), s_i: dkg.polynomialEvaluate(id, coeffs) }))
    const lambdas = ids.map((id) => dkg.deriveInterpolatingValue(ids, id))
    const sum = lambdas.reduce((acc, l) => dkg.modOrder(acc + l), 0n)
    assert.equal(sum, 1n, 'sum of λ_i(0) should be 1')
    const rec = dkg.reconstructConstantFromShares(shares)
    assert.equal(rec, a0, 'reconstructed a0 should equal original')
  })

  it('verifyFeldmanShare rejects tampered/non-subgroup commitment', () => {
    const coeffs = [0x21n, 0x31n, 0x41n]
    const commits = dkg.vssCommit(coeffs)
    const id = 2
    const s = dkg.polynomialEvaluate(BigInt(id), coeffs)
    // tamper C0 with a bogus point (synthetic non-subgroup/invalid)
    const tampered = commits.slice()
    // Intentionally use an arbitrary pair; strict verifier should return false or gracefully handle
    tampered[0] = [1n, 1n] as any
    const ok = dkg.verifyFeldmanShare(id, s, tampered)
    assert.strictEqual(ok, false, 'tampered/non-subgroup commitment should fail Feldman verification')
  })
})
