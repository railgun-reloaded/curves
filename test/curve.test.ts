import assert from 'node:assert'
import { describe, it } from 'node:test'

import { addPoint } from '@zk-kit/baby-jubjub'

import { RailJubCurvePoint } from '../src/curve.js'

const c = new RailJubCurvePoint()

describe('RailJubCurvePoint point serialization guards', () => {
  it('SerializeElement rejects the identity point', () => {
    assert.throws(() => c.SerializeElement(c.Identity()), /group identity/)
  })

  it('round-trips a valid subgroup point', () => {
    const P = c.ScalarBaseMult(123456789n)
    const bytes = c.SerializeElement(P)
    assert.equal(bytes.length, 32)
    assert.ok(c.pointsEqual(c.DeserializeElement(bytes), P))
  })

  it('DeserializeElement rejects a wrong-length buffer', () => {
    assert.throws(() => c.DeserializeElement(new Uint8Array(31)), /invalid length/)
  })

  it('DeserializeElement rejects bytes that are not a valid curve point', () => {
    // The scalar 1 encodes y = 1, whose x-coordinate has no valid square root.
    assert.throws(() => c.DeserializeElement(c.toBytes(1n)), /invalid point encoding/)
  })

  it('DeserializeElement rejects a point outside the prime-order subgroup', () => {
    // subgroup point + the (0,-1) 2-torsion point: a valid curve point with x != 0
    // that is not killed by the subgroup order, so it must be rejected.
    const twoTorsion: [bigint, bigint] = [0n, c.fieldPrime - 1n]
    const nonSubgroup = addPoint(c.ScalarBaseMult(5n), twoTorsion)
    assert.notEqual(nonSubgroup[0], 0n, 'expected x != 0 so the point is decompressable')
    const bytes = c.SerializeElement(nonSubgroup)
    assert.throws(() => c.DeserializeElement(bytes), /prime-order subgroup/)
  })
})

describe('RailJubCurvePoint scalar serialization guards', () => {
  it('SerializeScalar rejects out-of-range scalars', () => {
    assert.throws(() => c.SerializeScalar(-1n), /out of range/)
    assert.throws(() => c.SerializeScalar(c.order), /out of range/)
  })

  it('round-trips an in-range scalar', () => {
    const s = 987654321n
    assert.equal(c.DeserializeScalar(c.SerializeScalar(s)), s)
  })

  it('DeserializeScalar rejects a wrong-length buffer', () => {
    assert.throws(() => c.DeserializeScalar(new Uint8Array(31)), /invalid length/)
  })

  it('DeserializeScalar rejects non-zero top bits', () => {
    const buf = new Uint8Array(32)
    buf[31] = 0xe0
    assert.throws(() => c.DeserializeScalar(buf), /top bits/)
  })

  it('DeserializeScalar rejects a scalar >= subgroup order', () => {
    assert.throws(() => c.DeserializeScalar(c.toBytes(c.order)), /out of range/)
  })
})

describe('RailJubCurvePoint field/scalar arithmetic', () => {
  it('invModOrder throws when no inverse exists (0)', () => {
    assert.throws(() => c.invModOrder(0n), /inverse does not exist/)
  })

  it('invModOrder is a true modular inverse', () => {
    const a = 424242n
    assert.equal(c.modOrder(a * c.invModOrder(a)), 1n)
  })

  it('modOrder and modCurveOrder normalize negatives', () => {
    assert.equal(c.modOrder(-1n), c.order - 1n)
    assert.equal(c.modCurveOrder(-1n), c.curveOrder - 1n)
  })

  it('RandomScalar returns an in-range scalar in both modes', () => {
    for (const rejection of [true, false]) {
      const s = c.RandomScalar(rejection)
      assert.ok(s >= 0n && s < c.order, `scalar out of range (rejection=${rejection})`)
    }
  })
})

describe('RailJubCurvePoint Montgomery mapping guards', () => {
  it('rejects x = 0 (v undefined)', () => {
    assert.throws(() => c.toMontgomery({ x: 0n, y: 5n }), /x = 0/)
  })

  it('rejects y = 1 (identity, not mappable)', () => {
    assert.throws(() => c.toMontgomery({ x: 5n, y: 1n }), /y = 1/)
  })

  it('maps a real subgroup point without throwing', () => {
    const P = c.ScalarBaseMult(7n)
    const { u, v } = c.toMontgomery({ x: P[0], y: P[1] })
    assert.ok(typeof u === 'bigint' && typeof v === 'bigint')
  })
})
