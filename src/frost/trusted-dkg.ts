/* eslint-disable camelcase */
/* eslint-disable jsdoc/require-jsdoc */

import { gcm } from '@noble/ciphers/aes.js'
import { concatBytes, randomBytes } from '@noble/hashes/utils.js'
import type { Point } from '@zk-kit/baby-jubjub'
import { addPoint, mulPointEscalar } from '@zk-kit/baby-jubjub'

import { RailJubCurvePoint } from '../curve.js'
import { RFC9591Hasher } from '../hashing.js'

import type { EncryptedShare } from './types.js'

/**
 * Trusted-dealer and coordinator-less DKG primitive helpers for Baby Jubjub FROST.
 *
 * This class exposes the math and encrypted-share transport helpers used by
 * `DKGManager`, but does not enforce end-to-end protocol sequencing itself.
 */
class TrustedDKG extends RailJubCurvePoint {
  public readonly contextString = 'FROST-EDBABYJUJUB-BLAKE512-v1'
  hasher: RFC9591Hasher

  /** Creates a DKG helper bound to the default hash context. */
  constructor () {
    super()
    this.hasher = new RFC9591Hasher(this.contextString, this.order)
  }

  /**
   * Evaluates the sharing polynomial for a participant identifier.
   * @param x Participant identifier.
   * @param coefficients Polynomial coefficients in ascending order.
   * @returns The polynomial value modulo the subgroup order.
   */
  polynomialEvaluate (x: bigint, coefficients: bigint[]) {
    let value = 0n
    for (let i = coefficients.length - 1; i >= 0; i--) {
      value *= x
      value += coefficients[i]!
    }
    return this.modOrder(value)
  }

  /**
   * Generates trusted-dealer coefficients, shares, and commitments.
   * @param secretKey Dealer secret used as the constant term, which is the polynomial's base value.
   * @param MAX_PARTICIPANTS Total number of participant shares to generate.
   * @param MIN_PARTICIPANTS Threshold required for reconstruction or signing.
   * @returns Dealer shares, polynomial coefficients, and public commitments.
   */
  trustedDealerKeygen (secretKey: bigint, MAX_PARTICIPANTS: number, MIN_PARTICIPANTS: number) {
    const coefficients: bigint[] = []
    for (let i = 0; i < MIN_PARTICIPANTS - 1; i++) {
      coefficients.push(this.RandomScalar())
    }
    const { secretKeyShares: participantPrivateKeys, coefficients: coeffs } = this.secretShareShard(secretKey, coefficients, MAX_PARTICIPANTS)
    const vssCommitment = this.vssCommit(coeffs)
    return {
      participantPrivateKeys,
      coefficients: coeffs,
      base: vssCommitment[0]!,
      vssCommitment
    }
  }

  /**
   * Computes Baby Jubjub commitments for each polynomial coefficient.
   * @param coefficients Polynomial coefficients in ascending order.
   * @returns The per-coefficient public commitments.
   */
  vssCommit (coefficients: bigint[]) {
    const vssCommitment = []
    for (const coeff of coefficients) {
      const A_i = this.ScalarBaseMult(coeff)
      vssCommitment.push(A_i)
    }
    return vssCommitment
  }

  /**
   * Verifies a single Feldman VSS share against a dealer's commitments.
   * @param share_i Participant share input.
   * @param share_i.i Participant identifier.
   * @param share_i.sk_i Share scalar for that participant.
   * @param vssCommitment Dealer commitment vector.
   * @param _MIN_PARTICIPANTS Threshold parameter kept for compatibility.
   * @returns `true` when the share matches the commitment vector.
   */
  vssVerify (share_i: { i: bigint, sk_i: bigint }, vssCommitment: Point<bigint>[], _MIN_PARTICIPANTS: number) {
    const { i, sk_i } = share_i
    const S_i = this.ScalarBaseMult(sk_i)
    let S_iP = this.Identity()
    let pow = 1n
    for (let j = 0; j < vssCommitment.length; j++) {
      const commit = mulPointEscalar(vssCommitment[j]!, pow)
      S_iP = addPoint(S_iP, commit)
      pow *= i
    }
    return this.pointsEqual(S_i, S_iP)
  }

  /**
   * Splits a secret into per-participant shares using the supplied coefficients.
   * @param s Secret used as the constant term, which is the polynomial's base value.
   * @param coefficients Additional polynomial coefficients.
   * @param MAX_PARTICIPANTS Total number of shares to derive.
   * @returns The derived shares and the full coefficient list including `s`.
   */
  secretShareShard (s: bigint, coefficients: bigint[], MAX_PARTICIPANTS: number): { secretKeyShares: { x_i: number, y_i: bigint }[]; coefficients: bigint[] } {
    const coeffs = [s, ...coefficients]
    const secretKeyShares: { x_i: number, y_i: bigint }[] = []
    for (let x_i = 1; x_i <= MAX_PARTICIPANTS + 1; x_i++) {
      const y_i = this.polynomialEvaluate(BigInt(x_i), coeffs)
      secretKeyShares.push({ x_i, y_i })
    }

    return { secretKeyShares, coefficients: coeffs }
  }

  /**
   * Derives the group public key, participant public keys, and viewing key.
   * @param MAX_PARTICIPANTS Total number of participants.
   * @param MIN_PARTICIPANTS Threshold used to evaluate participant public keys.
   * @param vssCommitment Dealer commitment vector.
   * @returns Derived group metadata for the trusted-dealer flow.
   */
  deriveGroupInfo (MAX_PARTICIPANTS: number, MIN_PARTICIPANTS: number, vssCommitment: Point<bigint>[]) {
    const PK = vssCommitment[0]
    const participantPublicKeys = []
    for (let i = 1; i <= MAX_PARTICIPANTS + 1; i++) {
      let PK_i = this.Identity()
      let pow = 1n
      for (let j = 0; j < MIN_PARTICIPANTS; j++) {
        const commit = mulPointEscalar(vssCommitment[j]!, pow)
        PK_i = addPoint(PK_i, commit)
        pow *= BigInt(i)
      }
      participantPublicKeys.push(PK_i)
    }
    const viewingPrivateKey = new Uint8Array(this.deriveViewKeyFromPK([vssCommitment]))
    return { PK, participantPublicKeys, viewingPrivateKey }
  }

  /**
   * Validates that recipient identifiers are strictly increasing positive integers.
   * @param ids Recipient identifier list to validate.
   */
  static assertSortedConsecutiveIds (ids: number[]) {
    if (!ids.length) throw new Error('empty recipient id list')
    if (ids.some((id) => !Number.isInteger(id) || id <= 0)) {
      throw new Error('recipient ids must be strictly increasing positive integers (self may be excluded)')
    }
    for (let i = 1; i < ids.length; i++) {
      if (ids[i]! <= ids[i - 1]!) {
        throw new Error('recipient ids must be strictly increasing positive integers (self may be excluded)')
      }
    }
  }

  private verifyCommitmentsShape (allDealerCommitments: Point<bigint>[][]): number {
    const lens = allDealerCommitments.map((c) => (c?.length ?? 0))
    if (lens.length === 0) throw new Error('no dealer commitments')
    if (lens.some((l) => l <= 0)) throw new Error('dealer missing commitments')
    const t = lens[0]!
    for (const l of lens) {
      if (l !== t) throw new Error('commitment degree mismatch across dealers')
    }
    return t
  }

  computeSharesForIds (coefficients: bigint[], recipientIds: number[]): Record<number, bigint> {
    TrustedDKG.assertSortedConsecutiveIds(recipientIds)
    const out: Record<number, bigint> = {}
    for (const id of recipientIds) {
      if (!Number.isInteger(id) || id <= 0) throw new Error(`bad recipient id: ${id}`)
      out[id] = this.polynomialEvaluate(BigInt(id), coefficients)
    }
    return out
  }

  /**
   * Combines every dealer's constant commitment into the group public key.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns The aggregate group public key.
   */
  combineGroupPubkeyFromCommitments (allDealerCommitments: Point<bigint>[][]): Point<bigint> {
    if (!allDealerCommitments.length) throw new Error('no dealer commitments')
    this.verifyCommitmentsShape(allDealerCommitments)
    let acc: Point<bigint> = this.Identity()
    for (const dealerCom of allDealerCommitments) {
      if (!dealerCom?.length) throw new Error('dealer missing commitments')
      const P0 = dealerCom[0]!
      if (!this.pointsEqual(this.ScalarMult(P0, this.order), this.Identity())) {
        throw new Error('C0 not in subgroup')
      }
      acc = addPoint(acc, P0)
    }
    return acc
  }

  /**
   * Verifies that every dealer commitment lives in the expected subgroup.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns `true` when all commitments live in the expected subgroup.
   */
  verifyAllCommitmentsSubgroup (allDealerCommitments: Point<bigint>[][]): boolean {
    if (!allDealerCommitments.length) return false
    for (const dealerCom of allDealerCommitments) {
      if (!dealerCom?.length) return false
      for (const Cj of dealerCom) {
        if (!this.pointsEqual(this.ScalarMult(Cj, this.order), this.Identity())) return false
      }
    }
    return true
  }

  /**
   * Verifies a finalized participant share against a dealer's commitments.
   * @param id Participant identifier.
   * @param sk_i Share scalar for that participant.
   * @param commitments Dealer commitment vector.
   * @returns `true` when the share matches the commitments.
   */
  verifyFeldmanShare (
    id: number,
    sk_i: bigint,
    commitments: Array<Point<bigint>>
  ): boolean {
    try {
      if (!Number.isInteger(id) || id <= 0) return false
      if (!commitments?.length) return false

      const LHS = this.ScalarBaseMult(this.modOrder(sk_i))

      let RHS: Point<bigint> = this.Identity()
      let pow = 1n
      const idL = this.modOrder(BigInt(id))
      for (const Cj of commitments) {
        if (!this.pointsEqual(this.ScalarMult(Cj, this.order), this.Identity())) return false
        RHS = addPoint(RHS, this.ScalarMult(Cj, pow))
        pow = this.modOrder(pow * idL)
      }
      return this.pointsEqual(LHS, RHS)
    } catch {
      return false
    }
  }

  /**
   * Computes the Lagrange coefficient for a participant identifier at zero.
   * @param ids Participant identifiers in the reconstruction subset.
   * @param x_i Identifier to evaluate.
   * @returns The interpolation coefficient reduced modulo the subgroup order.
   */
  deriveInterpolatingValue (ids: bigint[], x_i: bigint): bigint {
    const found = ids.find(a => { return a === x_i })
    if (!found) throw new Error('invalid parameters')
    let num = 1n
    let dom = 1n
    for (const x_j of ids) {
      if (x_j === x_i) continue
      num = this.modOrder(num * this.modOrder(x_j))
      dom = this.modOrder(dom * this.modOrder(x_j - x_i))
    }
    const invDom = this.invModOrder(dom)
    return this.modOrder(num * invDom)
  }

  /**
   * Reconstructs the polynomial constant from a threshold subset of shares.
   * @param subset Threshold subset of participant shares.
   * @returns The reconstructed constant term.
   */
  reconstructConstantFromShares (subset: { id: number; s_i: bigint }[]): bigint {
    if (!subset.length) throw new Error('no shares')
    const ids = subset.map((s) => this.modOrder(BigInt(s.id)))
    let a0 = 0n
    for (const { id, s_i } of subset) {
      const lambda = this.deriveInterpolatingValue(ids, this.modOrder(BigInt(id)))
      a0 = this.modOrder(a0 + this.modOrder(s_i) * lambda)
    }
    return a0
  }

  private sortKey = (P: Point<bigint>) =>
    `${P[0].toString(16).padStart(64, '0')}:${P[1].toString(16).padStart(64, '0')}`

  /**
   * Derives a deterministic viewing key from the set of dealer commitments.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns The derived 32-byte viewing private key.
   */
  deriveViewKeyFromPK (allDealerCommitments: Point<bigint>[][]): Uint8Array {
    const C0s: Point<bigint>[] = []
    for (const dealerComms of allDealerCommitments) {
      if (!dealerComms?.length) continue
      C0s.push(dealerComms[0]!)
    }
    C0s.sort((a, b) => (this.sortKey(a) < this.sortKey(b) ? -1 : this.sortKey(a) > this.sortKey(b) ? 1 : 0))
    let acc = 0n
    for (const C0 of C0s) {
      // hash the affine coordinates + domain; interpret as scalar then accumulate in modL
      const v = this.hasher.H7(this.SerializeElement(C0))
      const v_k = this.modOrder(v)
      acc = this.modOrder(acc + v_k)
    }
    return this.toBytes(acc === 0n ? 1n : acc) // avoid zero key
  }

  /**
   * Finalizes a participant's aggregate signing share from all dealer shares.
   * @param participantId Participant identifier.
   * @param s_ki_byDealer Share contribution from every dealer.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns The finalized participant share, group public key, and viewing key.
   */
  finalizeParticipant (
    participantId: number,
    s_ki_byDealer: Array<{ dealerId: number; s_ki: bigint }>,
    allDealerCommitments: Point<bigint>[][]
  ): { share: { id: number; skShare: bigint; skShareDiv8: bigint }; PKGroup: Point<bigint>, viewingPrivateKey: Uint8Array } {
    if (!Number.isInteger(participantId) || participantId <= 0) {
      throw new Error('bad participantId')
    }
    if (!s_ki_byDealer.length || s_ki_byDealer.length !== allDealerCommitments.length) {
      throw new Error('dealer/share count mismatch')
    }
    const dealerIds = s_ki_byDealer.map((d) => d.dealerId).slice().sort((a, b) => a - b)
    TrustedDKG.assertSortedConsecutiveIds(dealerIds)
    let s_i = 0n
    for (const { s_ki } of s_ki_byDealer) s_i = this.modOrder(s_i + this.modOrder(s_ki))
    const skShareDiv8 = s_i
    const skShare = this.modOrder(8n * skShareDiv8)
    const share = { id: participantId, skShare, skShareDiv8 }
    const viewingPrivateKey = this.deriveViewKeyFromPK(allDealerCommitments)
    const PKGroup = this.combineGroupPubkeyFromCommitments(allDealerCommitments)
    return { share, PKGroup, viewingPrivateKey }
  }

  /**
   * Computes the canonical digest of the full dealer-commitment set.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns Digest used as AAD when encrypting and decrypting shares.
   */
  commitmentsDigest (allDealerCommitments: Point<bigint>[][]): bigint {
    const enc = this.encodeCommitmentsBytes(allDealerCommitments)
    return this.hasher.H5(enc)
  }

  private encodeCommitmentsBytes (allDealerCommitments: Point<bigint>[][]): Uint8Array {
    const dealers = allDealerCommitments.slice().filter(a => a?.length)
    dealers.sort((a, b) => (this.sortKey(a[0]!) < this.sortKey(b[0]!) ? -1 : 1))
    let out: Uint8Array = new Uint8Array()
    for (const dealer of dealers) {
      for (const Cj of dealer) {
        const enc = this.SerializeElement(Cj)
        out = concatBytes(out, enc)
      }
    }
    return out
  }

  /**
   * Encrypts each dealer share for its intended recipient with AES-GCM + AAD.
   * @param shares Map of recipient id to share scalar.
   * @param keyById Map of recipient id to derived shared secret.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns A map of recipient id to encrypted share payload.
   */
  encryptSharesAESGCMWithAAD (
    shares: Record<number, bigint>,
    keyById: Record<number, Uint8Array>,
    allDealerCommitments: Point<bigint>[][]
  ): Record<number, EncryptedShare> {
    const ids = Object.keys(shares).map(Number).sort((a, b) => a - b)
    TrustedDKG.assertSortedConsecutiveIds(ids)
    const out: Record<number, EncryptedShare> = {}
    const digest = this.commitmentsDigest(allDealerCommitments)
    const digestBytes = this.toBytes(digest)
    for (const [idStr, s] of Object.entries(shares)) {
      const id = Number(idStr)
      const key = keyById[id]
      if (!key || key.length !== 32) throw new Error(`bad AES key for id ${id}`)
      const nonce = randomBytes(12)
      const pt = this.toBytes(this.modOrder(s))
      const aad = concatBytes(this.SerializeScalar(BigInt(id)), digestBytes)
      const aead = gcm(key, nonce, aad)
      const ciphertext = aead.encrypt(pt)
      out[id] = { nonce, ciphertext }
    }
    return out
  }

  /**
   * Decrypts a single encrypted share for the specified participant.
   * @param enc Encrypted share payload.
   * @param keyBytes AES-GCM key bytes.
   * @param participantId Recipient participant identifier.
   * @param allDealerCommitments Commitment vectors from every dealer.
   * @returns The decrypted share scalar.
   */
  decryptShareAESGCMWithAAD (
    enc: EncryptedShare,
    keyBytes: Uint8Array,
    participantId: number,
    allDealerCommitments: Point<bigint>[][]
  ): bigint {
    if (keyBytes.length !== 32) throw new Error('bad AES key length')
    if (!Number.isInteger(participantId) || participantId <= 0) throw new Error('bad participant id')
    let nonce = new Uint8Array(Object.values(enc.nonce))
    const ct = new Uint8Array(Object.values(enc.ciphertext))
    if (nonce.length !== 12) {
      const out = new Uint8Array(12)
      if (nonce.length > 12) {
        // trim from the end
        out.set(nonce.subarray(0, 12))
      } else {
        // pad with zeros at the end
        out.set(nonce, 0)
      }
      nonce = out
    }
    if (nonce.length !== 12) throw new Error('bad nonce length (expected 12)')
    if (ct.length < 16) throw new Error('bad ciphertext (must include 16B tag)')
    const digest = this.commitmentsDigest(allDealerCommitments)
    const aad = concatBytes(this.SerializeScalar(BigInt(participantId)), this.toBytes(digest))
    const aead = gcm(keyBytes, nonce, aad)
    const pt = aead.decrypt(ct)
    return this.fromBytes(pt)
  }
}

export { TrustedDKG }
