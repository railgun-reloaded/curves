/* eslint-disable camelcase, jsdoc/require-jsdoc */

import { concatBytes } from '@noble/hashes/utils.js'
import type { Point } from '@zk-kit/baby-jubjub'
import { addPoint } from '@zk-kit/baby-jubjub'

import { RailJubCurvePoint } from '../curve.js'
import { RFC9591Hasher } from '../hashing.js'

import type { BindingFactor, Bindings, Commitment, NoncePair } from './types.js'

/**
 * Baby Jubjub FROST primitive implementation used by the signing manager.
 *
 * This class exposes low-level round operations and assumes the caller keeps
 * track of participant sets, commitments, and protocol ordering correctly.
 */
class BabyFROST extends RailJubCurvePoint {
  public readonly contextString = 'FROST-EDBABYJUJUB-BLAKE512-v1'
  hasher: RFC9591Hasher

  /** Creates a FROST helper bound to the default context string. */
  constructor () {
    super()
    this.hasher = new RFC9591Hasher(this.contextString, this.order)
  }

  /**
   * Computes the binding-factor hash domain.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H1 (m: Uint8Array): bigint {
    return this.hasher.H1(m)
  }

  /**
   * Computes the signing challenge compatible with EDDSA-Poseidon verification.
   * @param R8 Group commitment point.
   * @param A Group public key.
   * @param msgHash Message hash scalar.
   * @returns The derived scalar challenge.
   */
  H2 (R8: Point<bigint>, A: Point<bigint>, msgHash: bigint): bigint {
    return this.hasher.H2(R8, A, msgHash)
  }

  /**
   * Computes the deterministic nonce-derivation hash domain.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H3 (m: Uint8Array): bigint {
    return this.hasher.H3(m)
  }

  /**
   * Computes the message hash domain.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H4 (m: Uint8Array): bigint {
    return this.hasher.H4(m)
  }

  /**
   * Computes the commitment-list digest domain.
   * @param m Input bytes.
   * @returns The derived scalar.
   */
  H5 (m: Uint8Array): bigint {
    return this.hasher.H5(m)
  }

  /**
   * Derives a nonce scalar from signer secret material.
   * @param secret Signer secret scalar.
   * @returns The derived nonce scalar.
   */
  generateNonce (secret: bigint) {
    const random = this.SerializeScalar(this.RandomScalar())
    const serialized = this.SerializeScalar(secret)
    const h = concatBytes(random, serialized)
    return this.H3(h)
  }

  /**
   * Computes the Lagrange coefficient for `x_i` at zero.
   * @param L Participant identifier list.
   * @param x_i Identifier to evaluate.
   * @returns The interpolation coefficient.
   */
  deriveInterpolatingValue (L: bigint[], x_i: bigint) {
    const found = L.find(a => { return a === x_i })
    if (!found) throw new Error('invalid parameters')
    let num = 1n
    let dom = 1n
    for (const x_j of L) {
      if (x_j === x_i) continue
      num *= x_j
      dom *= x_j - x_i
    }
    const value = num / dom
    return value
  }

  /**
   * Encodes a commitment list into the byte form used by binding-factor hashing.
   * @param commitmentList Commitment list for the active round.
   * @returns Encoded commitment bytes.
   */
  encodeGroupCommitmentList (commitmentList: Commitment[]) {
    let encodedGroupCommitment: Uint8Array = new Uint8Array()
    for (const { identifier, hidingNonceCommitment, bindingNonceCommitment } of commitmentList) {
      const encodedCommitment = concatBytes(
        this.SerializeScalar(identifier),
        this.SerializeElement(hidingNonceCommitment),
        this.SerializeElement(bindingNonceCommitment)
      )
      encodedGroupCommitment = concatBytes(encodedGroupCommitment, encodedCommitment)
    }
    return encodedGroupCommitment
  }

  /**
   * Extracts participant identifiers from a commitment list.
   * @param commitmentList Commitment list for the active round.
   * @returns The participant identifiers.
   */
  participantsFromCommitmentList (commitmentList: Commitment[]) {
    const ids = []
    for (const { identifier } of commitmentList) {
      ids.push(identifier)
    }
    return ids
  }

  /**
   * Looks up a participant's binding factor inside a computed factor list.
   * @param bindingFactorList Computed binding factors.
   * @param identifier Participant identifier.
   * @returns The participant binding factor.
   */
  bindingFactorForParticipant (bindingFactorList: BindingFactor[], identifier: bigint) {
    for (const { identifier: id, bindingFactor } of bindingFactorList) {
      if (id === identifier) return bindingFactor
    }
    throw new Error('invalid participant')
  }

  /**
   * Computes the binding factor for every participant in the signing set.
   * @param groupPublicKey Group public key.
   * @param commitmentList Commitment list for the active round.
   * @param message Message bytes.
   * @returns The binding factors for every participant.
   */
  computeBindingFactors (groupPublicKey: Point<bigint>, commitmentList: Commitment[], message: Uint8Array) {
    const groupPublicKeyEnc = this.SerializeElement(groupPublicKey)
    const msgHash = this.H4(message)
    const encodedCommitmentHash = this.H5(this.encodeGroupCommitmentList(commitmentList))
    const rhoInputPrefix = concatBytes(groupPublicKeyEnc, this.toBytes(msgHash), this.toBytes(encodedCommitmentHash))
    const bindingFactorList = []
    for (const { identifier } of commitmentList) {
      const rhoInput = concatBytes(rhoInputPrefix, this.SerializeScalar(identifier))
      const bindingFactor = this.H1(rhoInput)!
      bindingFactorList.push({ identifier, bindingFactor })
    }
    return bindingFactorList
  }

  /**
   * Computes the aggregate group commitment for the active signing set.
   * @param commitmentList Commitment list for the active round.
   * @param bindingFactorList Binding factors for that round.
   * @returns The aggregate group commitment.
   */
  computeGroupCommitment (commitmentList: Commitment[], bindingFactorList: BindingFactor[]) {
    let groupCommitment = this.Identity()
    for (const { identifier, hidingNonceCommitment, bindingNonceCommitment } of commitmentList) {
      const bindingFactor = this.bindingFactorForParticipant(bindingFactorList, identifier)
      const bindingNonce = this.ScalarMult(bindingNonceCommitment, bindingFactor)
      groupCommitment = addPoint(addPoint(groupCommitment, hidingNonceCommitment), bindingNonce)
    }
    return groupCommitment
  }

  /**
   * Computes the per-message signing challenge.
   * @param groupCommitment Aggregate group commitment.
   * @param groupPublicKey Group public key.
   * @param message Message hash scalar.
   * @returns The per-message challenge scalar.
   */
  computeChallenge (groupCommitment: Point<bigint>, groupPublicKey: Point<bigint>, message: bigint) {
    return this.H2(groupCommitment, groupPublicKey, message)
  }

  /**
   * Generates round-1 nonces and public commitments for a signer.
   * @param sk_i Signer share scalar.
   * @param identifier Participant identifier.
   * @returns The private nonces and public commitments.
   */
  commit (sk_i: bigint, identifier: bigint): Bindings {
    const hidingNonce = this.generateNonce(this.modOrder(sk_i))
    const bindingNonce = this.generateNonce(this.modOrder(sk_i))
    const hidingNonceCommitment = this.ScalarBaseMult(hidingNonce)
    const bindingNonceCommitment = this.ScalarBaseMult(bindingNonce)
    const nonces = { hidingNonce, bindingNonce }
    const commitments = { identifier, hidingNonceCommitment, bindingNonceCommitment }
    return { nonces, commitments }
  }

  /**
   * Produces a signer-specific round-2 signature share.
   * @param identifier Participant identifier.
   * @param sk_i Signer share scalar.
   * @param groupPublicKey Group public key.
   * @param nonce_i Signer nonce pair from round 1.
   * @param message Message hash scalar.
   * @param commitmentList Commitment list for the active round.
   * @returns The participant's signature share.
   */
  sign (
    identifier: bigint,
    sk_i: bigint,
    groupPublicKey: Point<bigint>,
    nonce_i: NoncePair,
    message: bigint,
    commitmentList: Commitment[]
  ) {
    // Compute the binding factor(s)
    const bindingFactorList = this.computeBindingFactors(groupPublicKey, commitmentList, this.toBytes(message))
    const bindingFactor = this.bindingFactorForParticipant(bindingFactorList, identifier)
    // Compute the group commitment
    const groupCommitment = this.computeGroupCommitment(commitmentList, bindingFactorList)
    // Compute the interpolating value
    const participantList = this.participantsFromCommitmentList(commitmentList)
    const lambda_i = this.deriveInterpolatingValue(participantList, identifier)

    // Compute the per message challenge
    const challenge = this.computeChallenge(groupCommitment, groupPublicKey, message)

    // Compute the signature share
    const { hidingNonce, bindingNonce } = nonce_i
    const sigShare = hidingNonce + (bindingNonce * bindingFactor) + (lambda_i * sk_i * challenge)
    return this.modOrder(sigShare)
  }

  /**
   * Aggregates verified signature shares into a final FROST signature.
   * @param commitmentList Commitment list for the active round.
   * @param message Message hash scalar.
   * @param groupPublicKey Group public key.
   * @param sigShares Signature shares ordered by participant identifier.
   * @returns The aggregate FROST signature.
   */
  aggregate (commitmentList: Commitment[], message: bigint, groupPublicKey: Point<bigint>, sigShares: bigint[]) {
    const bindingFactorList = this.computeBindingFactors(groupPublicKey, commitmentList, this.toBytes(message))
    const groupCommitment = this.computeGroupCommitment(commitmentList, bindingFactorList)

    let z = 0n
    for (const z_i of sigShares) {
      z = this.modOrder(z + z_i)
    }
    return { R8: groupCommitment, S: this.modOrder(z) }
  }

  /**
   * Verifies an individual signer's signature share against its commitments.
   * @param identifier Participant identifier.
   * @param sk_i Signer share scalar.
   * @param commitment_i Commitment published by that signer.
   * @param sigShare_i Signature share to verify.
   * @param commitmentList Commitment list for the active round.
   * @param groupPublicKey Group public key.
   * @param message Message hash scalar.
   * @returns `true` when the signature share is valid.
   */
  verifySignatureShare (
    identifier: bigint,
    sk_i: bigint,
    commitment_i: Commitment,
    sigShare_i: bigint,
    commitmentList: Commitment[],
    groupPublicKey: Point<bigint>,
    message: bigint
  ) {
    const bindingFactorList = this.computeBindingFactors(groupPublicKey, commitmentList, this.toBytes(message))
    const bindingFactor = this.bindingFactorForParticipant(bindingFactorList, identifier)
    const groupCommitment = this.computeGroupCommitment(commitmentList, bindingFactorList)

    const { hidingNonceCommitment, bindingNonceCommitment } = commitment_i
    const bindingMult = this.ScalarMult(bindingNonceCommitment, bindingFactor)
    const commitmentShare = addPoint(hidingNonceCommitment, bindingMult)

    const challenge = this.computeChallenge(groupCommitment, groupPublicKey, message)

    const participantList = this.participantsFromCommitmentList(commitmentList)
    const lambda_i = this.deriveInterpolatingValue(participantList, identifier)

    const leftSide = this.ScalarBaseMult(sigShare_i)
    const rightSideScalar = this.modOrder(lambda_i * sk_i * challenge)
    const rightSidePoint = this.ScalarBaseMult(rightSideScalar)
    const rightSide = addPoint(commitmentShare, rightSidePoint)
    return this.pointsEqual(leftSide, rightSide)
  }
}

const frost = new BabyFROST()
export { frost, BabyFROST }

// export type { LocalNonces, CommitmentPublic, PartialSignature, AggregateSignature }
export default BabyFROST
