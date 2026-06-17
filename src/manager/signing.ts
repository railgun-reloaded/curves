import type { Point } from '@zk-kit/baby-jubjub'

import { bigIntToBuffer } from '../bytes.js'
import { eddsaBuild } from '../eddsa/index.js'
import { BabyFROST } from '../frost/index.js'
import type { Bindings, Commitment } from '../frost/types.js'

type SignerShare = { id: number; skShare: bigint }
type SessionBinding = { bindings: Bindings, share: SignerShare }
type PartialSignature = { identifier: number, partial: bigint }

/**
 * Small orchestration helper for the two-round Baby FROST signing flow.
 *
 * The manager assumes a single active round at a time and keeps mutable round
 * state in memory.
 */
class FROSTSigningManager {
  /** FROST primitive used for commit, sign, and aggregate operations. */
  frost: BabyFROST

  /** Local signer shares owned by this manager instance. */
  signers: SignerShare[] = []
  /** Per-round nonce and commitment bindings for the local signers. */
  localBindings: SessionBinding[] = []

  /** Round-1 commitments collected from remote participants. */
  remoteSigners: Commitment[] = []
  /** Finalized group public key for the active signing set. */
  groupPublicKey: Point<bigint>
  /** Collected partial signatures keyed by participant identifier. */
  partialsById: Map<number, bigint> = new Map()
  /** Threshold required to aggregate a final signature. */
  threshold: number

  /**
   * Number of round1() calls since the last resetRoundState(). The interleaved
   * exchange legitimately calls round1() exactly once per round (a node may even
   * receive every peer commitment before its own round1()), so a count > 1 means
   * local nonces were regenerated without re-exchanging — the cross-round footgun
   * that sign()/finalize() reject via assertRoundNotRestarted().
   */
  private round1CallsSinceReset = 0

  /**
   * Creates a signing manager bound to a finalized group public key.
   * @param publicKey Finalized group public key.
   * @param threshold Threshold required for aggregation.
   */
  constructor (publicKey: Point<bigint>, threshold: number) {
    this.frost = new BabyFROST()
    this.threshold = threshold
    this.groupPublicKey = publicKey
  }

  /**
   * Returns true when one of the local signers owns the provided identifier.
   * @param identifier Participant identifier.
   * @returns `true` when the signer is local.
   */
  hasId (identifier: bigint) {
    for (const s of this.signers) {
      if (s.id === Number(identifier)) return true
    }
    return false
  }

  /**
   * Adds a signer share owned by this manager instance.
   * @param signer Local signer share.
   */
  addSigner (signer: SignerShare) {
    if (this.signers.some(s => s.id === signer.id)) {
      throw new Error(`signer ${signer.id} already added`)
    }
    this.signers.push(signer)
  }

  /**
   * Adds a remote participant's round-1 commitment, ignoring duplicates by identifier.
   * @param commitment Remote participant commitment.
   */
  addRemoteSigner (commitment: Commitment) {
    const exists = this.remoteSigners.find(c => c.identifier === commitment.identifier)
    if (!exists) this.remoteSigners.push(commitment)
  }

  /**
   * Generates fresh local nonces and commitments for a new signing round.
   */
  round1 () {
    this.localBindings = []
    // Starting a fresh round must not carry partials collected for a previous
    // round; stale partials would otherwise be aggregated against new nonces.
    // (remoteSigners are intentionally left intact: the documented exchange flow
    // interleaves round1() and addRemoteSigner() across peers; use
    // resetRoundState() to clear remote commitments between distinct rounds.)
    this.partialsById.clear()
    // Count restarts so sign()/finalize() can reject a second round1() that
    // regenerated local nonces without an intervening resetRoundState().
    this.round1CallsSinceReset++

    for (const signer of this.signers) {
      const bindings = this.frost.commit(signer.skShare, BigInt(signer.id))
      const sb = {
        bindings,
        share: signer
      }
      this.localBindings.push(sb)
    }
  }

  /**
   * Exports the local round-1 commitments to send to peers.
   * @returns The local public commitments.
   */
  exportRound1 () {
    const commitments: Commitment[] = []
    for (const sb of this.localBindings) commitments.push({ ...sb.bindings.commitments })
    return commitments
  }

  /**
   * Builds the deterministic combined commitment list for the current round.
   * @returns The sorted commitment list.
   */
  getCommitmentList () {
    const byId = new Map<string, Commitment>()
    for (const c of this.exportRound1()) byId.set(String(c.identifier), c)
    for (const c of this.remoteSigners) if (!byId.has(String(c.identifier))) byId.set(String(c.identifier), c)
    const list = Array.from(byId.values())
    list.sort((a, b) => (a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0))
    const required = this.threshold
    if (list.length < required) {
      throw new Error(`Insufficient commitments: have ${list.length}, need >= ${required}`)
    }
    return list
  }

  /**
   * Throws if round1() was run more than once without a resetRoundState().
   *
   * Guards the cross-round footgun: a second round1() regenerates this node's
   * local nonces while peers still hold its previous commitments, so the group
   * commitment it computes no longer matches theirs and any partial it produces
   * is invalid. The documented restart path is resetRoundState() then round1().
   * @param where Calling context used in the error message.
   */
  private assertRoundNotRestarted (where: string) {
    if (this.round1CallsSinceReset > 1) {
      throw new Error(`${where}: round1() was run again without resetRoundState(); local nonces changed but the round was not re-exchanged. Call resetRoundState() and restart the round`)
    }
  }

  /**
   * Produces local signature shares for the provided message.
   * @param message Message scalar to sign.
   * @returns Signature shares for all local signers.
   */
  sign (message: bigint) {
    if (this.localBindings.length === 0) throw new Error('No local commitments; run round1 first')
    this.assertRoundNotRestarted('sign')
    const partials = []
    const commitmentList = this.getCommitmentList()
    if (commitmentList.length === 0) throw new Error('No commitments available; run round1 and collect remotes first')
    for (const signer of this.localBindings) {
      const partial = this.frost.sign(
        signer.bindings.commitments.identifier,
        signer.share.skShare,
        this.groupPublicKey,
        signer.bindings.nonces,
        message,
        commitmentList
      )
      const complete = { identifier: signer.share.id, partial }
      partials.push(complete)
    }
    return partials
  }

  /**
   * Records partial signatures received from peers, ignoring duplicates by identifier.
   * @param partials Partial signatures received from peers.
   */
  receivePartials (partials: PartialSignature[]) {
    for (const p of partials) {
      const id = Number(p.identifier)
      if (!this.partialsById.has(id)) this.partialsById.set(id, p.partial)
    }
  }

  /**
   * Finalizes an aggregate signature once all expected partials are available.
   * @param message Message scalar being signed.
   * @returns The aggregate FROST signature.
   */
  finalize (message: bigint) {
    this.assertRoundNotRestarted('finalize')
    const commitmentList = this.getCommitmentList()
    if (commitmentList.length === 0) throw new Error('No commitments available; cannot finalize')
    const expectedIds = commitmentList.map(c => Number(c.identifier))
    // require all expected shares for correctness under current flow
    const missing = expectedIds.filter(id => !this.partialsById.has(id))
    if (missing.length > 0) throw new Error(`Missing partials for identifiers: ${missing.join(', ')}`)

    const byId = new Map<number, Commitment>()
    for (const c of commitmentList) byId.set(Number(c.identifier), c)
    for (const { share } of this.localBindings) {
      const id = share.id
      const sigShare = this.partialsById.get(id)
      if (sigShare == null) continue
      const commitmentLocal = byId.get(id)
      if (!commitmentLocal) throw new Error(`Missing commitment for local id ${id}`)
      const ok = this.frost.verifySignatureShare(
        BigInt(id),
        share.skShare,
        commitmentLocal,
        sigShare,
        commitmentList,
        this.groupPublicKey,
        message
      )
      if (!ok) throw new Error(`Local signature share failed verification for local signer ${id}`)
    }

    const sigShares: bigint[] = expectedIds.map(id => this.partialsById.get(id)!)
    const sig = this.frost.aggregate(commitmentList, message, this.groupPublicKey, sigShares)
    // Only local signature shares can be checked above (verifySignatureShare needs
    // each signer's secret share, which we hold only for local signers). A forged
    // or malformed *remote* partial would otherwise produce an invalid aggregate
    // returned without complaint, so verify the aggregate before handing it back.
    // Per-signer fault attribution would require exchanging public verification
    // shares, which this manager does not model.
    const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(message), sig, this.groupPublicKey)
    if (!ok) throw new Error('Aggregate signature failed verification; a partial signature is invalid')
    return sig
  }

  /**
   * Returns the participant identifiers implied by the current commitment list.
   * @returns The participant identifiers for the active round.
   */
  expectedParticipantIds () {
    return this.getCommitmentList().map(c => Number(c.identifier))
  }

  /**
   * Returns the identifiers still missing a partial signature.
   * @returns The missing participant identifiers.
   */
  getMissingPartials () {
    const expected = this.expectedParticipantIds()
    return expected.filter(id => !this.partialsById.has(id))
  }

  /**
   * Returns true when every signer in the active commitment list has a partial.
   *
   * finalize() interpolates over the full commitment list, so a partial is
   * required from every participant in it — not merely `threshold`-many. (The
   * threshold floor is enforced separately by getCommitmentList().)
   * @returns `true` when the round has every expected partial and can finalize.
   */
  readyToFinalize () {
    return this.getMissingPartials().length === 0
  }

  /**
   * Clears mutable round state so the manager can start a fresh signing round.
   */
  resetRoundState () {
    this.localBindings = []
    this.remoteSigners = []
    this.partialsById.clear()
    this.round1CallsSinceReset = 0
  }
}

export type { SignerShare, SessionBinding, PartialSignature }
export { FROSTSigningManager }
