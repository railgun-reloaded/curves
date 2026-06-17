import type { Point } from '@zk-kit/baby-jubjub'

import { bigIntToBuffer } from '../bytes.js'
import { eddsaBuild } from '../eddsa/index.js'
import { BabyFROST } from '../frost/index.js'
import type { Bindings, Commitment } from '../frost/types.js'

type SignerShare = { id: number; skShare: bigint }
type SessionBinding = { bindings: Bindings, share: SignerShare }
type PartialSignature = { identifier: number, partial: bigint }
type SigningSession = {
  msgHash: bigint,
  signers: SignerShare[],
  groupPublicKey: Point<bigint>,
  remoteSigners: Commitment[],
  partials: bigint[]
}

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
  /** External session snapshots recorded for consumers. */
  sessions: SigningSession[] = []
  /** Threshold required to aggregate a final signature. */
  threshold: number

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
      if (s.id === Number(identifier.toString(10))) return true
    }
    return false
  }

  /**
   * Records an external session snapshot for consumers that want to track rounds.
   * @param msgHash Message hash for the session.
   * @param signers Signers included in the session.
   * @param publicKey Group public key.
   * @returns The recorded session object.
   */
  createSession (msgHash: bigint, signers: SignerShare[], publicKey: Point<bigint>) {
    const session = {
      msgHash,
      signers,
      groupPublicKey: publicKey,
      remoteSigners: [],
      partials: []
    }
    this.sessions.push(session)
    return session
  }

  /**
   * Adds a signer share owned by this manager instance.
   * @param signer Local signer share.
   */
  addSigner (signer: SignerShare) {
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
   * Produces local signature shares for the provided message hash.
   * @param msgHash Message hash to sign.
   * @returns Signature shares for all local signers.
   */
  sign (msgHash: bigint) {
    const partials = []
    const commitmentList = this.getCommitmentList()
    if (commitmentList.length === 0) throw new Error('No commitments available; run round1 and collect remotes first')
    for (const signer of this.localBindings) {
      const partial = this.frost.sign(
        signer.bindings.commitments.identifier,
        signer.share.skShare,
        this.groupPublicKey,
        signer.bindings.nonces,
        msgHash,
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
   * @param msgHash Message hash being signed.
   * @returns The aggregate FROST signature.
   */
  finalize (msgHash: bigint) {
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
        msgHash
      )
      if (!ok) throw new Error(`Local signature share failed verification for local signer ${id}`)
    }

    const sigShares: bigint[] = expectedIds.map(id => this.partialsById.get(id)!)
    const sig = this.frost.aggregate(commitmentList, msgHash, this.groupPublicKey, sigShares)
    // Only local signature shares can be checked above (verifySignatureShare needs
    // each signer's secret share, which we hold only for local signers). A forged
    // or malformed *remote* partial would otherwise produce an invalid aggregate
    // returned without complaint, so verify the aggregate before handing it back.
    // Per-signer fault attribution would require exchanging public verification
    // shares, which this manager does not model.
    const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(msgHash), sig, this.groupPublicKey)
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
   * Returns true when enough partials are present to satisfy the threshold.
   * @returns `true` when the round has enough partials to finalize.
   */
  readyToFinalize () {
    const commitmentList = this.getCommitmentList()
    const expectedIds = commitmentList.map(c => Number(c.identifier))
    const available = expectedIds.filter(id => this.partialsById.has(id)).length
    const required = this.threshold
    return available >= required
  }

  /**
   * Clears mutable round state so the manager can start a fresh signing round.
   */
  resetRoundState () {
    this.localBindings = []
    this.remoteSigners = []
    this.partialsById.clear()
  }
}

export type { SignerShare, SessionBinding, PartialSignature, SigningSession }
export { FROSTSigningManager }
