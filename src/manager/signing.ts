import type { Point } from '@zk-kit/baby-jubjub'

import { bigIntToBuffer } from '../bytes.js'
import { eddsaBuild } from '../eddsa/index.js'
import { BabyFROST } from '../frost/index.js'
import type { Bindings, Commitment } from '../frost/types.js'

type SignerShare = { id: number; skShare: bigint }
type SessionBinding = { bindings: Bindings, share: SignerShare }
type PartialSignature = { identifier: number, partial: bigint }

const DEFAULT_SESSION = 'default'

/**
 * One isolated two-round FROST signing session (one message) owned by a
 * {@link FROSTSigningManager}.
 *
 * All per-round state (local nonces, collected peer commitments, partials)
 * lives here, so independent sessions never interfere. A session is single-use:
 * to sign again, start a new session or reset() this one. Durable identity
 * (local signer shares, group public key, threshold) lives on the manager.
 */
class SigningSession {
  /** Unique identifier of this session within its manager. */
  readonly id: string
  /** Owning manager providing frost, signer shares, group key, and threshold. */
  private readonly manager: FROSTSigningManager
  /** Per-round nonce and commitment bindings for the local signers. */
  localBindings: SessionBinding[] = []
  /** Round-1 commitments collected from remote participants. */
  remoteSigners: Commitment[] = []
  /** Collected partial signatures keyed by participant identifier. */
  partialsById: Map<number, bigint> = new Map()
  /** Whether round1() has already run; a session may only commit once. */
  private committed = false
  /** Message passed to sign(), re-checked by finalize(). */
  private message: bigint | undefined

  /**
   * Creates a session owned by a manager.
   * @param manager Owning signing manager (provides frost, group key, signers).
   * @param id Unique session identifier.
   */
  constructor (manager: FROSTSigningManager, id: string) {
    this.manager = manager
    this.id = id
  }

  /**
   * Generates fresh local nonces and commitments for this session's round 1.
   *
   * A session may only commit once: re-running it would regenerate local nonces
   * while peers still hold the previous commitments, so any partial produced
   * would be invalid. Use reset() (or a new session) to sign again.
   */
  round1 () {
    if (this.committed) {
      throw new Error(`session ${this.id} already committed; reset() it or start a new session to sign again`)
    }
    this.localBindings = []
    this.partialsById.clear()
    for (const signer of this.manager.signers) {
      const bindings = this.manager.frost.commit(signer.skShare, BigInt(signer.id))
      this.localBindings.push({ bindings, share: signer })
    }
    this.committed = true
  }

  /**
   * Exports this session's local round-1 commitments to send to peers.
   * @returns The local public commitments.
   */
  exportRound1 () {
    const commitments: Commitment[] = []
    for (const sb of this.localBindings) commitments.push({ ...sb.bindings.commitments })
    return commitments
  }

  /**
   * Adds a peer's round-1 commitment to this session, ignoring duplicate ids.
   * @param commitment Remote participant commitment.
   */
  addRemoteSigner (commitment: Commitment) {
    const exists = this.remoteSigners.find(c => c.identifier === commitment.identifier)
    if (!exists) this.remoteSigners.push(commitment)
  }

  /**
   * Builds the deterministic combined commitment list for this session.
   * @returns The sorted commitment list.
   */
  getCommitmentList () {
    const byId = new Map<string, Commitment>()
    for (const c of this.exportRound1()) byId.set(String(c.identifier), c)
    for (const c of this.remoteSigners) if (!byId.has(String(c.identifier))) byId.set(String(c.identifier), c)
    const list = Array.from(byId.values())
    list.sort((a, b) => (a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0))
    const required = this.manager.threshold
    if (list.length < required) {
      throw new Error(`Insufficient commitments: have ${list.length}, need >= ${required}`)
    }
    return list
  }

  /**
   * Produces local signature shares for the provided message.
   * @param message Message scalar to sign.
   * @returns Signature shares for all local signers.
   */
  sign (message: bigint) {
    if (this.localBindings.length === 0) throw new Error('No local commitments; run round1 first')
    const commitmentList = this.getCommitmentList()
    if (commitmentList.length === 0) throw new Error('No commitments available; run round1 and collect remotes first')
    this.message = message
    const partials = []
    for (const signer of this.localBindings) {
      const partial = this.manager.frost.sign(
        signer.bindings.commitments.identifier,
        signer.share.skShare,
        this.manager.groupPublicKey,
        signer.bindings.nonces,
        message,
        commitmentList
      )
      partials.push({ identifier: signer.share.id, partial })
    }
    return partials
  }

  /**
   * Records partial signatures received from peers, ignoring duplicates by id.
   * @param partials Partial signatures received from peers.
   */
  receivePartials (partials: PartialSignature[]) {
    for (const p of partials) {
      const id = Number(p.identifier)
      if (!this.partialsById.has(id)) this.partialsById.set(id, p.partial)
    }
  }

  /**
   * Returns the participant identifiers implied by the current commitment list.
   * @returns The participant identifiers for this session.
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
   * Finalizes an aggregate signature once all expected partials are available.
   * @param message Message scalar being signed (must match the signed message).
   * @returns The aggregate FROST signature.
   */
  finalize (message: bigint) {
    if (this.message !== undefined && this.message !== message) {
      throw new Error(`finalize message does not match the message signed in session ${this.id}`)
    }
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
      const ok = this.manager.frost.verifySignatureShare(
        BigInt(id),
        share.skShare,
        commitmentLocal,
        sigShare,
        commitmentList,
        this.manager.groupPublicKey,
        message
      )
      if (!ok) throw new Error(`Local signature share failed verification for local signer ${id}`)
    }

    const sigShares: bigint[] = expectedIds.map(id => this.partialsById.get(id)!)
    const sig = this.manager.frost.aggregate(commitmentList, message, this.manager.groupPublicKey, sigShares)
    // Only local signature shares can be checked above (verifySignatureShare needs
    // each signer's secret share, which we hold only for local signers). A forged
    // or malformed *remote* partial would otherwise produce an invalid aggregate
    // returned without complaint, so verify the aggregate before handing it back.
    // Per-signer fault attribution would require exchanging public verification
    // shares, which this manager does not model.
    const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(message), sig, this.manager.groupPublicKey)
    if (!ok) throw new Error('Aggregate signature failed verification; a partial signature is invalid')
    return sig
  }

  /**
   * Clears this session's round state so it can run round1() again.
   */
  reset () {
    this.localBindings = []
    this.remoteSigners = []
    this.partialsById.clear()
    this.committed = false
    this.message = undefined
  }
}

/**
 * Orchestration helper for the two-round Baby FROST signing flow.
 *
 * Holds the durable signing identity (local signer shares, group public key,
 * threshold) and manages one or more {@link SigningSession}s. Each session is an
 * isolated round, so a single manager can drive concurrent signings of distinct
 * messages. The flat round methods (round1/sign/finalize/...) operate on a
 * lazily-created `'default'` session for single-session callers.
 */
class FROSTSigningManager {
  /** FROST primitive used for commit, sign, and aggregate operations. */
  frost: BabyFROST

  /** Local signer shares owned by this manager instance. */
  signers: SignerShare[] = []
  /** Finalized group public key for the active signing set. */
  groupPublicKey: Point<bigint>
  /** Threshold required to aggregate a final signature. */
  threshold: number
  /** Live signing sessions keyed by session id. */
  private sessions: Map<string, SigningSession> = new Map()

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
    return this.signers.some(s => s.id === Number(identifier))
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

  // --- session lifecycle ----------------------------------------------------

  /**
   * Starts a new isolated signing session.
   * @param id Session identifier (defaults to the shared 'default' session).
   * @returns The created session.
   */
  startSession (id: string = DEFAULT_SESSION) {
    if (this.sessions.has(id)) throw new Error(`signing session ${id} already exists`)
    const session = new SigningSession(this, id)
    this.sessions.set(id, session)
    return session
  }

  /**
   * Returns an existing session.
   * @param id Session identifier (defaults to 'default').
   * @returns The session.
   */
  session (id: string = DEFAULT_SESSION) {
    const session = this.sessions.get(id)
    if (!session) throw new Error(`unknown signing session ${id}`)
    return session
  }

  /**
   * Reports whether a session exists.
   * @param id Session identifier (defaults to 'default').
   * @returns `true` when the session exists.
   */
  hasSession (id: string = DEFAULT_SESSION) {
    return this.sessions.has(id)
  }

  /**
   * Discards a session and its round state.
   * @param id Session identifier (defaults to 'default').
   */
  endSession (id: string = DEFAULT_SESSION) {
    this.sessions.delete(id)
  }

  /**
   * Lazily creates and returns the implicit single-session used by the flat API.
   * @returns The default session.
   */
  private defaultSession () {
    return this.sessions.get(DEFAULT_SESSION) ?? this.startSession(DEFAULT_SESSION)
  }

  // --- flat single-session API ----------------------------------------------
  // Thin delegates to a lazily-created 'default' session, preserving the
  // single-session API. See SigningSession for the documented behavior.

  /**
   * Runs round 1 on the default session.
   * @returns The default session's round-1 result.
   */
  round1 () { return this.defaultSession().round1() }
  /**
   * Exports the default session's local round-1 commitments.
   * @returns The local public commitments.
   */
  exportRound1 () { return this.defaultSession().exportRound1() }
  /**
   * Adds a peer commitment to the default session.
   * @param commitment Remote participant commitment.
   * @returns The default session's result for the added commitment.
   */
  addRemoteSigner (commitment: Commitment) { return this.defaultSession().addRemoteSigner(commitment) }
  /**
   * Produces local signature shares on the default session.
   * @param message Message scalar to sign.
   * @returns Signature shares for all local signers.
   */
  sign (message: bigint) { return this.defaultSession().sign(message) }
  /**
   * Records peer partial signatures on the default session.
   * @param partials Partial signatures received from peers.
   * @returns The default session's result for the recorded partials.
   */
  receivePartials (partials: PartialSignature[]) { return this.defaultSession().receivePartials(partials) }
  /**
   * Aggregates the default session into a final signature.
   * @param message Message that was signed.
   * @returns The aggregate signature.
   */
  finalize (message: bigint) { return this.defaultSession().finalize(message) }
  /**
   * Participant identifiers implied by the default session's commitment list.
   * @returns The expected participant identifiers.
   */
  expectedParticipantIds () { return this.defaultSession().expectedParticipantIds() }
  /**
   * Identifiers still missing a partial on the default session.
   * @returns The missing participant identifiers.
   */
  getMissingPartials () { return this.defaultSession().getMissingPartials() }
  /**
   * Whether the default session has every expected partial.
   * @returns `true` when the round can finalize.
   */
  readyToFinalize () { return this.defaultSession().readyToFinalize() }
  /**
   * Resets the default session so a new round can start.
   * @returns The default session's reset result.
   */
  resetRoundState () { return this.defaultSession().reset() }

  /**
   * Partial signatures collected on the default session.
   * @returns The default session's partials map.
   */
  get partialsById () { return this.defaultSession().partialsById }
  /**
   * Peer commitments collected on the default session.
   * @returns The default session's remote commitments.
   */
  get remoteSigners () { return this.defaultSession().remoteSigners }
  /**
   * Local bindings held by the default session.
   * @returns The default session's local bindings.
   */
  get localBindings () { return this.defaultSession().localBindings }
}

export type { SignerShare, SessionBinding, PartialSignature }
export { FROSTSigningManager, SigningSession }
