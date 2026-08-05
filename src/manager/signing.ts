import type { Point } from '@zk-kit/baby-jubjub'

import { bigIntToBuffer } from '../bytes.js'
import { eddsaBuild } from '../eddsa/index.js'
import { BabyFROST } from '../frost/index.js'
import type { Bindings, Commitment } from '../frost/types.js'

type SignerShare = { id: number; skShare: bigint }
type SessionBinding = { bindings: Bindings, share: SignerShare }
type PartialSignature = { identifier: number, partial: bigint }

/** Hex-encoded `[x, y]` curve point. */
type HexPoint = [string, string]

/** JSON-safe form of a FROST round-1 commitment. */
interface CommitmentSnapshot {
  identifier: string
  hidingNonceCommitment: HexPoint
  bindingNonceCommitment: HexPoint
}

/** JSON-safe form of a local signer's round-1 bindings (includes secret nonces). */
interface SessionBindingSnapshot {
  nonces: { hidingNonce: string; bindingNonce: string }
  commitments: CommitmentSnapshot
  share: { id: number; skShare: string }
}

/** JSON-safe snapshot of a single {@link SigningSession}. */
interface SigningSessionSnapshot {
  id: string
  committed: boolean
  message?: string | undefined
  localBindings: SessionBindingSnapshot[]
  remoteSigners: CommitmentSnapshot[]
  partials: Array<[number, string]>
}

/**
 * Which class of snapshot a payload is, so the two restore paths cannot be
 * confused for one another.
 *
 * - `safe`: carries no live nonces. Restoring it any number of times is sound.
 * - `mid-round`: carries the local nonces of committed sessions. **Single use.**
 */
type SnapshotKind = 'safe' | 'mid-round'

/**
 * JSON-safe snapshot of a {@link FROSTSigningManager} and its sessions.
 *
 * Both kinds contain secret material: `signers[].skShare` is long-term key
 * material in either case, so a snapshot always belongs in trusted storage.
 * The `kind` field distinguishes a further, sharper hazard — see
 * {@link SnapshotKind} and {@link FROSTSigningManager#toMidRoundJSON}.
 */
interface SigningManagerSnapshot {
  version: number
  kind: SnapshotKind
  threshold: number
  groupPublicKey: HexPoint
  signers: Array<{ id: number; skShare: string }>
  sessions: SigningSessionSnapshot[]
  /** Ids of committed sessions dropped from a `safe` snapshot, for diagnostics. */
  omittedSessions?: string[]
}

const DEFAULT_SESSION = 'default'
const SNAPSHOT_VERSION = 2

/**
 * Hex-encodes a bigint for a snapshot.
 * @param v Value to encode.
 * @returns The 0x-prefixed hex encoding.
 */
const bigToHex = (v: bigint) => '0x' + v.toString(16)
/**
 * Hex-encodes a curve point for a snapshot.
 * @param p Point to encode.
 * @returns The point as an [x, y] hex pair.
 */
const pointToHex = (p: Point<bigint>): HexPoint => [bigToHex(p[0]), bigToHex(p[1])]
/**
 * Decodes a snapshot [x, y] hex pair back into a curve point.
 * @param h Hex pair to decode.
 * @returns The decoded point.
 */
const hexToPoint = (h: HexPoint): Point<bigint> => [BigInt(h[0]), BigInt(h[1])]
/**
 * Converts a round-1 commitment into its JSON-safe snapshot form.
 * @param c Commitment to encode.
 * @returns The hex-encoded commitment snapshot.
 */
const commitmentToSnapshot = (c: Commitment): CommitmentSnapshot => ({
  identifier: bigToHex(c.identifier),
  hidingNonceCommitment: pointToHex(c.hidingNonceCommitment),
  bindingNonceCommitment: pointToHex(c.bindingNonceCommitment),
})
/** Stateless curve helper used to validate points decoded from a snapshot. */
const snapshotValidator = new BabyFROST()
/**
 * Rebuilds a round-1 commitment from its snapshot form, validating its points.
 * @param s Commitment snapshot to decode.
 * @returns The decoded commitment.
 */
const snapshotToCommitment = (s: CommitmentSnapshot): Commitment => {
  const identifier = BigInt(s.identifier)
  if (identifier <= 0n) throw new Error(`invalid commitment identifier ${identifier} in snapshot`)
  const hidingNonceCommitment = hexToPoint(s.hidingNonceCommitment)
  const bindingNonceCommitment = hexToPoint(s.bindingNonceCommitment)
  // A snapshot is untrusted input: it may have been written by a peer, edited
  // on disk, or produced by an older build. Validate exactly as if the
  // commitment had arrived over the wire.
  snapshotValidator.assertValidElement(hidingNonceCommitment, `snapshot commitment ${identifier}: hiding nonce`)
  snapshotValidator.assertValidElement(bindingNonceCommitment, `snapshot commitment ${identifier}: binding nonce`)
  return { identifier, hidingNonceCommitment, bindingNonceCommitment }
}

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
    // Reject a peer announcing identifier 0: it would enter the commitment list
    // and shift every honest signer's Lagrange coefficients.
    if (commitment.identifier <= 0n) {
      throw new Error(`invalid commitment identifier ${commitment.identifier}: participant identifiers must be positive integers`)
    }
    // Nonce commitments arrive as already-decoded points and never pass through
    // DeserializeElement. Reject anything off the curve, the identity, or
    // outside the prime-order subgroup, so a malformed peer is named here
    // rather than surfacing later as an unattributable aggregate failure.
    this.manager.frost.assertValidElement(commitment.hidingNonceCommitment, `commitment ${commitment.identifier}: hiding nonce`)
    this.manager.frost.assertValidElement(commitment.bindingNonceCommitment, `commitment ${commitment.identifier}: binding nonce`)
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

  /**
   * Whether this session has run round1 and therefore holds live local nonces.
   *
   * A committed session cannot appear in a `safe` manager snapshot, because
   * serializing its nonces is what creates the single-use hazard.
   * @returns `true` once round1() has run and before reset().
   */
  hasCommitted (): boolean {
    return this.committed
  }

  /**
   * Serializes this session to a JSON-safe snapshot (includes secret nonces).
   * @returns The session snapshot.
   */
  toSnapshot (): SigningSessionSnapshot {
    return {
      id: this.id,
      committed: this.committed,
      message: this.message === undefined ? undefined : bigToHex(this.message),
      localBindings: this.localBindings.map((sb) => ({
        nonces: {
          hidingNonce: bigToHex(sb.bindings.nonces.hidingNonce),
          bindingNonce: bigToHex(sb.bindings.nonces.bindingNonce),
        },
        commitments: commitmentToSnapshot(sb.bindings.commitments),
        share: { id: sb.share.id, skShare: bigToHex(sb.share.skShare) },
      })),
      remoteSigners: this.remoteSigners.map(commitmentToSnapshot),
      partials: Array.from(this.partialsById.entries()).map(([id, v]) => [id, bigToHex(v)]),
    }
  }

  /**
   * Rebuilds a session from a snapshot produced by {@link SigningSession#toSnapshot}.
   * @param manager Owning manager for the restored session.
   * @param snap A session snapshot.
   * @returns The restored session.
   */
  static fromSnapshot (manager: FROSTSigningManager, snap: SigningSessionSnapshot): SigningSession {
    const session = new SigningSession(manager, snap.id)
    session.committed = snap.committed
    session.message = snap.message === undefined ? undefined : BigInt(snap.message)
    session.localBindings = snap.localBindings.map((b) => ({
      bindings: {
        nonces: { hidingNonce: BigInt(b.nonces.hidingNonce), bindingNonce: BigInt(b.nonces.bindingNonce) },
        commitments: snapshotToCommitment(b.commitments),
      },
      share: { id: b.share.id, skShare: BigInt(b.share.skShare) },
    }))
    session.remoteSigners = snap.remoteSigners.map(snapshotToCommitment)
    session.partialsById = new Map(snap.partials.map(([id, v]) => [id, BigInt(v)]))
    return session
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
    // A participant identifier of 0 would make this signer's share the shared
    // secret itself; the interpolation rejects it, so refuse it at the door.
    if (!Number.isInteger(signer.id) || signer.id <= 0) {
      throw new Error(`invalid signer id ${signer.id}: participant identifiers must be positive integers`)
    }
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

  // --- persistence ----------------------------------------------------------

  /**
   * Serializes the manager to a snapshot that carries no live nonces, and is
   * therefore sound to restore any number of times.
   *
   * Sessions that have already committed (run round1) hold local nonces, so
   * they are **dropped**; their ids are listed in `omittedSessions`. To resume a
   * committed session you need {@link FROSTSigningManager#toMidRoundJSON}, which
   * carries a single-use hazard.
   *
   * The snapshot still contains `signers[].skShare` — long-term key material —
   * so persist it only to trusted storage.
   * @returns A versioned, hex-encoded `safe` snapshot suitable for JSON.stringify.
   */
  toJSON (): SigningManagerSnapshot {
    const live = Array.from(this.sessions.values())
    const resumable = live.filter((s) => !s.hasCommitted())
    const omitted = live.filter((s) => s.hasCommitted()).map((s) => s.id)
    return {
      version: SNAPSHOT_VERSION,
      kind: 'safe',
      threshold: this.threshold,
      groupPublicKey: pointToHex(this.groupPublicKey),
      signers: this.signers.map((s) => ({ id: s.id, skShare: bigToHex(s.skShare) })),
      sessions: resumable.map((s) => s.toSnapshot()),
      ...(omitted.length ? { omittedSessions: omitted } : {}),
    }
  }

  /**
   * Serializes the manager including the local nonces of committed sessions, so
   * a signing already past round 1 can be resumed and still produce partials
   * that match the commitments peers hold.
   *
   * **This snapshot is single use.** The nonces it carries must sign at most one
   * message. Restoring the same payload more than once and signing different
   * messages reuses `(hidingNonce, bindingNonce)` across distinct challenges;
   * enough such partials form a solvable linear system in the signer's secret
   * share. Restoring twice is a key-compromise event even inside trusted
   * storage, so the caller must mark the stored payload consumed *before*
   * signing from it, and never fan it out to more than one process.
   * @returns A versioned, hex-encoded `mid-round` snapshot. Treat as single use.
   */
  toMidRoundJSON (): SigningManagerSnapshot {
    return {
      version: SNAPSHOT_VERSION,
      kind: 'mid-round',
      threshold: this.threshold,
      groupPublicKey: pointToHex(this.groupPublicKey),
      signers: this.signers.map((s) => ({ id: s.id, skShare: bigToHex(s.skShare) })),
      sessions: Array.from(this.sessions.values()).map((s) => s.toSnapshot()),
    }
  }

  /**
   * Rebuilds a manager from a `safe` snapshot produced by {@link FROSTSigningManager#toJSON}.
   *
   * Rejects a `mid-round` payload: restoring one is the single-use operation
   * that must be spelled out at the call site.
   * @param snapshot A `safe` snapshot at the current SNAPSHOT_VERSION.
   * @returns A manager restored to the snapshot's state.
   */
  static fromJSON (snapshot: SigningManagerSnapshot): FROSTSigningManager {
    if (snapshot?.kind === 'mid-round') {
      throw new Error('this is a mid-round snapshot and carries live nonces; restore it with fromMidRoundJSON(), which must be used at most once per snapshot')
    }
    return FROSTSigningManager.restore(snapshot, 'safe')
  }

  /**
   * Rebuilds a manager from a `mid-round` snapshot produced by
   * {@link FROSTSigningManager#toMidRoundJSON}, including live nonces.
   *
   * **Use at most once per snapshot.** See `toMidRoundJSON` for why: a second
   * restore that signs a different message reuses the nonces and can expose the
   * signing share. Mark the stored payload consumed before calling this.
   * @param snapshot A `mid-round` snapshot at the current SNAPSHOT_VERSION.
   * @returns A manager restored to the snapshot's exact state, nonces included.
   */
  static fromMidRoundJSON (snapshot: SigningManagerSnapshot): FROSTSigningManager {
    return FROSTSigningManager.restore(snapshot, 'mid-round')
  }

  /**
   * Shared restore path for both snapshot kinds.
   * @param snapshot Snapshot to rebuild from.
   * @param expected Snapshot kind the caller has already validated.
   * @returns The restored manager.
   */
  private static restore (snapshot: SigningManagerSnapshot, expected: SnapshotKind): FROSTSigningManager {
    if (!snapshot || snapshot.version !== SNAPSHOT_VERSION) {
      throw new Error(`unsupported signing snapshot version: ${snapshot?.version}`)
    }
    if (snapshot.kind !== expected) {
      const use = expected === 'mid-round' ? 'fromJSON()' : 'fromMidRoundJSON()'
      throw new Error(`expected a ${expected} snapshot, got kind '${snapshot.kind}'; restore that payload with ${use}`)
    }
    const manager = new FROSTSigningManager(hexToPoint(snapshot.groupPublicKey), snapshot.threshold)
    for (const s of snapshot.signers) manager.signers.push({ id: s.id, skShare: BigInt(s.skShare) })
    for (const sessSnap of snapshot.sessions) {
      manager.sessions.set(sessSnap.id, SigningSession.fromSnapshot(manager, sessSnap))
    }
    return manager
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

export type { SignerShare, SessionBinding, PartialSignature, SigningManagerSnapshot, SigningSessionSnapshot }
export { FROSTSigningManager, SigningSession }
