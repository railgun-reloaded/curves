import {
  x25519
} from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { bytesToBigInt } from '@railgun-reloaded/bytes'

import type { Point } from '../babyjubjub.js'
import { TrustedDKG } from '../frost/trusted-dkg.js'
import type { EncryptedShare } from '../frost/types.js'

// Lightweight internal state to prevent wrong-order usage and surface clear errors
// also output state updates for the upstream clients.

enum DKGFlowState {
  Init = 'init',
  RosterAssigned = 'roster-assigned',
  CommitmentsCreated = 'commitments-created',
  CommitmentsCollected = 'commitments-collected',
  SharesEncrypted = 'shares-encrypted',
  EncryptedSharesCollected = 'encrypted-shares-collected',
  Finalized = 'finalized',
}

/**
 * Local pipeline progress — the steps *this* participant has performed.
 *
 * This is deliberately separate from collection progress (which dealer
 * commitments / encrypted shares have arrived). Those are two independent
 * dimensions of a DKG round: a dealer produces its own artifacts while
 * concurrently receiving peers', and peer messages arrive out of order.
 * Tracking them separately and deriving the linear {@link DKGFlowState} on
 * demand keeps a single source of truth and avoids lockstep assumptions.
 */
interface DKGSteps {
  rosterAssigned: boolean
  selfCommitmentsCreated: boolean
  selfSharesEncrypted: boolean
  finalized: boolean
}

const SNAPSHOT_VERSION = 1

/**
 * JSON-safe, resumable snapshot of a {@link DKGManager}.
 *
 * All binary and bigint fields are hex-encoded so the object round-trips
 * through `JSON.stringify`/`JSON.parse`. NOTE: this contains the participant's
 * secret communication key and decrypted local shares — treat it as secret.
 */
interface DKGSnapshot {
  version: number
  name: string
  secretComKey: string
  participantID?: number | undefined
  roster: Record<number, string>
  keysByID: Record<number, string>
  shares: Record<number, string>
  recipientIds: number[]
  encryptedShares: Record<number, Record<number, { nonce: string; ciphertext: string }>>
  commitmentsByDealerId: Record<number, [string, string][]>
  steps: DKGSteps
}

/**
 * Stateful orchestration helper for trusted-dealer and coordinator-less DKG.
 *
 * Instances are single-flow helpers. Recreate them for new sessions instead of
 * trying to reuse finalized state. In-progress sessions can be persisted and
 * resumed across process restarts via {@link DKGManager#toJSON} and
 * {@link DKGManager.fromJSON}.
 */
class DKGManager {
  /** Human-readable participant name used in announcements. */
  name: string
  /** Underlying trusted-dealer / coordinator-less DKG primitive. */
  dkg: TrustedDKG
  /** Local participant identifier once the roster is known. */
  participantID: number | undefined
  /** Secret X25519 communication key used for share encryption. */
  private secretComKey: Uint8Array
  /** Public X25519 communication key announced to peers. */
  pubComKey: Uint8Array
  /** Mapping of participant id to public communication key. */
  roster: Record<number, Uint8Array>
  /** Per-peer shared secrets derived from the roster. */
  keysByID: Record<number, Uint8Array> = {}
  /** This participant's decrypted shares keyed by dealer id. */
  private shares: Record<number, bigint> = {}
  /** Participant identifiers this dealer produced shares for. */
  recipientIds: number[] = []
  /** Encrypted share bundles keyed by dealer id then recipient id. */
  encryptedShares: Record<number, Record<number, EncryptedShare>> = {}
  /** Public commitment vectors keyed by dealer id. */
  private commitmentsByDealerId: Record<number, Point<bigint>[]> = {}

  /**
   * Local pipeline progress. Collection progress lives in the maps above and is
   * queried via rosterCovers(); the linear state is derived from both.
   */
  private steps: DKGSteps = {
    rosterAssigned: false,
    selfCommitmentsCreated: false,
    selfSharesEncrypted: false,
    finalized: false,
  }

  /** Monotonic ordering used to compare flow states. */
  private readonly stateOrder: Record<DKGFlowState, number> = {
    [DKGFlowState.Init]: 0,
    [DKGFlowState.RosterAssigned]: 1,
    [DKGFlowState.CommitmentsCreated]: 2,
    [DKGFlowState.CommitmentsCollected]: 3,
    [DKGFlowState.SharesEncrypted]: 4,
    [DKGFlowState.EncryptedSharesCollected]: 5,
    [DKGFlowState.Finalized]: 6,
  }

  // --- derived-state selectors ---------------------------------------------

  /**
   * Roster participant ids in ascending order.
   * @returns The roster ids, sorted ascending.
   */
  private sortedRosterIds (): number[] {
    return Object.keys(this.roster || {}).map(Number).sort((a, b) => a - b)
  }

  /**
   * Reports whether a per-dealer map has exactly one entry per roster id.
   * @param map Map keyed by dealer/participant id to test for completeness.
   * @returns True when the map covers the full roster (a complete set).
   */
  private rosterCovers (map: Record<number, unknown>): boolean {
    const rosterIds = this.sortedRosterIds()
    if (!rosterIds.length) return false
    const ids = Object.keys(map).map(Number).sort((a, b) => a - b)
    return ids.length === rosterIds.length && rosterIds.every((id, i) => id === ids[i])
  }

  /**
   * Lists peers whose dealer commitments are still outstanding.
   * @returns Roster ids whose dealer commitments have not yet been collected.
   */
  missingCommitments (): number[] {
    return this.sortedRosterIds().filter((id) => !this.commitmentsByDealerId[id])
  }

  /**
   * Lists peers whose encrypted-share bundles are still outstanding.
   * @returns Roster ids whose encrypted-share bundles have not yet been collected.
   */
  missingEncryptedShares (): number[] {
    return this.sortedRosterIds().filter((id) => !this.encryptedShares[id])
  }

  /**
   * Reports whether every roster member's dealer commitments have arrived.
   * @returns True once the commitment set covers the full roster.
   */
  private commitmentsComplete (): boolean { return this.rosterCovers(this.commitmentsByDealerId) }

  /**
   * Reports whether every roster member's encrypted share bundle has arrived.
   * @returns True once the encrypted-share set covers the full roster.
   */
  private encryptedSharesComplete (): boolean { return this.rosterCovers(this.encryptedShares) }

  /**
   * Projects the two progress dimensions onto the legacy linear flow state.
   * State is derived from data, never assigned imperatively, so collection of
   * the final commitment/share automatically advances the reported state.
   * @returns The current DKG flow state.
   */
  getState (): DKGFlowState {
    if (this.steps.finalized) return DKGFlowState.Finalized
    if (this.encryptedSharesComplete()) return DKGFlowState.EncryptedSharesCollected
    if (this.steps.selfSharesEncrypted) return DKGFlowState.SharesEncrypted
    if (this.commitmentsComplete()) return DKGFlowState.CommitmentsCollected
    if (this.steps.selfCommitmentsCreated) return DKGFlowState.CommitmentsCreated
    if (this.steps.rosterAssigned) return DKGFlowState.RosterAssigned
    return DKGFlowState.Init
  }

  /**
   * Coordination snapshot for UIs and protocol drivers: the derived state plus
   * exactly what this participant is still waiting on from peers.
   * @returns Current state and the roster ids with outstanding artifacts.
   */
  progress () {
    return {
      state: this.getState(),
      awaitingCommitments: this.missingCommitments(),
      awaitingEncryptedShares: this.missingEncryptedShares(),
    }
  }

  // --- guards ---------------------------------------------------------------

  /**
   * Throws unless the current state is one of the allowed states.
   * @param where Caller name used in the error message.
   * @param allowed States permitted for the calling operation.
   */
  private ensureStateIn (where: string, allowed: DKGFlowState[]) {
    const state = this.getState()
    if (!allowed.includes(state)) {
      const allowedStr = allowed.join('|')
      throw new Error(`${where} invalid state: ${state}; allowed: ${allowedStr}`)
    }
  }

  /**
   * Throws unless the current state is at least the given minimum.
   * @param where Caller name used in the error message.
   * @param min Minimum state required for the calling operation.
   */
  private ensureStateAtLeast (where: string, min: DKGFlowState) {
    const state = this.getState()
    if (this.stateOrder[state] < this.stateOrder[min]) {
      throw new Error(`${where} requires state >= ${min}, current=${state}`)
    }
  }

  /**
   * Returns every dealer's commitment vector ordered by dealer id.
   * @returns Commitment vectors for all dealers in roster order.
   */
  private getAllDealerCommitments (): Point<bigint>[][] {
    // must have collected complete commitments set
    this.ensureStateAtLeast('getAllDealerCommitments', DKGFlowState.CommitmentsCollected)
    if (!this.sortedRosterIds().length) throw new Error('roster not assigned')
    if (!Object.keys(this.commitmentsByDealerId).length) throw new Error('no dealer commitments have been added')
    if (!this.commitmentsComplete()) throw new Error('missing commitments for one or more dealers')

    return this.sortedRosterIds().map((id) => this.commitmentsByDealerId[id]!)
  }

  /**
   * Creates a DKG manager for a named participant.
   * @param participantName Human-readable participant name.
   * @param secretCommKey Optional 32-byte communication key; random if omitted.
   */
  constructor (participantName: string, secretCommKey?: Uint8Array) {
    this.dkg = new TrustedDKG()
    // this.secretComKey = this.dkg.RandomScalar() -- example of another way for random bytes... this key does not need to be a scalar though.
    this.secretComKey = secretCommKey ?? randomBytes(32)
    this.name = participantName
    // this will be announced with public commitments
    this.pubComKey = this.getPublicKey(this.secretComKey)
    this.roster = {}
  }

  // --- persistence ----------------------------------------------------------

  /**
   * Serializes the in-progress (or finalized) session to a JSON-safe snapshot.
   *
   * The snapshot includes secret material (this participant's communication key
   * and any decrypted local shares); persist it only to trusted storage.
   * @returns A versioned, hex-encoded snapshot suitable for JSON.stringify.
   */
  toJSON (): DKGSnapshot {
    /**
     * Hex-encodes a bigint for the snapshot.
     * @param v Value to encode.
     * @returns The 0x-prefixed hex encoding.
     */
    const bigHex = (v: bigint) => '0x' + v.toString(16)
    /**
     * Hex-encodes every byte array in an id-keyed record.
     * @param rec Record of id to bytes.
     * @returns The same record with hex-encoded values.
     */
    const bytesRecord = (rec: Record<number, Uint8Array>) => {
      const out: Record<number, string> = {}
      for (const id in rec) out[id] = bytesToHex(rec[id]!)
      return out
    }

    const shares: Record<number, string> = {}
    for (const id in this.shares) shares[id] = bigHex(this.shares[id]!)

    const encryptedShares: DKGSnapshot['encryptedShares'] = {}
    for (const dealerId in this.encryptedShares) {
      const bundle = this.encryptedShares[dealerId]!
      const outBundle: Record<number, { nonce: string; ciphertext: string }> = {}
      for (const rid in bundle) {
        const e = bundle[rid]!
        outBundle[rid] = { nonce: bytesToHex(e.nonce), ciphertext: bytesToHex(e.ciphertext) }
      }
      encryptedShares[dealerId] = outBundle
    }

    const commitmentsByDealerId: DKGSnapshot['commitmentsByDealerId'] = {}
    for (const dealerId in this.commitmentsByDealerId) {
      commitmentsByDealerId[dealerId] = this.commitmentsByDealerId[dealerId]!.map(
        (pt) => [bigHex(pt[0]), bigHex(pt[1])] as [string, string]
      )
    }

    return {
      version: SNAPSHOT_VERSION,
      name: this.name,
      secretComKey: bytesToHex(this.secretComKey),
      participantID: this.participantID,
      roster: bytesRecord(this.roster),
      keysByID: bytesRecord(this.keysByID),
      shares,
      recipientIds: [...this.recipientIds],
      encryptedShares,
      commitmentsByDealerId,
      steps: { ...this.steps },
    }
  }

  /**
   * Rebuilds a manager from a snapshot produced by {@link DKGManager#toJSON}.
   * @param snapshot A snapshot at the current SNAPSHOT_VERSION.
   * @returns A manager restored to the snapshot's exact orchestration state.
   */
  static fromJSON (snapshot: DKGSnapshot): DKGManager {
    if (!snapshot || snapshot.version !== SNAPSHOT_VERSION) {
      throw new Error(`unsupported DKG snapshot version: ${snapshot?.version}`)
    }
    const mgr = new DKGManager(snapshot.name, hexToBytes(snapshot.secretComKey))
    mgr.participantID = snapshot.participantID

    /**
     * Decodes every hex string in an id-keyed record back to bytes.
     * @param rec Record of id to hex string.
     * @returns The same record with decoded byte values.
     */
    const bytesRecord = (rec: Record<number, string>) => {
      const out: Record<number, Uint8Array> = {}
      for (const id in rec) out[id] = hexToBytes(rec[id]!)
      return out
    }
    mgr.roster = bytesRecord(snapshot.roster)
    mgr.keysByID = bytesRecord(snapshot.keysByID)

    const shares: Record<number, bigint> = {}
    for (const id in snapshot.shares) shares[id] = BigInt(snapshot.shares[id]!)
    mgr.shares = shares

    mgr.recipientIds = [...snapshot.recipientIds]

    const encryptedShares: Record<number, Record<number, EncryptedShare>> = {}
    for (const dealerId in snapshot.encryptedShares) {
      const bundle = snapshot.encryptedShares[dealerId]!
      const outBundle: Record<number, EncryptedShare> = {}
      for (const rid in bundle) {
        const e = bundle[rid]!
        outBundle[rid] = { nonce: hexToBytes(e.nonce), ciphertext: hexToBytes(e.ciphertext) }
      }
      encryptedShares[dealerId] = outBundle
    }
    mgr.encryptedShares = encryptedShares

    const commitmentsByDealerId: Record<number, Point<bigint>[]> = {}
    for (const dealerId in snapshot.commitmentsByDealerId) {
      commitmentsByDealerId[dealerId] = snapshot.commitmentsByDealerId[dealerId]!.map(
        (pt) => [BigInt(pt[0]), BigInt(pt[1])] as Point<bigint>
      )
    }
    mgr.commitmentsByDealerId = commitmentsByDealerId

    mgr.steps = { ...snapshot.steps }
    return mgr
  }

  /**
   * Runs a single trusted-dealer key generation flow and returns finalized outputs.
   * @param privateKey Dealer secret used as the constant polynomial term.
   * @param desiredShares Total number of participant shares to derive.
   * @param threshold Minimum number of shares required for signing/recovery.
   * @returns Finalized trusted-dealer shares, group public key, and viewing key.
   */
  runTrustedKeygen (privateKey: bigint, desiredShares: number, threshold: number) {
    if (!Number.isInteger(desiredShares) || desiredShares <= 0) throw new Error('desiredShares must be a positive integer')
    if (!Number.isInteger(threshold) || threshold <= 0) throw new Error('threshold must be a positive integer')
    if (threshold > desiredShares) throw new Error('threshold cannot exceed desiredShares')
    const result = this.dkg.trustedDealerKeygen(privateKey, desiredShares, threshold)
    const groupInfo = this.dkg.deriveGroupInfo(desiredShares, threshold, result.vssCommitment)

    const output = {
      shares: result.participantPrivateKeys.map(a => {
        return {
          identifier: a.x_i,
          skShare: '0x' + this.dkg.modOrder(a.y_i * 8n).toString(16),
          skShareDiv8: '0x' + a.y_i.toString(16)
        }
      }),
      groupPublicKey: groupInfo.PK!.map(a => '0x' + a.toString(16)),
      viewingPrivateKey: groupInfo.viewingPrivateKey,
    }
    return output
  }

  /**
   * Returns this participant's announcement payload for roster construction.
   * @returns The participant name and public X25519 communication key.
   */
  getAnnouncement () {
    return { pubKey: this.pubComKey, name: this.name }
  }

  /**
   * Assigns the local participant identifier once the roster is known.
   * @param identifier Positive integer identifier assigned to this participant.
   */
  assignIdentifier (identifier: number) {
    if (!Number.isInteger(identifier) || identifier <= 0) throw new Error('bad participant identifier')
    this.participantID = identifier
  }

  /**
   * Assigns the full participant roster and derives per-peer shared secrets.
   * The local participant's own announcement key must be present in the roster.
   * @param roster Mapping of participant id to 32-byte public communication key.
   */
  assignRoster (roster: Record<number, Uint8Array>) {
    this.ensureStateIn('assignRoster', [DKGFlowState.Init])
    // Basic shape validation
    if (!roster || typeof roster !== 'object') throw new Error('invalid roster')
    const ids = Object.keys(roster).map(Number).sort((a, b) => a - b)
    if (!ids.length) throw new Error('empty roster')
    ids.forEach((id) => { if (!Number.isInteger(id) || id <= 0) throw new Error(`bad roster id: ${id}`) })

    this.roster = {}
    this.keysByID = {}
    let matchedSelf = false
    for (const idStr in roster) {
      const id = Number(idStr)
      const key = roster[id]!
      if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error(`bad roster pubkey for id ${id}`)
      this.roster[id] = key
      if (bytesToBigInt(this.pubComKey) === bytesToBigInt(key)) {
        this.assignIdentifier(id)
        matchedSelf = true
      }
      const shared = this.getSharedSecret(key)
      if (!shared || shared.length !== 32) throw new Error(`failed to derive shared secret for id ${id}`)
      this.keysByID[id] = shared
    }
    if (!matchedSelf) throw new Error('our announcement pubKey not present in roster')
    this.steps.rosterAssigned = true
  }

  /**
   * Generates local polynomial commitments and dealer shares for a DKG round.
   * Produces only — the caller broadcasts the returned commitments and feeds
   * them back through {@link DKGManager#addParticipantCommitments}, exactly as
   * it does for every peer dealer (one uniform collection path).
   * @param secret Dealer secret used as the constant polynomial term.
   * @param desiredShares Total number of participants expected in the roster.
   * @param threshold Minimum number of shares required by the DKG.
   * @returns The dealer's per-recipient shares and public commitments.
   */
  commitmentRound (secret: bigint, desiredShares: number, threshold: number) {
    if (typeof this.participantID === 'undefined') throw new Error('missing participant identifier')
    this.ensureStateIn('commitmentRound', [DKGFlowState.RosterAssigned])
    if (!Number.isInteger(desiredShares) || desiredShares <= 0) throw new Error('desiredShares must be a positive integer')
    if (!Number.isInteger(threshold) || threshold <= 0) throw new Error('threshold must be a positive integer')
    if (threshold > desiredShares) throw new Error('threshold cannot exceed desiredShares')

    // Ensure roster matches desiredShares
    const rosterIds = Object.keys(this.roster).map(Number).sort((a, b) => a - b)
    if (rosterIds.length !== desiredShares) throw new Error('roster size does not match desiredShares')

    const { coefficients, vssCommitment: commitments } = this.dkg.trustedDealerKeygen(secret, desiredShares, threshold)
    const recipientIds = []
    for (let id = 1; id <= desiredShares; id++) {
      recipientIds.push(id)
    }
    this.recipientIds = recipientIds
    const shares = this.dkg.computeSharesForIds(coefficients, recipientIds)
    this.shares = shares
    this.steps.selfCommitmentsCreated = true
    return { shares, commitments }
  }

  /**
   * Stores a dealer's public commitments for later verification and finalization.
   * @param participantID Dealer identifier.
   * @param participantCommitments Public commitments broadcast by that dealer.
   */
  addParticipantCommitments (participantID: number, participantCommitments: Point<bigint>[]) {
    this.ensureStateIn('addParticipantCommitments', [DKGFlowState.CommitmentsCreated, DKGFlowState.CommitmentsCollected])
    if (!Number.isInteger(participantID) || participantID <= 0) throw new Error('bad participant id for commitments')
    if (!participantCommitments?.length) throw new Error('empty commitments from participant')
    // State advances automatically once this completes the set (see getState).
    this.commitmentsByDealerId[participantID] = participantCommitments
  }

  /**
   * Stores a dealer's encrypted share bundle for this DKG session.
   * @param participantID Dealer identifier.
   * @param shares Map of recipient id to encrypted share payload.
   */
  addEncryptedShares (participantID: number, shares: Record<number, EncryptedShare>) {
    this.ensureStateAtLeast('addEncryptedShares', DKGFlowState.CommitmentsCollected)
    if (!Number.isInteger(participantID) || participantID <= 0) throw new Error('bad dealer id for encrypted shares')
    if (!shares || typeof shares !== 'object') throw new Error('invalid encrypted shares bundle')
    // Malformed entries are tolerated here and surface a strong error at decrypt
    // time (getDecryptedShares). State advances automatically once this
    // completes the set (see getState).
    this.encryptedShares[participantID] = shares
  }

  /**
   * Encrypts local dealer shares for each roster participant using AES-GCM.
   * @returns A per-recipient map of encrypted share payloads.
   */
  getEncryptedShares () {
    // commitmentRound() does not self-add its own commitments; the caller feeds
    // them back through addParticipantCommitments() like any peer's. A caller
    // written against the older self-adding behaviour otherwise just stalls here
    // waiting on itself, so name that case explicitly.
    if (
      typeof this.participantID !== 'undefined' &&
      this.steps.selfCommitmentsCreated &&
      !this.commitmentsByDealerId[this.participantID]
    ) {
      throw new Error(`getEncryptedShares is still awaiting this participant's own commitments (id ${this.participantID}); commitmentRound() does not self-add, feed its commitments back via addParticipantCommitments()`)
    }
    // make sure the commitments are not empty, and same length as 'max participants'
    this.ensureStateIn('getEncryptedShares', [DKGFlowState.CommitmentsCollected])
    if (!Object.keys(this.shares).length) throw new Error('no local shares computed; run commitmentRound first')
    const allDealerCommitments = this.getAllDealerCommitments()
    // Ensure we have derived a shared key for every intended recipient
    const rosterIds = Object.keys(this.roster).map(Number).sort((a, b) => a - b)
    for (const id of rosterIds) {
      const k = this.keysByID[id]
      if (!k || k.length !== 32) throw new Error(`missing shared key for participant ${id}`)
    }
    const out = this.dkg.encryptSharesAESGCMWithAAD(this.shares, this.keysByID, allDealerCommitments)
    this.steps.selfSharesEncrypted = true
    return out
  }

  /**
   * Decrypts the caller's shares from every dealer once all bundles are available.
   * @returns A map of dealer id to decrypted share scalar.
   */
  getDecryptedShares () {
    if (typeof this.participantID === 'undefined') throw new Error('missing participant identifier')
    this.ensureStateIn('getDecryptedShares', [DKGFlowState.EncryptedSharesCollected])
    const allDealerCommitments = this.getAllDealerCommitments()
    const decryptedByDealer: Record<number, bigint> = {}
    const rosterIds = Object.keys(this.roster).map(Number).sort((a, b) => a - b)

    const missing: number[] = []
    for (const dealerId of rosterIds) {
      const bundle = this.encryptedShares[dealerId]
      const enc = bundle?.[this.participantID]
      const key = this.keysByID[dealerId]
      if (!bundle || !enc || !key) {
        missing.push(dealerId)
        continue
      }
      let decrypted: bigint
      try {
        decrypted = this.dkg.decryptShareAESGCMWithAAD(
          enc,
          key,
          this.participantID,
          allDealerCommitments
        )
      } catch (cause) {
        throw new Error(`failed to decrypt share from dealer ${dealerId}`, { cause })
      }
      // Verify the decrypted share lies on the dealer's committed polynomial.
      // AES-GCM AAD only authenticates transport against the commitment digest;
      // it does not prove the share is consistent with the Feldman commitments.
      // Without this check a malicious/buggy dealer could fold an invalid share
      // into the aggregate signing key undetected.
      const dealerCommitments = this.commitmentsByDealerId[dealerId]
      if (!dealerCommitments || !this.dkg.verifyFeldmanShare(this.participantID, decrypted, dealerCommitments)) {
        throw new Error(`invalid share from dealer ${dealerId}: failed Feldman verification`)
      }
      decryptedByDealer[dealerId] = decrypted
    }
    if (missing.length) {
      throw new Error(`missing encrypted shares or keys from dealers: ${missing.join(', ')}`)
    }
    return decryptedByDealer
  }

  /**
   * Finalizes the participant's aggregate signing share and group metadata.
   * @returns The finalized participant share, group public key, and viewing key.
   */
  finalize () {
    if (typeof this.participantID === 'undefined') throw new Error('missing participant identifier')
    this.ensureStateIn('finalize', [DKGFlowState.EncryptedSharesCollected])
    const dec = this.getDecryptedShares()
    const shares: Array<{ dealerId: number; s_ki: bigint }> = []
    for (const d in dec) {
      shares.push({ dealerId: Number(d), s_ki: dec[d]! })
    }
    const allDealerCommitments = this.getAllDealerCommitments()
    const res = this.dkg.finalizeParticipant(this.participantID, shares, allDealerCommitments)
    this.steps.finalized = true
    return res
  }

  /**
   * Derives the public X25519 communication key used for share transport.
   * @param secretKey Private 32-byte X25519-compatible secret key.
   * @returns The public communication key.
   */
  getPublicKey (secretKey: Uint8Array) {
    const key = x25519.getPublicKey(secretKey)
    return key
  }

  /**
   * Derives a shared secret with another participant's communication key.
   * @param theirPub Another participant's public communication key.
   * @returns The derived shared secret.
   */
  getSharedSecret (theirPub: Uint8Array) {
    const shared = x25519.getSharedSecret(this.secretComKey, theirPub)
    return shared
  }
}

export { DKGManager, DKGFlowState }
export type { DKGSnapshot }
