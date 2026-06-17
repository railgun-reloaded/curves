import {
  x25519
} from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToBigInt } from '@railgun-reloaded/bytes'
import type { Point } from '@zk-kit/baby-jubjub'

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
 * Stateful orchestration helper for trusted-dealer and coordinator-less DKG.
 *
 * Instances are single-flow helpers. Recreate them for new sessions instead of
 * trying to reuse finalized state.
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

  /** Current orchestration state guarding call ordering. */
  private state: DKGFlowState = DKGFlowState.Init

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

  /**
   * Throws unless the current state is one of the allowed states.
   * @param where Caller name used in the error message.
   * @param allowed States permitted for the calling operation.
   */
  private ensureStateIn (where: string, allowed: DKGFlowState[]) {
    if (!allowed.includes(this.state)) {
      const allowedStr = allowed.join('|')
      throw new Error(`${where} invalid state: ${this.state}; allowed: ${allowedStr}`)
    }
  }

  /**
   * Throws unless the current state is at least the given minimum.
   * @param where Caller name used in the error message.
   * @param min Minimum state required for the calling operation.
   */
  private ensureStateAtLeast (where: string, min: DKGFlowState) {
    if (this.stateOrder[this.state] < this.stateOrder[min]) {
      throw new Error(`${where} requires state >= ${min}, current=${this.state}`)
    }
  }

  /**
   * Returns the current orchestration state for UI or protocol coordination.
   * @returns The current DKG flow state.
   */
  getState () { return this.state }

  /**
   * Returns every dealer's commitment vector ordered by dealer id.
   * @returns Commitment vectors for all dealers in roster order.
   */
  private getAllDealerCommitments (): Point<bigint>[][] {
    // must have collected complete commitments set
    this.ensureStateAtLeast('getAllDealerCommitments', DKGFlowState.CommitmentsCollected)
    const rosterIds = Object.keys(this.roster || {}).map(Number).sort((a, b) => a - b)
    if (!rosterIds.length) throw new Error('roster not assigned')

    const ids = Object.keys(this.commitmentsByDealerId).map(Number).sort((a, b) => a - b)
    if (ids.length === 0) throw new Error('no dealer commitments have been added')
    if (ids.length !== rosterIds.length || ids.some((id, i) => id !== rosterIds[i])) {
      throw new Error('missing commitments for one or more dealers')
    }
    const ordered: Point<bigint>[][] = []
    for (const id of ids) ordered.push(this.commitmentsByDealerId[id]!)
    return ordered
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
    this.state = DKGFlowState.RosterAssigned
  }

  /**
   * Generates local polynomial commitments and dealer shares for a DKG round.
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
    this.state = DKGFlowState.CommitmentsCreated
    this.addParticipantCommitments(this.participantID!, commitments)
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
    this.commitmentsByDealerId[participantID] = participantCommitments
    // If roster is known and we have a full set of commitments, advance state
    const rosterIds = Object.keys(this.roster || {}).map(Number).sort((a, b) => a - b)
    const commitIds = Object.keys(this.commitmentsByDealerId).map(Number).sort((a, b) => a - b)
    if (rosterIds.length && rosterIds.length === commitIds.length && rosterIds.every((id, i) => id === commitIds[i])) {
      this.state = DKGFlowState.CommitmentsCollected
    }
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
    // Basic validation for our expected entry if we know our id
    if (typeof this.participantID !== 'undefined') {
      const mine = shares[this.participantID]
      if (!mine || !(mine.nonce instanceof Uint8Array) || !(mine.ciphertext instanceof Uint8Array)) {
        // Allow storing anyway, but surface a strong error when decrypting
      }
    }
    this.encryptedShares[participantID] = shares
    const rosterIds = Object.keys(this.roster || {}).map(Number).sort((a, b) => a - b)
    const encIds = Object.keys(this.encryptedShares).map(Number).sort((a, b) => a - b)
    if (rosterIds.length && rosterIds.length === encIds.length && rosterIds.every((id, i) => id === encIds[i])) {
      this.state = DKGFlowState.EncryptedSharesCollected
    }
  }

  /**
   * Encrypts local dealer shares for each roster participant using AES-GCM.
   * @returns A per-recipient map of encrypted share payloads.
   */
  getEncryptedShares () {
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
    this.state = DKGFlowState.SharesEncrypted
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
    this.state = DKGFlowState.Finalized
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
