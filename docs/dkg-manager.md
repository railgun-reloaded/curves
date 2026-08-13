# DKGManager

A small orchestration helper around the FROST DKG primitives that supports two flows:

- Trusted-dealer keygen: one dealer produces all shares and the group public key.
- Coordinator-less multi-dealer: many dealers each contribute a polynomial; participants encrypt/decrypt shares and finalize their own share.

This README covers the public API, step-by-step usage, and common errors. The code lives in `src/manager/dkg.ts`.

## Determinism (by design)

Given the same input secrets, the DKG produces:

- a **deterministic** group public key and `viewingPrivateKey` — both depend only on the secrets (the constant terms of the dealer polynomials), so re-running with the same secrets always yields the same group key; and
- **non-deterministic** individual signing shares (`skShare`) — the higher-order polynomial coefficients are sampled fresh from a CSPRNG on every run (`trustedDealerKeygen`), so each run yields a different valid (t, n) sharing of the *same* group secret.

This is intentional and is **not** a bug: reproducible secret shares would let a re-run regenerate identical share material (a replay/leakage footgun). Any threshold subset still reconstructs and signs for the same group public key. To recover or resume a participant's exact share, persist its snapshot via `toJSON()`/`fromJSON()` rather than relying on re-derivation. (Two other values default to random but do not affect the resulting keys: the communication keypair — pass one to the constructor to fix it — and FROST signing nonces.)

## Public API (stable)

- `new DKGManager()`
- `getAnnouncement(): { pubKey: Uint8Array }` — publish your X25519 public key for share encryption.
- `assignRoster(roster: Record<number, Uint8Array>): void` — map of participantId → X25519 public key. Your own key must be present.
- `runTrustedKeygen(secret: bigint, n: number, t: number)` → `{ shares, groupPublicKey, viewingPrivateKey }`
- `commitmentRound(secret: bigint, n: number, t: number)` → `{ shares: Record<number, bigint>, commitments: Point[] }`
- `addParticipantCommitments(dealerId: number, commitments: Point[]): void`
- `getEncryptedShares()` → `Record<number, { nonce: Uint8Array, ciphertext: Uint8Array }>`
- `addEncryptedShares(dealerId: number, shares: Record<number, EncryptedShare>): void`
- `finalize()` → `{ share: { id, skShare, skShareDiv8 }, PKGroup, viewingPrivateKey }`

Coordination & persistence
- `getState(): DKGFlowState` — current flow state, derived from collected data (never tracked imperatively).
- `progress()` → `{ state, awaitingCommitments: number[], awaitingEncryptedShares: number[] }` — what this participant is still waiting on from peers.
- `missingCommitments(): number[]` / `missingEncryptedShares(): number[]` — outstanding roster ids per dimension.
- `toJSON(): DKGSnapshot` — JSON-safe, versioned snapshot for pause/resume. **Contains secret material** (this participant's communication key and any decrypted local shares); store only in trusted storage.
- `static DKGManager.fromJSON(snapshot): DKGManager` — rebuild a manager and continue the flow across a process restart.

Notes
- Participant IDs are 1..N positive integers.
- Shares and commitments must be provided for every dealer in the roster before finalizing.
- `commitmentRound` produces only — it does **not** auto-store your own commitment. Feed the returned `commitments` back through `addParticipantCommitments` for your own id, exactly as you do for every peer dealer.

## Flow 1: Trusted-dealer keygen

When a single dealer generates all shares and the group key.

```ts
import { DKGManager } from '../src/manager/dkg'

const dkg = new DKGManager()
const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn
const n = 5
const t = 3

const { groupPublicKey, shares, viewingPrivateKey } = dkg.runTrustedKeygen(secret, n, t)
// shares: [{ identifier, skShare, skShareDiv8 }]
// groupPublicKey: [xHex, yHex]
```

Validation
- `n > 0`, `t > 0`, `t <= n`.

## Flow 2: Coordinator-less multi-dealer

Every dealer contributes a polynomial. Each participant obtains an encrypted share from every dealer, decrypts locally, and finalizes their own share.

High level steps per dealer:

1. Announce and roster
```ts
const dealer = new DKGManager()
const announce = dealer.getAnnouncement() // { pubKey }
// Build a roster across all dealers
const roster: Record<number, Uint8Array> = { 1: pub1, 2: pub2, 3: pub3, 4: pub4, 5: pub5 }
dealer.assignRoster(roster) // assigns dealer.participantID implicitly based on its own pubKey
```

2. Commitment round (per dealer)
```ts
const { shares, commitments } = dealer.commitmentRound(secret_i, n, t)
// Broadcast `commitments` to everyone; keep `shares` to encrypt next.
// `commitmentRound` does not store your own commitment — add it like any peer's
// in the collection step below (your id is included in `allCommitments`).
```

3. Collect commitments (your own included)
```ts
for (const [dealerId, comms] of Object.entries(allCommitments)) {
  dealer.addParticipantCommitments(Number(dealerId), comms)
}
// dealer.progress().awaitingCommitments lists any roster ids still missing
```

4. Encrypt and distribute shares (per dealer)
```ts
const encryptedByRecipient = dealer.getEncryptedShares()
// Send encryptedByRecipient[participantId] to each participant
```

5. Collect encrypted shares (per participant)
```ts
for (const [dealerId, encBundle] of Object.entries(collectedEncrypted)) {
  dealer.addEncryptedShares(Number(dealerId), encBundle)
}
```

6. Finalize local share (per participant)
```ts
const { share, PKGroup, viewingPrivateKey } = dealer.finalize()
// share.id === dealer.participantID
```

Validation and ordering
- `assignRoster` must run before `commitmentRound`.
- Each `addParticipantCommitments` must be called for all dealers listed in roster (same ID set).
- `getEncryptedShares` requires a complete commitment set and local shares from `commitmentRound`.
- `addEncryptedShares` must be called for all dealers in roster.
- `finalize` throws if any dealers are missing.

## Migrating from a self-adding `commitmentRound`

`commitmentRound` used to store its own commitments internally, so callers fed
only their peers' commitments back in. It no longer does: every commitment now
arrives through the single `addParticipantCommitments` path, including your own.

A caller written against the older behaviour does not fail at the call site — it
simply never reaches `commitments-collected`, because it is waiting on itself.
Check `progress().awaitingCommitments`: if it contains your own
`participantID`, add your own commitments:

```ts
const { shares, commitments } = dealer.commitmentRound(secret_i, n, t)
dealer.addParticipantCommitments(dealer.participantID!, commitments) // <- now required
```

`getEncryptedShares` detects this case specifically and throws naming your own
id rather than reporting a generic state error.

## Pause and resume

A session can be persisted between any two steps and rebuilt later (e.g. across a
process restart). State is derived from the collected data, so a restored manager
resumes exactly where it left off.

```ts
// persist (snapshot is JSON-serializable; treat it as secret)
const snapshot = dealer.toJSON()
await store.put(sessionId, JSON.stringify(snapshot))

// ...later, in a fresh process
const restored = DKGManager.fromJSON(JSON.parse(await store.get(sessionId)))
restored.getState() // resumes at the same flow state
restored.getEncryptedShares() // continue the flow
```

## Error messages and causes

- `roster not assigned` — call `assignRoster` first.
- `our announcement pubKey not present in roster` — include the current manager's pubKey in roster.
- `roster size does not match desiredShares` — ensure `n` equals roster size.
- `missing commitments for one or more dealers` — collect all dealer commitments before encrypting or finalizing.
- `missing encrypted shares or keys from dealers: ...` — not all encrypted shares were collected.
- `threshold cannot exceed desiredShares` — fix `t` vs `n`.

## Tips

- Participant IDs are 1..N consecutively.
- The `viewingPrivateKey` is derived deterministically from the set of dealers (C0 commitments) and is identical across participants.
- The returned `PKGroup` is the sum of the first commitments across dealers.
