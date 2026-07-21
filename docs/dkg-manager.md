# DKGManager

A small orchestration helper around the FROST DKG primitives that supports two flows:

- Trusted-dealer keygen: one dealer produces all shares and the group public key.
- Coordinator-less multi-dealer: many dealers each contribute a polynomial; participants encrypt/decrypt shares and finalize their own share.

This README covers the public API, step-by-step usage, and common errors. The code lives in `src/manager/dkg.ts`.

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

Notes
- Participant IDs are 1..N positive integers.
- Shares and commitments must be provided for every dealer in the roster before finalizing.

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
// Broadcast `commitments` to everyone; keep `shares` to encrypt next
```

3. Collect commitments
```ts
for (const [dealerId, comms] of Object.entries(allCommitments)) {
  dealer.addParticipantCommitments(Number(dealerId), comms)
}
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
