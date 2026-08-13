# FROSTSigningManager

Orchestrates the 2-round FROST signing flow on top of `BabyFROST` primitives, given a finalized group public key and per-participant shares.

This README documents the public API, a minimal E2E example, and helper methods for readiness and diagnostics. The code lives in `src/manager/signing.ts`.

## Public API (stable)

- `new FROSTSigningManager(groupPublicKey: Point, threshold: number)`
- `addSigner({ id: number, skShare: bigint }): void` — add a local signer/share owned by this manager instance. Throws on a duplicate id.
- `round1(): void` — generate fresh commitments for local signers and clear collected partials. To start a genuinely new round, call `resetRoundState()` first (see Tips).
- `exportRound1(): Commitment[]` — commitments for local signers to share with others.
- `addRemoteSigner(commitment: Commitment): void` — add a commitment from another participant (id is unique).
- `sign(message: bigint): { identifier: number, partial: bigint }[]` — produce signature shares for all local signers, bound to the combined commitment list.
- `receivePartials(partials: { identifier, partial }[]): void` — collect partials from others.
- `finalize(message: bigint)` → aggregated signature (tuple `[R8x, R8y, s]` from `BabyFROST`). Throws unless a partial is present for **every** participant in the commitment list, and re-verifies the aggregate before returning.

Helper methods
- `expectedParticipantIds(): number[]` — identifiers implied by the current commitment list.
- `getMissingPartials(): number[]` — identifiers without collected partials.
- `readyToFinalize(): boolean` — true when **every** participant in the commitment list has a partial (`getMissingPartials()` is empty). Note: the commitment list may exceed `threshold`; `finalize()` interpolates over the whole list, so all of them must sign.
- `resetRoundState(): void` — clears commitments and partials and allows a fresh `round1()`.

### Sessions (concurrent signings)

Per-round state lives in a `SigningSession`. The flat methods above operate on a lazily-created `'default'` session — fine for signing one message at a time. To sign several messages concurrently on one manager (one device holding the same share(s) in multiple signings), use explicit sessions:

- `startSession(id?: string): SigningSession` — create an isolated session (throws if `id` exists).
- `session(id?: string): SigningSession` — fetch an existing session.
- `hasSession(id?: string): boolean`, `endSession(id?: string): void`.

A `SigningSession` exposes the same round methods (`round1`, `exportRound1`, `addRemoteSigner`, `sign`, `receivePartials`, `finalize`, `expectedParticipantIds`, `getMissingPartials`, `readyToFinalize`, `reset`). Sessions never share round state, so messages exchanged for one session must be routed to the matching session id on every participant.

A session is single-commit: calling `round1()` twice throws (`already committed`) — call `reset()` to restart. `finalize(message)` also asserts `message` matches what `sign(message)` signed.

### Pause and resume

A signing manager and its sessions can be serialized between steps and rebuilt later (e.g. across a process restart). There are two snapshot kinds, because resuming a signing that is already past round 1 carries a hazard that resuming one before round 1 does not.

Both kinds contain `signers[].skShare` — long-term key material — so either belongs only in trusted storage.

#### `toJSON()` / `fromJSON()` — safe, restore as often as you like

The default path, and what `JSON.stringify(manager)` produces. It carries no live nonces, so restoring the same payload any number of times is sound.

Sessions that have already run `round1()` hold nonces, so they are **dropped** from this snapshot; their ids are listed in `omittedSessions`. What survives is the manager's durable identity (threshold, group public key, signer shares) plus any session that has not yet committed.

```ts
await store.put(id, JSON.stringify(manager))          // safe payload
const restored = FROSTSigningManager.fromJSON(JSON.parse(await store.get(id)))
```

#### `toMidRoundJSON()` / `fromMidRoundJSON()` — single use

Use this only to resume a signing already past round 1. It keeps each committed session's local nonces, which is what lets the restored manager produce partials that still match the commitments peers already hold.

> **A mid-round snapshot must be restored at most once.**
>
> Its nonces may sign at most one message. Restore the same payload twice and sign different messages, and the same `(hidingNonce, bindingNonce)` pair is used under different challenges. FROST's binding factor means two such partials are not immediately solvable, but three distinct messages give three independent equations in three unknowns (`d_i`, `e_i`, `s_i`) — enough to recover the signer's secret share. This is a key-compromise event **even if the snapshot never leaves trusted storage**, because it is a use-count problem, not a confidentiality one.
>
> Mark the stored payload consumed *before* signing from it, and never hand the same payload to more than one process or retry.

```ts
// pausing mid-round
await store.putOnce(id, JSON.stringify(manager.toMidRoundJSON()))

// resuming — consume first, then sign
const raw = await store.takeOnce(id)                  // must not return twice
const restored = FROSTSigningManager.fromMidRoundJSON(JSON.parse(raw))
const partials = restored.sign(message)
```

The two entry points refuse each other's payloads: `fromJSON()` throws on a `mid-round` snapshot, and `fromMidRoundJSON()` throws on a `safe` one, so the single-use path is always explicit at the call site.

## Minimal E2E usage (t-of-n)

```ts
import { FROSTSigningManager } from '../src/manager/signing'
import { eddsaBuild } from '../src' // provides verifyPoseidon
import { bigIntToBuffer } from '../src/bytes'

const t = 3
const groupPublicKey = /* Point<bigint> from DKG */

// choose any t participants that have finalized DKG shares
const signers: FROSTSigningManager[] = []
for (const { id, skShare } of subsetShares) {
  const sm = new FROSTSigningManager(groupPublicKey, t)
  sm.addSigner({ id, skShare })
  signers.push(sm)
}

// round 1: produce + exchange commitments
for (const sm of signers) {
  sm.round1()
  const local = sm.exportRound1()
  for (const c of local) {
    for (const peer of signers) if (!peer.hasId(c.identifier)) peer.addRemoteSigner(c)
  }
}

// round 2: sign and exchange partials
const msg = 42069n
const partialsFromAll: { identifier: number, partial: bigint }[][] = []
for (const sm of signers) partialsFromAll.push(sm.sign(msg))
for (const sm of signers) for (const batch of partialsFromAll) sm.receivePartials(batch)

// finalize and verify
const sig = signers[0].finalize(msg)
const ok = eddsaBuild.verifyPoseidon(bigIntToBuffer(msg), sig, groupPublicKey)
```

## Validation and errors

- `getCommitmentList` sorts commitments by identifier and enforces `list.length >= threshold`.
- `sign` and `finalize` throw when commitments are missing or inconsistent.
- `finalize` verifies local signature shares before aggregation and throws if any fail verification.
- Use `readyToFinalize` and `getMissingPartials` to monitor progress.

## Tips

- Keep one manager instance per participating device/process. Each instance can manage one or more local shares if needed.
- Do not model a threshold round with a single manager plus its own exported commitments; peers must exchange commitments and partials across distinct participants.
- Always call `round1()` before `exportRound1()` and `sign()`.
- To sign again (new message or restart), either start a new session or call `resetRoundState()`/`session.reset()` and then `round1()`, and re-exchange commitments. A session is single-commit: calling `round1()` twice throws, because it would regenerate your local nonces while peers still hold your old commitments and any partial would be invalid.
- Identifiers must be positive integers and must match identifiers assigned during DKG.
