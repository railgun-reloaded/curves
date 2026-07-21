# FROSTSigningManager

Orchestrates the 2-round FROST signing flow on top of `BabyFROST` primitives, given a finalized group public key and per-participant shares.

This README documents the public API, a minimal E2E example, and helper methods for readiness and diagnostics. The code lives in `src/manager/signing.ts`.

## Public API (stable)

- `new FROSTSigningManager(groupPublicKey: Point, threshold: number)`
- `addSigner({ id: number, skShare: bigint }): void` — add a local signer/share owned by this manager instance.
- `round1(): void` — generate commitments for local signers and reset round state.
- `exportRound1(): Commitment[]` — commitments for local signers to share with others.
- `addRemoteSigner(commitment: Commitment): void` — add a commitment from another participant (id is unique).
- `sign(msgHash: bigint): { identifier: number, partial: bigint }[]` — produce signature shares for all local signers, bound to the combined commitment list.
- `receivePartials(partials: { identifier, partial }[]): void` — collect partials from others.
- `finalize(msgHash: bigint)` → aggregated signature (tuple `[R8x, R8y, s]` from `BabyFROST`).

Helper methods
- `expectedParticipantIds(): number[]` — identifiers implied by the current commitment list.
- `getMissingPartials(): number[]` — identifiers without collected partials.
- `readyToFinalize(): boolean` — true when at least `threshold` partials are available among expected ids.
- `resetRoundState(): void` — clears commitments and partials.

## Minimal E2E usage (t-of-n)

```ts
import { FROSTSigningManager } from '../src/manager/signing'
import { eddsaBuild } from '../src' // provides verifyPoseidon
import { bigIntToBuffer } from '@zk-kit/utils'

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
- Identifiers must be positive integers and must match identifiers assigned during DKG.
