# @railgun-reloaded/curves

`@railgun-reloaded/curves` is a dependency-light TypeScript package for Baby Jubjub, Poseidon, EDDSA-Poseidon, FROST signing, and distributed key generation helpers used by RAILGUN-style applications.

## What It Ships

- EDDSA-Poseidon signing and verification helpers
- Baby FROST signing primitives
- Trusted-dealer and coordinator-less DKG primitives
- High-level `DKGManager` and `FROSTSigningManager` orchestration helpers
- Byte and bigint conversion helpers used throughout the package
- Shareable viewing key and multisig payload helpers

## Install

```bash
npm install @railgun-reloaded/curves
```

## Package Exports

Top-level package:

```ts
import {
	BabyFROST,
	DKGManager,
	EddsaPoseidon,
	FROSTSigningManager,
	decodeMultisigKey,
	decodeShareableKey,
	eddsaBuild,
	getPublicSpendingKey,
	getPublicViewingKey,
	getShareableMultisigKey,
	getShareableViewingKey,
	poseidon,
	poseidonHex,
	signEDDSA,
	verifyEDDSA,
} from '@railgun-reloaded/curves'
```

Subpath exports:

```ts
import BabyFROST from '@railgun-reloaded/curves/babyfrost'
import { TrustedDKG } from '@railgun-reloaded/curves/trusted-dkg'
import { DKGManager, FROSTSigningManager } from '@railgun-reloaded/curves/manager'
```

## Recommended Entry Points

- Use `DKGManager` when application code needs a guided coordinator-less or trusted-dealer DKG flow.
- Use `FROSTSigningManager` when application code needs a two-round signing orchestrator.
- Use `BabyFROST` and `TrustedDKG` directly only when you need lower-level control.
- Use the root helper functions for serialization and small EDDSA/Poseidon utilities.

## Quick Start

### Keygen: Trusted-Dealer

Use this flow when one trusted dealer generates the secret-sharing polynomial, derives every participant share, and returns the shared group public key.

```ts
import { DKGManager } from '@railgun-reloaded/curves'

const dkg = new DKGManager('participant-1')
const secret = 0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn

const { shares, groupPublicKey, viewingPrivateKey } = dkg.runTrustedKeygen(secret, 5, 3)
```

What this returns:

- `shares`: one finalized share per participant, with both `skShare` and `skShareDiv8`
- `groupPublicKey`: the shared Baby Jubjub group public key
- `viewingPrivateKey`: the deterministic viewing key derived for the group

Use this when a single trusted party is allowed to know the original secret during setup.

### Keygen: Coordinator-Less `TrustedDKG`

Use this flow when no single dealer should own the whole secret. Each dealer contributes its own polynomial, publishes commitments, and each participant finalizes its share by summing one verified share from every dealer.

This example is based directly on the coordinator-less end-to-end flow exercised in `test/trusted-dkg-e2e.test.ts`.

```ts
import { TrustedDKG } from '@railgun-reloaded/curves/trusted-dkg'

const dkg = new TrustedDKG()
const threshold = 3
const participantIds = [1, 2, 3, 4, 5]

// Each dealer creates its own polynomial coefficients.
const dealers = [
	{ id: 1, coeffs: dkg.trustedDealerKeygen(0x11n, 5, threshold).coefficients },
	{ id: 2, coeffs: dkg.trustedDealerKeygen(0x22n, 5, threshold).coefficients },
	{ id: 3, coeffs: dkg.trustedDealerKeygen(0x33n, 5, threshold).coefficients },
	{ id: 4, coeffs: dkg.trustedDealerKeygen(0x44n, 5, threshold).coefficients },
	{ id: 5, coeffs: dkg.trustedDealerKeygen(0x55n, 5, threshold).coefficients },
]

// Each dealer publishes Feldman commitments and computes one private share for
// every participant id.
const commitmentsByDealer: Record<number, [bigint, bigint][]> = {}
const sharesByDealer: Record<number, Record<number, bigint>> = {}

for (const dealer of dealers) {
	commitmentsByDealer[dealer.id] = dkg.vssCommit(dealer.coeffs)
	sharesByDealer[dealer.id] = dkg.computeSharesForIds(dealer.coeffs, participantIds)
}

// Each participant verifies the share received from each dealer, then finalizes
// its own aggregate share by summing the verified dealer shares.
const finalizedShares = participantIds.map((participantId) => {
	const sharesForParticipant = dealers.map((dealer) => ({
		dealerId: dealer.id,
		s_ki: sharesByDealer[dealer.id]![participantId]!,
	}))

	for (const dealer of dealers) {
		const ok = dkg.vssVerify(
			{ i: BigInt(participantId), sk_i: sharesByDealer[dealer.id]![participantId]! },
			commitmentsByDealer[dealer.id]!,
			threshold,
		)
		if (!ok) throw new Error(`invalid share from dealer ${dealer.id} for participant ${participantId}`)
	}
	return dkg.finalizeParticipant(
		participantId,
		sharesForParticipant,
		dealers.map((dealer) => commitmentsByDealer[dealer.id]!),
	) // { share, PKGroup, viewingPrivateKey } for this participant
})
```

What peers exchange during coordinator-less keygen:

- Each dealer broadcasts its commitment vector from `vssCommit(...)`
- Each dealer privately sends one scalar share `s_ki` to each participant id
- Each participant verifies every received share against that dealer's commitments
- Each participant finalizes its own share locally with `finalizeParticipant(...)`

Coordinator-less invariants:

- Every participant must use the same full dealer commitment set
- Every participant must verify one share from every dealer before finalization
- Any threshold subset of finalized aggregate shares can reconstruct the aggregate secret constant

### Signing: FROST Orchestration

After key generation, the signing flow is the same for both approaches above.

- Trusted-dealer keygen returns `shares` plus `groupPublicKey` directly.
- Coordinator-less `TrustedDKG` keygen returns one finalized `{ share, PKGroup, viewingPrivateKey }` per participant.

In both cases, signing starts from the same two inputs:

- one finalized signing share per participating signer
- one shared group public key for the whole signer set

That means the FROST round structure below does not change based on how the shares were generated. Once participants hold finalized shares and agree on the group public key, commitment exchange and partial-signature exchange work the same way.

The manager models one participant at a time. In a real `t-of-n` round, peers must exchange two kinds of data:

1. Round 1 commitments
	 Each peer generates nonce commitments locally with `round1()` and sends the exported commitments to the other selected signers.
2. Round 2 partial signatures
	 After every signer has the same commitment set, each peer signs the same message hash and sends its partial signature to the other selected signers.

The critical invariant is that all participating peers must sign against the same ordered commitment list for the same message hash. If one peer signs against a different signer set or stale round state, aggregation is no longer valid.

```ts
import { DKGManager, FROSTSigningManager, bigIntToBuffer, eddsaBuild } from '@railgun-reloaded/curves'

const threshold = 3
const dkg = new DKGManager('participant-1')
const trusted = dkg.runTrustedKeygen(0x43583e33fb2f47faa243b5cdf8cb251f7e9482f0386064901ae0c5e2134b78fn, 5, threshold)

// If you used coordinator-less TrustedDKG instead, you would derive the same
// signing inputs from `finalizedShares.map(({ share }) => share)` and the shared
// `PKGroup` returned during finalization.
const groupPublicKey = trusted.groupPublicKey.map((coordinate) => BigInt(coordinate)) as [bigint, bigint]
const signingSubset = trusted.shares.slice(0, threshold)

// Each participating peer/process owns one finalized share and one manager.
const signers = signingSubset.map((share) => {
	const manager = new FROSTSigningManager(groupPublicKey, threshold)
	manager.addSigner({
		id: share.identifier,
		skShare: BigInt(share.skShare),
	})
	return manager
})

// Round 1: every peer creates local nonces and public commitments.
// These commitments must be broadcast to the other selected peers.
for (const signer of signers) {
	signer.round1()
	const localCommitments = signer.exportRound1()

	// In a real network flow, send `localCommitments` to the other peers here.
	// Every peer must collect the same commitment set before round 2.
	for (const commitment of localCommitments) {
		for (const peer of signers) {
			if (!peer.hasId(commitment.identifier)) peer.addRemoteSigner(commitment)
		}
	}
}

// Round 2: once every peer has the full commitment list, each peer signs the
// same message hash and sends its partial signature to the other peers.
const partialBatches = signers.map((signer) => signer.sign(42069n))

// In a real network flow, each element of `partialBatches` would be sent from
// one peer to the others. Every peer must collect enough partials for the same
// commitment set before finalization.
for (const signer of signers) {
	for (const batch of partialBatches) signer.receivePartials(batch)
}

// Any peer with the full partial set can aggregate the final signature.
const signature = signers[0].finalize(42069n)
const valid = eddsaBuild.verifyPoseidon(bigIntToBuffer(42069n), signature, groupPublicKey)
```

What peers exchange during signing:

- Before round 1: the selected signer set and the message hash to be signed
- During round 1: each participant's `Commitment[]` output from `exportRound1()`
- During round 2: each participant's `{ identifier, partial }[]` output from `sign()`
- After aggregation: the final aggregate signature can be verified by any peer with the group public key

Operational notes:

- Recreate or reset manager state between signing rounds. Do not reuse stale commitments or partials.
- Every participating peer must agree on the same signer subset for a given round.
- Do not mix commitments or partials from different messages.
- `finalize()` currently expects all identifiers implied by the active commitment list, not just any arbitrary threshold subset received late.

## Security Notes

- Treat all encoded payloads and any caller-supplied strings as untrusted input.
- Participant identifiers are expected to be positive integers and, in DKG flows, consecutive across the roster.
- Manager instances are stateful single-flow helpers. Reset or recreate them between rounds rather than reusing stale state.
- The shareable key helpers are serialization helpers, not secure storage primitives.
- `FROSTSigningManager` models one participating device/process at a time; real threshold signing requires one manager per participating share-holder.
- `FROSTSigningManager.addSigner` expects the finalized signing scalar as `skShare`.

## Documentation

- DKG manager flow: [docs/dkg-manager.md](docs/dkg-manager.md)
- Signing manager flow: [docs/signing-manager.md](docs/signing-manager.md)

## Development

```bash
npm run build
npm test
npm run coverage
npm run lint
```

## License

MIT
