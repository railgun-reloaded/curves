import type { Point } from '../babyjubjub.js'

/** Finalized signer share produced by DKG finalization. */
interface Share {
  id: number
  skShare: bigint
  skShareDiv8: bigint
}

/** Public nonce commitments broadcast during FROST round 1. */
interface Commitment {
  identifier: bigint;
  hidingNonceCommitment: Point<bigint>;
  bindingNonceCommitment: Point<bigint>;
}

/** Binding factor assigned to a participant for a specific signing set. */
interface BindingFactor {
  identifier: bigint;
  bindingFactor: bigint;
}

/** Secret nonce pair held locally by a signer during round 2. */
interface NoncePair {
  hidingNonce: bigint;
  bindingNonce: bigint;
}

/** Round-1 output combining private nonces and public commitments. */
interface Bindings {
  nonces: NoncePair,
  commitments: Commitment
}

/** Dealer-local input shape for share generation helpers. */
interface ParticipantInput {
  id: number             // 1..N
  seed: Uint8Array       // 32 bytes (private to dealer)
  password: Uint8Array   // 32 bytes (private to dealer)
}

/** AES-GCM encrypted secret share payload delivered to a recipient. */
interface EncryptedShare {
  nonce: Uint8Array
  ciphertext: Uint8Array
}

export type {
  Commitment,
  BindingFactor,
  NoncePair,
  Bindings,
  Share,
  ParticipantInput,
  EncryptedShare,
}
