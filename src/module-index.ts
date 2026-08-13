import { decode as msgpackDecode, encode as msgpackEncode } from '@msgpack/msgpack'
import { getPublicKey } from '@noble/ed25519'
import { bytesToBigInt, bytesToHex, hexToBytes } from '@railgun-reloaded/bytes'

import type { Point } from './babyjubjub.js'
import { bigIntToBuffer, leBigIntToBuffer, leBufferToBigInt } from './bytes.js'
import type { Signature } from './eddsa/babyposeidon.js'
import { EddsaPoseidon, eddsaBuild } from './eddsa/index.js'
import { BabyFROST, frost } from './frost/index.js'
import type {
  BindingFactor,
  Bindings,
  Commitment,
  EncryptedShare,
  NoncePair,
  ParticipantInput,
  Share,
} from './frost/types.js'
import { DKGManager, FROSTSigningManager } from './manager/index.js'
import { poseidonFn } from './poseidon/poseidon-lite-wrapper.js'

type DecodedShareableKey = {
  vpriv: string
  spub: string
  sid?: string
  sk?: string
  pid?: number
}

type DecodedMultisigKey = {
  vpriv: Uint8Array
  spub: Point<bigint>
  sid: string
  sk: string
  pid: number
}

/**
 * Narrows an unknown value to a plain record for safe property access.
 * @param value Value to test.
 * @returns `true` when the value is a non-null object.
 */
function isRecord (value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

/**
 * Strips an optional `0x` prefix and validates/pads a hex string.
 * @param value Candidate hex string.
 * @param field Field name used in error messages.
 * @returns The normalized even-length hex string without `0x`.
 */
function normalizeHex (value: string, field: string): string {
  const hex = value.startsWith('0x') ? value.slice(2) : value
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error(`Invalid ${field}: expected hex string`)
  if (!hex.length) throw new Error(`Invalid ${field}: empty hex string`)
  return hex.length % 2 === 0 ? hex : `0${hex}`
}

/**
 * Asserts that a private key is exactly 32 bytes.
 * @param key Key bytes to check.
 * @param field Field name used in error messages.
 */
function assertPrivateKeyLength (key: Uint8Array, field: string) {
  if (key.length !== 32) throw new Error(`Invalid ${field} length`)
}

/**
 * Hashes Baby Jubjub field inputs with the repo's Poseidon wrapper.
 * Inputs are interpreted as little-endian field elements encoded as bytes.
 * @param inputs Field elements encoded as byte arrays.
 * @returns The Poseidon digest encoded as bytes.
 */
function poseidon (inputs: Uint8Array[]) {
  const result = poseidonFn(inputs.map(a => a.toReversed())) as bigint
  return bigIntToBuffer(result).toReversed()
}

/**
 * Hashes BigInt-compatible string inputs with Poseidon.
 * Each input must be parsable by `BigInt`, for example a decimal string or a
 * `0x`-prefixed hex string.
 * @param inputs BigInt-compatible decimal or hex strings.
 * @param outputHex When `true`, returns a hex string without `0x` prefix.
 * @returns The Poseidon digest as a bigint or hex string.
 */
function poseidonHex (inputs: string[], outputHex = false) {
  const parsed = inputs.map((input, index) => {
    try {
      return BigInt(input)
    } catch {
      throw new Error(`Invalid Poseidon input at index ${index}`)
    }
  })
  const result = poseidon(parsed.map(bigIntToBuffer))
  const output = bytesToBigInt(result)
  return outputHex ? output.toString(16) : output
}

/**
 * Derives a Baby Jubjub public spending key from a 32-byte private key.
 * @param privateKey Private spending key bytes.
 * @returns The affine Baby Jubjub public key.
 */
function getPublicSpendingKey (privateKey: Uint8Array): [bigint, bigint] {
  assertPrivateKeyLength(privateKey, 'private key')
  return eddsaBuild.prv2pub(privateKey)
}

/**
 * Derives the 32-byte public viewing key from a 32-byte private viewing key.
 * @param privateViewingKey Private viewing key bytes.
 * @returns The derived public viewing key bytes.
 */
async function getPublicViewingKey (privateViewingKey: Uint8Array): Promise<Uint8Array> {
  assertPrivateKeyLength(privateViewingKey, 'private viewing key')
  return getPublicKey(privateViewingKey)
}

/**
 * Signs a Poseidon message hash with a 32-byte private key.
 * @param privateKey Private signing key bytes.
 * @param message Poseidon message hash to sign.
 * @returns The EDDSA-Poseidon signature.
 */
function signEDDSA (privateKey: Uint8Array, message: bigint): Signature {
  assertPrivateKeyLength(privateKey, 'private key')
  const u8 = bigIntToBuffer(message)
  return eddsaBuild.signPoseidon(privateKey, u8)
}

/**
 * Verifies a Poseidon signature against the provided Baby Jubjub public key.
 * @param message Poseidon message hash that was signed.
 * @param signature Signature to verify.
 * @param pubkey Signer public key.
 * @returns `true` when the signature is valid.
 */
function verifyEDDSA (message: bigint, signature: Signature, pubkey: [bigint, bigint]) {
  const u8 = bigIntToBuffer(message)
  return eddsaBuild.verifyPoseidon(u8, signature, pubkey)
}

/**
 * Encodes a viewing private key and spending public key into a shareable hex payload.
 * The viewing key is left-padded to preserve its full 32-byte representation.
 * @param spendingPublicKey Public spending key to serialize.
 * @param viewingPrivateKey Private viewing key bytes.
 * @returns Hex-encoded msgpack payload.
 */
function getShareableViewingKey (spendingPublicKey: Point<bigint>, viewingPrivateKey: Uint8Array) {
  assertPrivateKeyLength(viewingPrivateKey, 'viewing private key')
  const spendingPublicKeyString = eddsaBuild.fromBytes(eddsaBuild.packPoint(spendingPublicKey)).toString(16).padStart(64, '0')
  const data = {
    vpriv: eddsaBuild.fromBytes(viewingPrivateKey.toReversed()).toString(16).padStart(64, '0'),
    spub: spendingPublicKeyString,
  }
  return bytesToHex(msgpackEncode(data))
}

/**
 * Decodes a shareable viewing or multisig payload from its hex-encoded msgpack representation.
 * This validates the basic payload shape because the input is caller-controlled.
 * @param shareableKey Hex-encoded msgpack payload.
 * @returns The decoded shareable key fields.
 */
function decodeShareableKey (shareableKey: string): DecodedShareableKey {
  const normalized = normalizeHex(shareableKey, 'shareable key')
  const buf = hexToBytes(normalized)
  const rawDecoded = msgpackDecode(buf)
  if (!isRecord(rawDecoded)) throw new Error('Invalid shareable key payload')
  const vpriv = rawDecoded['vpriv']
  const spub = rawDecoded['spub']
  const sid = rawDecoded['sid']
  const sk = rawDecoded['sk']
  const pid = rawDecoded['pid']
  if (typeof vpriv !== 'string' || typeof spub !== 'string') {
    throw new Error('Invalid shareable key payload')
  }
  if (typeof sid !== 'undefined' && typeof sid !== 'string') throw new Error('Invalid shareable key session id')
  if (typeof sk !== 'undefined' && typeof sk !== 'string') throw new Error('Invalid shareable key symmetric key')
  if (typeof pid !== 'undefined' && typeof pid !== 'number') {
    throw new Error('Invalid shareable key participant id')
  }
  if (typeof pid === 'number' && (!Number.isInteger(pid) || pid <= 0)) {
    throw new Error('Invalid shareable key participant id')
  }
  return {
    vpriv,
    spub,
    ...(typeof sid === 'string' ? { sid } : {}),
    ...(typeof sk === 'string' ? { sk } : {}),
    ...(typeof pid === 'number' ? { pid } : {}),
  }
}

/**
 * Decodes a multisig shareable key into typed binary/public-key components.
 * @param multisigShareableKey Hex-encoded msgpack payload.
 * @returns The decoded multisig payload with typed binary fields.
 */
function decodeMultisigKey (multisigShareableKey: string): DecodedMultisigKey {
  const decoded = decodeShareableKey(multisigShareableKey)
  const participantId = decoded.pid
  if (typeof decoded.sid !== 'string' || typeof decoded.sk !== 'string' || typeof participantId !== 'number' || !Number.isInteger(participantId)) {
    throw new Error('Invalid multisig shareable key payload')
  }

  const spub = eddsaBuild.toBytes(BigInt(`0x${normalizeHex(decoded.spub, 'spending public key')}`))
  const unpacked = eddsaBuild.unpackPoint(spub)
  if (!unpacked) throw new Error('Invalid multisig shareable key public key')

  const reformatted: DecodedMultisigKey = {
    vpriv: hexToBytes(normalizeHex(decoded.vpriv, 'viewing private key')),
    spub: unpacked,
    sid: decoded.sid,
    sk: '0x' + decoded.sk,
    pid: participantId,
  }
  return reformatted
}

/**
 * Encodes multisig session metadata together with the viewing key payload.
 * @param spendingPublicKey Public spending key to serialize.
 * @param viewingPrivateKey Private viewing key bytes.
 * @param sessionID Application session identifier.
 * @param symmetricKey Session symmetric key as hex.
 * @param participantId Positive integer participant identifier.
 * @returns Hex-encoded msgpack payload.
 */
function getShareableMultisigKey (spendingPublicKey: Point<bigint>, viewingPrivateKey: Uint8Array, sessionID: string, symmetricKey: string, participantId: number) {
  assertPrivateKeyLength(viewingPrivateKey, 'viewing private key')
  const spendingPublicKeyString = eddsaBuild.fromBytes(eddsaBuild.packPoint(spendingPublicKey)).toString(16).padStart(64, '0')
  const formattedSymmetricKey = symmetricKey.startsWith('0x') ? symmetricKey.slice(2) : symmetricKey
  if (!sessionID.length) throw new Error('Invalid sessionID')
  if (!Number.isInteger(participantId) || participantId <= 0) throw new Error('Invalid participantId')
  const data = {
    vpriv: eddsaBuild.fromBytes(viewingPrivateKey.toReversed()).toString(16).padStart(64, '0'),
    spub: spendingPublicKeyString,
    sid: sessionID,
    sk: formattedSymmetricKey,
    pid: participantId
  }
  return bytesToHex(msgpackEncode(data))
}

export type {
  BindingFactor,
  Bindings,
  Commitment,
  DecodedMultisigKey,
  DecodedShareableKey,
  EncryptedShare,
  NoncePair,
  ParticipantInput,
  Point,
  Share,
}

export {
  bytesToBigInt,
  bigIntToBuffer,
  leBigIntToBuffer,
  leBufferToBigInt,
  frost,
  BabyFROST,
  FROSTSigningManager,
  DKGManager,
  eddsaBuild,
  EddsaPoseidon,
  getPublicSpendingKey,
  getPublicViewingKey,
  getShareableViewingKey,
  getShareableMultisigKey,
  decodeShareableKey,
  decodeMultisigKey,
  signEDDSA,
  verifyEDDSA,
  poseidon,
  poseidonHex,
}
