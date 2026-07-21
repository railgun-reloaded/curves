import { bytesToBigInt } from '@railgun-reloaded/bytes'
import * as poseidonLib from 'poseidon-lite'

import { bigIntToBuffer } from '../bytes.js'

type PoseidonInput = bigint | number | string | Uint8Array

/**
 * Runs the fixed-arity Poseidon permutation matching the input count.
 * Inputs may be bigint, number, string, or Uint8Array and are coerced to field
 * elements before hashing.
 * @param inputs Between 1 and 16 Poseidon inputs.
 * @param returnBigInt When `true`, returns bigint output; otherwise byte output.
 * @param nOuts Number of field outputs to return.
 * @returns The Poseidon digest as bigint(s) or byte array(s).
 */
function poseidonFn (inputs: (PoseidonInput)[], returnBigInt = true, nOuts?: number) {
  const inputLen = inputs.length
  if (nOuts === undefined) {
    nOuts = 1 // Default to 1 output if not specified
  }

  if (inputLen < 1 || inputLen > 16) {
    throw new Error('Poseidon function index must be between 1 and 16')
  }

  // check if the inputs are uint8arrays, if they are convert to bigint
  for (let i = 0; i < inputs.length; i++) {
    const input: any = inputs[i]
    if (input === undefined || input === null) {
      throw new Error(`Input at index ${i} is undefined or null`)
    }
    if (typeof input === 'string') {
      inputs[i] = BigInt(input)
    } else if (typeof input === 'number') {
      inputs[i] = BigInt(input)
    } else if (input instanceof Uint8Array) {
      inputs[i] = bytesToBigInt(input) // Ensure the input is a valid Uint8Array
    } else if (typeof input !== 'bigint') {
      throw new Error(`Invalid input type: ${typeof input}`)
    }
  }
  // @ts-expect-error dynamic index into the poseidon-lite namespace has no index signature
  const libFn = poseidonLib[`poseidon${inputLen}`]
  const output = libFn(inputs as PoseidonInput[], nOuts)
  // convert this back into uint8array if nOuts is 1
  if (returnBigInt) {
    if (nOuts === 1) {
      // If nOuts is 1, return a single bigint
      if (typeof output !== 'bigint') {
        throw new Error(`Expected output to be a bigint, got ${typeof output}`)
      }
      return output
    } else {
      // If nOuts > 1, return an array of bigints
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        if (typeof out !== 'bigint') {
          throw new Error(`Expected output to be a bigint, got ${typeof out}`)
        }
        return out
      })
    }
  } else {
    if (nOuts === 1) {
      return bigIntToBuffer(output as bigint)
    } else {
      // If nOuts > 1, return an array of uint8arrays
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        return bigIntToBuffer(out as bigint)
      })
    }
  }
}

export { poseidonFn }
