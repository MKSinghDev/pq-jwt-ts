/**
 * Key generation for ML-DSA algorithms
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { MlDsaAlgo, type Keypair } from "./types.js";
import { bytesToHex } from "./utils.js";

/**
 * Generates a keypair for the specified ML-DSA algorithm
 *
 * @param algo - The ML-DSA algorithm variant
 * @returns Keypair with hex-encoded private and public keys
 *
 * @example
 * ```ts
 * import { generateKeypair, MlDsaAlgo } from "@awth/pq-jwt";
 *
 * const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
 * ```
 */
export function generateKeypair(algo: MlDsaAlgo): Keypair {
  let keypair: { secretKey: Uint8Array; publicKey: Uint8Array };

  switch (algo) {
    case MlDsaAlgo.Dsa44:
      keypair = ml_dsa44.keygen();
      break;
    case MlDsaAlgo.Dsa65:
      keypair = ml_dsa65.keygen();
      break;
    case MlDsaAlgo.Dsa87:
      keypair = ml_dsa87.keygen();
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algo}`);
  }

  return {
    privateKey: bytesToHex(keypair.secretKey),
    publicKey: bytesToHex(keypair.publicKey),
  };
}

/**
 * Derives the public key from a private key
 *
 * @param algo - The ML-DSA algorithm variant
 * @param privateKeyHex - Hex-encoded private key
 * @returns Hex-encoded public key
 *
 * @example
 * ```ts
 * import { getPublicKey, MlDsaAlgo } from "@awth/pq-jwt";
 *
 * const publicKey = getPublicKey(MlDsaAlgo.Dsa65, privateKey);
 * ```
 */
export function getPublicKey(algo: MlDsaAlgo, privateKeyHex: string): string {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  let publicKeyBytes: Uint8Array;

  switch (algo) {
    case MlDsaAlgo.Dsa44:
      publicKeyBytes = ml_dsa44.getPublicKey(privateKeyBytes);
      break;
    case MlDsaAlgo.Dsa65:
      publicKeyBytes = ml_dsa65.getPublicKey(privateKeyBytes);
      break;
    case MlDsaAlgo.Dsa87:
      publicKeyBytes = ml_dsa87.getPublicKey(privateKeyBytes);
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algo}`);
  }

  return bytesToHex(publicKeyBytes);
}

// Re-import for local use
import { hexToBytes } from "./utils.js";
