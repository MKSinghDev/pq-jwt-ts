/**
 * @awth/pq-jwt - Post-Quantum JWT implementation using ML-DSA
 *
 * A quantum-resistant JWT implementation using ML-DSA (Module-Lattice Digital Signature Algorithm)
 * signatures for future-proof authentication tokens.
 *
 * @example
 * ```ts
 * import { generateKeypair, sign, verify, MlDsaAlgo } from "@awth/pq-jwt";
 *
 * // Generate keypair
 * const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
 *
 * // Sign JWT
 * const now = Math.floor(Date.now() / 1000);
 * const { jwt, publicKey: pubKey, jti } = await sign(
 *   MlDsaAlgo.Dsa65,
 *   "https://myapp.com",
 *   now + 3600,
 *   privateKey
 * );
 *
 * // Verify JWT
 * const payload = await verify(jwt, publicKey, "https://myapp.com");
 * ```
 *
 * @module
 */

// Export types
export { MlDsaAlgo, type Claims, type JwtHeader, type SignResult, type Keypair } from "./types.ts";

// Export key generation
export { generateKeypair, getPublicKey } from "./keygen.ts";

// Export signing
export { sign, SignerBuilder } from "./signer.ts";

// Export verification
export { verify, Verifier, VerifierBuilder } from "./verifier.ts";

// Export utilities (for advanced use cases)
export { bytesToHex, hexToBytes, base64UrlEncode, base64UrlDecode, getCurrentTimestamp } from "./utils.ts";
