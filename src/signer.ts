/**
 * JWT signing functionality with ML-DSA
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { v7 as uuidv7 } from "uuid";
import { MlDsaAlgo, type Claims, type JwtHeader, type SignResult } from "./types";
import { base64UrlEncode, bytesToHex, generateKid, getCurrentTimestamp, hexToBytes } from "./utils";
import { getPublicKey } from "./keygen";

/**
 * Validates JWT claims before signing
 */
function validateClaims(claims: Claims): void {
  // Validate exp > iat (if iat is present)
  if (claims.iat !== undefined && claims.exp <= claims.iat) {
    throw new Error(`Expiration (exp=${claims.exp}) must be after issued at (iat=${claims.iat})`);
  }

  // Validate nbf < exp (if nbf is present)
  if (claims.nbf !== undefined && claims.nbf >= claims.exp) {
    throw new Error(`Not before (nbf=${claims.nbf}) must be before expiration (exp=${claims.exp})`);
  }

  // Validate jti is not empty
  if (!claims.jti || claims.jti.trim() === "") {
    throw new Error("JWT ID (jti) cannot be empty");
  }
}

/**
 * Signs JWT claims and returns a JWT string with public key and jti
 *
 * @param algo - The ML-DSA algorithm variant
 * @param iss - Issuer (REQUIRED)
 * @param exp - Expiration time as Unix timestamp in seconds (REQUIRED)
 * @param privateKeyHex - Hex-encoded private key
 * @returns SignResult with jwt, publicKey, and jti
 *
 * @example
 * ```ts
 * import { sign, MlDsaAlgo, generateKeypair } from "@awth/pq-jwt";
 *
 * const { privateKey } = generateKeypair(MlDsaAlgo.Dsa65);
 * const now = Math.floor(Date.now() / 1000);
 *
 * const { jwt, publicKey, jti } = await sign(
 *   MlDsaAlgo.Dsa65,
 *   "https://myapp.com",
 *   now + 3600,
 *   privateKey
 * );
 * ```
 */
export async function sign(
  algo: MlDsaAlgo,
  iss: string,
  exp: number,
  privateKeyHex: string
): Promise<SignResult> {
  const now = getCurrentTimestamp();
  const jti = uuidv7();

  const claims: Claims = {
    iss,
    exp,
    iat: now,
    jti,
  };

  // Validate claims
  validateClaims(claims);

  // Get public key
  const publicKeyHex = getPublicKey(algo, privateKeyHex);

  // Generate kid from public key
  const kid = await generateKid(publicKeyHex);

  return signInternal(algo, claims, privateKeyHex, publicKeyHex, kid);
}

/**
 * Internal sign implementation
 */
function signInternal(
  algo: MlDsaAlgo,
  claims: Claims,
  privateKeyHex: string,
  publicKeyHex: string,
  kid: string
): SignResult {
  // Create header
  const header: JwtHeader = {
    alg: algo,
    typ: "JWT",
    kid,
  };

  // Encode header and payload
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(claims));
  const signingInput = `${headerB64}.${payloadB64}`;

  // Sign
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const messageBytes = new TextEncoder().encode(signingInput);
  let signatureBytes: Uint8Array;

  switch (algo) {
    case MlDsaAlgo.Dsa44:
      signatureBytes = ml_dsa44.sign(messageBytes, privateKeyBytes);
      break;
    case MlDsaAlgo.Dsa65:
      signatureBytes = ml_dsa65.sign(messageBytes, privateKeyBytes);
      break;
    case MlDsaAlgo.Dsa87:
      signatureBytes = ml_dsa87.sign(messageBytes, privateKeyBytes);
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algo}`);
  }

  const signatureB64 = base64UrlEncode(signatureBytes);
  const jwt = `${signingInput}.${signatureB64}`;

  return {
    jwt,
    publicKey: publicKeyHex,
    jti: claims.jti,
  };
}

/**
 * Signer builder for advanced JWT signing with custom claims
 */
export class SignerBuilder {
  private algo?: MlDsaAlgo;
  private privateKey?: string;
  private issuer?: string;
  private expiration?: number;
  private subject?: string;
  private audience?: string;
  private issuedAt?: number;
  private skipIat = false;
  private notBefore?: number;
  private jwtId: string = uuidv7();
  private customClaims: Record<string, unknown> = {};

  /**
   * Sets the algorithm (REQUIRED)
   */
  algorithm(algo: MlDsaAlgo): this {
    this.algo = algo;
    return this;
  }

  /**
   * Sets the private key (REQUIRED)
   */
  setPrivateKey(privateKey: string): this {
    this.privateKey = privateKey;
    return this;
  }

  /**
   * Sets the issuer (REQUIRED)
   */
  setIssuer(iss: string): this {
    this.issuer = iss;
    return this;
  }

  /**
   * Sets the expiration time (REQUIRED) - Unix timestamp in seconds
   */
  setExpiration(exp: number): this {
    this.expiration = exp;
    return this;
  }

  /**
   * Sets the subject (optional)
   */
  setSubject(sub: string): this {
    this.subject = sub;
    return this;
  }

  /**
   * Sets the audience (optional)
   */
  setAudience(aud: string): this {
    this.audience = aud;
    return this;
  }

  /**
   * Sets the issued at time (optional)
   * If not set, defaults to current time
   */
  setIssuedAt(iat: number): this {
    this.issuedAt = iat;
    this.skipIat = false;
    return this;
  }

  /**
   * Skips the issued at (iat) claim
   */
  skipIssuedAt(): this {
    this.skipIat = true;
    this.issuedAt = undefined;
    return this;
  }

  /**
   * Sets the not before time (optional) - Unix timestamp in seconds
   */
  setNotBefore(nbf: number): this {
    this.notBefore = nbf;
    return this;
  }

  /**
   * Sets the JWT ID (optional)
   * If not set, a UUID v7 is automatically generated
   */
  setJwtId(jti: string): this {
    this.jwtId = jti;
    return this;
  }

  /**
   * Adds custom claims
   */
  addCustomClaims(claims: Record<string, unknown>): this {
    // Filter out standard JWT claims
    const standardClaims = ["iss", "exp", "iat", "sub", "aud", "nbf", "jti"];
    for (const [key, value] of Object.entries(claims)) {
      if (!standardClaims.includes(key)) {
        this.customClaims[key] = value;
      }
    }
    return this;
  }

  /**
   * Builds and signs the JWT
   */
  async build(): Promise<SignResult> {
    if (!this.algo) throw new Error("Algorithm is required");
    if (!this.privateKey) throw new Error("Private key is required");
    if (!this.issuer) throw new Error("Issuer (iss) is required");
    if (this.expiration === undefined) throw new Error("Expiration (exp) is required");

    // Build claims
    const claims: Claims = {
      iss: this.issuer,
      exp: this.expiration,
      jti: this.jwtId,
      ...this.customClaims,
    };

    // Add optional claims
    if (this.subject) claims.sub = this.subject;
    if (this.audience) claims.aud = this.audience;
    if (this.notBefore !== undefined) claims.nbf = this.notBefore;

    // Handle iat
    if (!this.skipIat) {
      claims.iat = this.issuedAt ?? getCurrentTimestamp();
    }

    // Validate claims
    validateClaims(claims);

    // Get public key
    const publicKeyHex = getPublicKey(this.algo, this.privateKey);

    // Generate kid
    const kid = await generateKid(publicKeyHex);

    return signInternal(this.algo, claims, this.privateKey, publicKeyHex, kid);
  }
}
