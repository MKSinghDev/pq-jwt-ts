/**
 * JWT verification functionality with ML-DSA
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { MlDsaAlgo, type Claims, type JwtHeader } from "./types";
import { base64UrlDecode, getCurrentTimestamp, hexToBytes } from "./utils";

/**
 * Verifies a JWT and returns the decoded payload
 *
 * @param jwt - The JWT string to verify
 * @param publicKeyHex - Hex-encoded public verifying key
 * @param expectedIssuer - Expected issuer that must match the JWT's iss claim
 * @returns Decoded payload string if verification succeeds
 *
 * @example
 * ```ts
 * import { verify } from "@awth/pq-jwt";
 *
 * const payload = await verify(jwt, publicKey, "https://myapp.com");
 * const claims = JSON.parse(payload);
 * ```
 */
export async function verify(
  jwt: string,
  publicKeyHex: string,
  expectedIssuer: string
): Promise<string> {
  const verifier = new VerifierBuilder()
    .setPublicKey(publicKeyHex)
    .setIssuer(expectedIssuer)
    .build();

  return verifier.verify(jwt);
}

/**
 * Verifier class for JWT verification with configurable validations
 */
export class Verifier {
  constructor(
    private publicKey: string,
    private expectedIssuer: string,
    private expectedAudience?: string,
    private expectedSubject?: string,
    private leeway: number = 0
  ) {}

  /**
   * Verifies a JWT and returns the decoded payload
   */
  verify(jwt: string): string {
    // Split JWT into parts
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid JWT format: expected 3 parts");
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode and parse header
    const headerJson = new TextDecoder().decode(base64UrlDecode(headerB64!));
    const header: JwtHeader = JSON.parse(headerJson);

    // Get algorithm
    const algo = header.alg as MlDsaAlgo;
    if (!Object.values(MlDsaAlgo).includes(algo)) {
      throw new Error(`Unsupported algorithm: ${algo}`);
    }

    // Verify signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const signatureBytes = base64UrlDecode(signatureB64!);
    this.verifySignature(algo, signingInput, signatureBytes);

    // Decode payload
    const payloadJson = new TextDecoder().decode(base64UrlDecode(payloadB64!));
    const claims: Claims = JSON.parse(payloadJson);

    // Validate claims
    this.validateClaims(claims);

    return payloadJson;
  }

  /**
   * Verifies the cryptographic signature
   */
  private verifySignature(algo: MlDsaAlgo, signingInput: string, signatureBytes: Uint8Array): void {
    const publicKeyBytes = hexToBytes(this.publicKey);
    const messageBytes = new TextEncoder().encode(signingInput);

    let isValid: boolean;

    try {
      switch (algo) {
        case MlDsaAlgo.Dsa44:
          isValid = ml_dsa44.verify(signatureBytes, messageBytes, publicKeyBytes);
          break;
        case MlDsaAlgo.Dsa65:
          isValid = ml_dsa65.verify(signatureBytes, messageBytes, publicKeyBytes);
          break;
        case MlDsaAlgo.Dsa87:
          isValid = ml_dsa87.verify(signatureBytes, messageBytes, publicKeyBytes);
          break;
        default:
          throw new Error(`Unsupported algorithm: ${algo}`);
      }

      if (!isValid) {
        throw new Error("Signature verification failed");
      }
    } catch (error) {
      throw new Error(`Signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Validates JWT claims according to configured rules
   */
  private validateClaims(claims: Claims): void {
    const now = getCurrentTimestamp();

    // REQUIRED: Validate expiration (exp must exist and be in the future)
    if (!claims.exp || claims.exp <= now - this.leeway) {
      throw new Error(`Token has expired (exp=${claims.exp}, now=${now})`);
    }

    // REQUIRED: Validate issuer exists
    if (!claims.iss || claims.iss.trim() === "") {
      throw new Error("Issuer (iss) claim is missing or empty");
    }

    // REQUIRED: Validate expected issuer
    if (claims.iss !== this.expectedIssuer) {
      throw new Error(`Invalid issuer: expected '${this.expectedIssuer}', got '${claims.iss}'`);
    }

    // OPTIONAL: Validate expected audience if configured
    if (this.expectedAudience) {
      if (!claims.aud) {
        throw new Error(`Audience (aud) claim is missing, expected '${this.expectedAudience}'`);
      }
      if (claims.aud !== this.expectedAudience) {
        throw new Error(`Invalid audience: expected '${this.expectedAudience}', got '${claims.aud}'`);
      }
    }

    // OPTIONAL: Validate expected subject if configured
    if (this.expectedSubject) {
      if (!claims.sub) {
        throw new Error(`Subject (sub) claim is missing, expected '${this.expectedSubject}'`);
      }
      if (claims.sub !== this.expectedSubject) {
        throw new Error(`Invalid subject: expected '${this.expectedSubject}', got '${claims.sub}'`);
      }
    }

    // OPTIONAL: Validate not before (nbf) if present
    if (claims.nbf && claims.nbf > now + this.leeway) {
      throw new Error(`Token not yet valid (nbf=${claims.nbf}, now=${now})`);
    }
  }

  /**
   * Returns the public key being used by this verifier
   */
  getPublicKey(): string {
    return this.publicKey;
  }
}

/**
 * Verifier builder for advanced JWT verification with configurable validations
 */
export class VerifierBuilder {
  private publicKey?: string;
  private expectedIssuer?: string;
  private expectedAudience?: string;
  private expectedSubject?: string;
  private leeway: number = 0;

  /**
   * Sets the public key (REQUIRED)
   */
  setPublicKey(publicKey: string): this {
    this.publicKey = publicKey;
    return this;
  }

  /**
   * Sets the expected issuer for validation (REQUIRED)
   */
  setIssuer(issuer: string): this {
    this.expectedIssuer = issuer;
    return this;
  }

  /**
   * Sets the expected audience for validation (optional)
   */
  setAudience(audience: string): this {
    this.expectedAudience = audience;
    return this;
  }

  /**
   * Sets the expected subject for validation (optional)
   */
  setSubject(subject: string): this {
    this.expectedSubject = subject;
    return this;
  }

  /**
   * Sets the time leeway for exp/nbf validation (optional)
   * Adds a time buffer (in seconds) to account for clock skew between systems.
   * Default is 0 seconds.
   */
  setLeeway(leeway: number): this {
    this.leeway = leeway;
    return this;
  }

  /**
   * Builds the Verifier instance
   */
  build(): Verifier {
    if (!this.publicKey) throw new Error("Public key is required");
    if (!this.expectedIssuer) throw new Error("Issuer is required");

    return new Verifier(
      this.publicKey,
      this.expectedIssuer,
      this.expectedAudience,
      this.expectedSubject,
      this.leeway
    );
  }
}
