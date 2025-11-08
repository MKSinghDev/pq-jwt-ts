/**
 * ML-DSA Algorithm variants
 *
 * Based on NIST FIPS 204 standard
 */
export enum MlDsaAlgo {
  /** ML-DSA-44: NIST Category 2 (~AES-128) - For IoT and constrained devices */
  Dsa44 = "ML-DSA-44",
  /** ML-DSA-65: NIST Category 3 (~AES-192) - Recommended for most applications */
  Dsa65 = "ML-DSA-65",
  /** ML-DSA-87: NIST Category 5 (~AES-256) - For high-security requirements */
  Dsa87 = "ML-DSA-87",
}

/**
 * JWT Claims structure
 *
 * Standard JWT claims as defined in RFC 7519
 */
export interface Claims {
  /** Issuer (REQUIRED) */
  iss: string;
  /** Expiration time (REQUIRED) - Unix timestamp in seconds */
  exp: number;
  /** Issued at (optional) - Unix timestamp in seconds */
  iat?: number;
  /** Subject (optional) */
  sub?: string;
  /** Audience (optional) */
  aud?: string;
  /** Not before (optional) - Unix timestamp in seconds */
  nbf?: number;
  /** JWT ID (REQUIRED) - Unique identifier for the JWT (UUID v7) */
  jti: string;
  /** Custom claims */
  [key: string]: unknown;
}

/**
 * JWT Header structure
 */
export interface JwtHeader {
  /** Algorithm - always ML-DSA variant */
  alg: string;
  /** Type - always "JWT" */
  typ: "JWT";
  /** Key ID - SHA-256 thumbprint of public key */
  kid: string;
}

/**
 * Result type for sign operations
 */
export interface SignResult {
  /** The signed JWT string */
  jwt: string;
  /** Hex-encoded public key */
  publicKey: string;
  /** JWT ID (UUID v7) */
  jti: string;
}

/**
 * Keypair result
 */
export interface Keypair {
  /** Hex-encoded private key */
  privateKey: string;
  /** Hex-encoded public key */
  publicKey: string;
}
