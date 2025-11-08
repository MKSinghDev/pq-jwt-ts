/**
 * Utility functions for encoding/decoding and cryptographic operations
 */

/**
 * Converts bytes to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Converts hex string to bytes
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex string: odd length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Base64URL encode (no padding)
 */
export function base64UrlEncode(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Base64URL decode
 */
export function base64UrlDecode(input: string): Uint8Array {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  return new Uint8Array(Array.from(binary, (c) => c.charCodeAt(0)));
}

/**
 * Generates a Key ID (kid) from a public key using SHA-256
 * Takes first 16 bytes (32 hex chars) for readability
 */
export async function generateKid(publicKeyHex: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(publicKeyHex);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = new Uint8Array(hashBuffer);
  // Take first 16 bytes (32 hex chars)
  return bytesToHex(hashArray.slice(0, 16));
}

/**
 * Gets current Unix timestamp in seconds
 */
export function getCurrentTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}
