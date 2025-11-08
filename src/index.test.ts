/**
 * Tests for pq-jwt library
 */

import { test, expect, describe } from "bun:test";
import { generateKeypair, sign, verify, MlDsaAlgo, SignerBuilder, VerifierBuilder } from "./index.ts";

describe("Key Generation", () => {
  test("should generate keypair for ML-DSA-44", () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa44);
    expect(privateKey).toBeTruthy();
    expect(publicKey).toBeTruthy();
    expect(typeof privateKey).toBe("string");
    expect(typeof publicKey).toBe("string");
  });

  test("should generate keypair for ML-DSA-65", () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    expect(privateKey).toBeTruthy();
    expect(publicKey).toBeTruthy();
  });

  test("should generate keypair for ML-DSA-87", () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa87);
    expect(privateKey).toBeTruthy();
    expect(publicKey).toBeTruthy();
  });

  test("should generate different keypairs on each call", () => {
    const kp1 = generateKeypair(MlDsaAlgo.Dsa65);
    const kp2 = generateKeypair(MlDsaAlgo.Dsa65);
    expect(kp1.privateKey).not.toBe(kp2.privateKey);
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  });
});

describe("Basic Sign and Verify", () => {
  test("should sign and verify JWT with ML-DSA-65", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt, publicKey: returnedPubKey, jti } = await sign(
      MlDsaAlgo.Dsa65,
      "https://test.com",
      now + 3600,
      privateKey
    );

    expect(jwt).toBeTruthy();
    expect(returnedPubKey).toBe(publicKey);
    expect(jti).toBeTruthy();
    expect(jwt.split(".")).toHaveLength(3);

    const payload = await verify(jwt, publicKey, "https://test.com");
    const claims = JSON.parse(payload);
    expect(claims.iss).toBe("https://test.com");
    expect(claims.jti).toBe(jti);
  });

  test("should fail verification with wrong public key", async () => {
    const { privateKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const { publicKey: wrongPublicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt } = await sign(
      MlDsaAlgo.Dsa65,
      "https://test.com",
      now + 3600,
      privateKey
    );

    await expect(verify(jwt, wrongPublicKey, "https://test.com")).rejects.toThrow();
  });

  test("should fail verification with wrong issuer", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt } = await sign(
      MlDsaAlgo.Dsa65,
      "https://test.com",
      now + 3600,
      privateKey
    );

    await expect(verify(jwt, publicKey, "https://wrong.com")).rejects.toThrow("Invalid issuer");
  });

  test("should fail verification with expired token", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    // Create token that's already expired (using builder to set iat in the past)
    const oldTime = now - 7200; // 2 hours ago
    const { jwt } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(oldTime + 3600) // Expired 1 hour ago
      .setIssuedAt(oldTime) // Set iat to 2 hours ago
      .build();

    await expect(verify(jwt, publicKey, "https://test.com")).rejects.toThrow("Token has expired");
  });
});

describe("SignerBuilder", () => {
  test("should build and sign JWT with all claims", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt, jti } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://myapp.com")
      .setExpiration(now + 3600)
      .setSubject("user123")
      .setAudience("https://api.myapp.com")
      .addCustomClaims({ role: "admin", permissions: ["read", "write"] })
      .build();

    expect(jwt).toBeTruthy();
    expect(jti).toBeTruthy();

    const payload = await verify(jwt, publicKey, "https://myapp.com");
    const claims = JSON.parse(payload);
    expect(claims.iss).toBe("https://myapp.com");
    expect(claims.sub).toBe("user123");
    expect(claims.aud).toBe("https://api.myapp.com");
    expect(claims.role).toBe("admin");
    expect(claims.permissions).toEqual(["read", "write"]);
  });

  test("should throw error when missing required fields", async () => {
    const { privateKey } = generateKeypair(MlDsaAlgo.Dsa65);

    await expect(
      new SignerBuilder()
        .algorithm(MlDsaAlgo.Dsa65)
        .setPrivateKey(privateKey)
        .build()
    ).rejects.toThrow("Issuer (iss) is required");
  });

  test("should allow skipping iat claim", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(now + 3600)
      .skipIssuedAt()
      .build();

    const payload = await verify(jwt, publicKey, "https://test.com");
    const claims = JSON.parse(payload);
    expect(claims.iat).toBeUndefined();
  });
});

describe("VerifierBuilder", () => {
  test("should verify with audience validation", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(now + 3600)
      .setAudience("https://api.test.com")
      .build();

    const verifier = new VerifierBuilder()
      .setPublicKey(publicKey)
      .setIssuer("https://test.com")
      .setAudience("https://api.test.com")
      .build();

    const payload = verifier.verify(jwt);
    const claims = JSON.parse(payload);
    expect(claims.aud).toBe("https://api.test.com");
  });

  test("should fail verification when audience doesn't match", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jwt } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(now + 3600)
      .setAudience("https://api.test.com")
      .build();

    const verifier = new VerifierBuilder()
      .setPublicKey(publicKey)
      .setIssuer("https://test.com")
      .setAudience("https://wrong.api.com")
      .build();

    expect(() => verifier.verify(jwt)).toThrow("Invalid audience");
  });

  test("should support leeway for clock skew", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    // Create token that expired 30 seconds ago (using builder to set iat in the past)
    const oldTime = now - 60; // 60 seconds ago
    const { jwt } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(now - 30) // Expired 30 seconds ago
      .setIssuedAt(oldTime) // Set iat to 60 seconds ago
      .build();

    // Should fail without leeway
    await expect(verify(jwt, publicKey, "https://test.com")).rejects.toThrow();

    // Should pass with 60 seconds leeway
    const verifier = new VerifierBuilder()
      .setPublicKey(publicKey)
      .setIssuer("https://test.com")
      .setLeeway(60)
      .build();

    const payload = verifier.verify(jwt);
    expect(payload).toBeTruthy();
  });
});

describe("All Algorithms", () => {
  test.each([MlDsaAlgo.Dsa44, MlDsaAlgo.Dsa65, MlDsaAlgo.Dsa87])(
    "should work with %s",
    async (algo) => {
      const { privateKey, publicKey } = generateKeypair(algo);
      const now = Math.floor(Date.now() / 1000);

      const { jwt } = await sign(algo, "https://test.com", now + 3600, privateKey);

      const payload = await verify(jwt, publicKey, "https://test.com");
      const claims = JSON.parse(payload);
      expect(claims.iss).toBe("https://test.com");
    }
  );
});

describe("JTI (JWT ID)", () => {
  test("should generate unique UUID v7 for jti", async () => {
    const { privateKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);

    const { jti: jti1 } = await sign(MlDsaAlgo.Dsa65, "https://test.com", now + 3600, privateKey);
    const { jti: jti2 } = await sign(MlDsaAlgo.Dsa65, "https://test.com", now + 3600, privateKey);

    expect(jti1).not.toBe(jti2);
    // UUID v7 format validation (basic check)
    expect(jti1).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test("should allow custom jti", async () => {
    const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
    const now = Math.floor(Date.now() / 1000);
    const customJti = "my-custom-id-12345";

    const { jwt, jti } = await new SignerBuilder()
      .algorithm(MlDsaAlgo.Dsa65)
      .setPrivateKey(privateKey)
      .setIssuer("https://test.com")
      .setExpiration(now + 3600)
      .setJwtId(customJti)
      .build();

    expect(jti).toBe(customJti);

    const payload = await verify(jwt, publicKey, "https://test.com");
    const claims = JSON.parse(payload);
    expect(claims.jti).toBe(customJti);
  });
});
