# 🔐 @awth/pq-jwt

**Post-Quantum JWT** - A quantum-resistant JWT implementation using ML-DSA (Module-Lattice Digital Signature Algorithm) signatures for TypeScript/JavaScript.

> 🛡️ **Future-proof your authentication** - Protect your JWTs against quantum computer attacks with NIST-standardized post-quantum cryptography.

## 🌟 Features

- ✅ **Quantum-Resistant** - Uses ML-DSA (FIPS 204) signatures that remain secure even against quantum attacks
- ✅ **Multiple Security Levels** - Choose from ML-DSA-44, ML-DSA-65, or ML-DSA-87 based on your needs
- ✅ **Standards Compliant** - JWT format following RFC 7519
- ✅ **TypeScript-First** - Full TypeScript support with comprehensive type definitions
- ✅ **Flexible API** - Simple functions and advanced Builder patterns
- ✅ **Mandatory JTI** - Built-in UUID v7 for session management with large JWTs
- ✅ **Zero Config** - Works out of the box with Bun, Node.js, and browsers
- ✅ **Well Tested** - Comprehensive test coverage
- ✅ **Lightweight** - Minimal dependencies (@noble/post-quantum + uuid)

## 📦 Installation

```bash
# Using Bun (recommended)
bun add @awth/pq-jwt

# Using npm
npm install @awth/pq-jwt

# Using yarn
yarn add @awth/pq-jwt

# Using pnpm
pnpm add @awth/pq-jwt
```

## 🚀 Quick Start

```typescript
import { generateKeypair, sign, verify, MlDsaAlgo } from "@awth/pq-jwt";

// 1. Generate a keypair
const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);

// 2. Create and sign a JWT
const now = Math.floor(Date.now() / 1000);
const { jwt, publicKey: pubKey, jti } = await sign(
  MlDsaAlgo.Dsa65,
  "https://myapp.com",      // Issuer
  now + 3600,                // Expires in 1 hour
  privateKey
);

console.log("JWT:", jwt);
console.log("JWT ID (jti):", jti);

// 3. Verify the JWT
const payload = await verify(jwt, publicKey, "https://myapp.com");
console.log("Verified payload:", payload);

console.log("✓ JWT verified successfully!");
```

## 📚 Usage Examples

### Basic Authentication Token

```typescript
import { generateKeypair, sign, verify, MlDsaAlgo } from "@awth/pq-jwt";

// Generate long-term keypair (store securely!)
const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);

// Create user session token
const now = Math.floor(Date.now() / 1000);
const { jwt, publicKey: pubKey, jti } = await sign(
  MlDsaAlgo.Dsa65,
  "https://myapp.com",
  now + 3600,
  privateKey
);

// Later: verify the token
const payload = await verify(jwt, publicKey, "https://myapp.com");
console.log("Authenticated user:", payload);
```

### Advanced Authentication Token (Builder API with Custom Claims)

```typescript
import { SignerBuilder, MlDsaAlgo, generateKeypair } from "@awth/pq-jwt";

const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
const now = Math.floor(Date.now() / 1000);

// Create signer with all standard claims and custom data
const { jwt, publicKey: pubKey, jti } = await new SignerBuilder()
  .algorithm(MlDsaAlgo.Dsa65)
  .setPrivateKey(privateKey)
  .setIssuer("https://myapp.com")
  .setExpiration(now + 3600)
  .setSubject("user123")
  .setAudience("https://api.myapp.com")
  .addCustomClaims({
    name: "Alice",
    role: "admin",
    permissions: ["read", "write", "delete"],
  })
  .build();

console.log("Token payload:", JSON.parse(await verify(jwt, publicKey, "https://myapp.com")));
```

### Verifier with Audience and Subject Validation

```typescript
import { SignerBuilder, VerifierBuilder, MlDsaAlgo, generateKeypair } from "@awth/pq-jwt";

const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
const now = Math.floor(Date.now() / 1000);

// Create JWT
const { jwt } = await new SignerBuilder()
  .algorithm(MlDsaAlgo.Dsa65)
  .setPrivateKey(privateKey)
  .setIssuer("https://test.com")
  .setExpiration(now + 3600)
  .setAudience("https://api.test.com")
  .setSubject("user@example.com")
  .build();

// Verify with audience and subject validation
const verifier = new VerifierBuilder()
  .setPublicKey(publicKey)
  .setIssuer("https://test.com")
  .setAudience("https://api.test.com")
  .setSubject("user@example.com")
  .setLeeway(60) // 60 seconds leeway for clock skew
  .build();

const payload = verifier.verify(jwt);
console.log("Verified:", payload);
```

## 🔑 Security Levels

Choose the right security level for your use case:

| Variant | NIST Level | Signature Size | Key Gen | Sign | Verify | Use Case |
|---------|-----------|----------------|---------|------|--------|----------|
| **ML-DSA-44** | Category 2 | ~2.4 KB | ~200 µs | ~460 µs | ~140 µs | IoT devices, low-power systems |
| **ML-DSA-65** | Category 3 | ~3.3 KB | ~350 µs | ~930 µs | ~220 µs | **Recommended for most applications** |
| **ML-DSA-87** | Category 5 | ~4.6 KB | ~440 µs | ~550 µs | ~315 µs | High-security requirements, long-term secrets |

### Security Level Comparison

- **NIST Category 2** ≈ AES-128 security
- **NIST Category 3** ≈ AES-192 security (Recommended)
- **NIST Category 5** ≈ AES-256 security

### Choosing an Algorithm

```typescript
import { MlDsaAlgo } from "@awth/pq-jwt";

// For most web applications (recommended)
const algo = MlDsaAlgo.Dsa65;

// For IoT or bandwidth-constrained environments
const algo = MlDsaAlgo.Dsa44;

// For maximum security (government, financial)
const algo = MlDsaAlgo.Dsa87;
```

## 🍪 Session Management for Large JWTs

Post-quantum JWTs are significantly larger (3-6 KB) than classical JWTs (~300 bytes), making them impractical to store in cookies due to browser size limits (~4 KB per cookie). Here's the recommended pattern:

### Cookie + Server-Side Storage Pattern

Instead of storing the entire JWT in a cookie, store only the `jti` (JWT ID) and keep the full JWT server-side:

```typescript
import { generateKeypair, sign, verify, MlDsaAlgo } from "@awth/pq-jwt";

// 1. Generate and sign JWT
const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
const now = Math.floor(Date.now() / 1000);

const { jwt, publicKey: pubKey, jti } = await sign(
  MlDsaAlgo.Dsa65,
  "https://myapp.com",
  now + 3600,  // 1 hour expiration
  privateKey
);

// 2. Store JWT server-side (Redis, database, etc.)
await redis.setex(jti, 3600, jwt);
// OR
// await db.insert({ jti, jwt, expires_at: now + 3600 });

// 3. Store only the jti in cookie (36 bytes as UUID)
// Set-Cookie: session_id={jti}; HttpOnly; Secure; SameSite=Strict

// 4. On subsequent requests, retrieve JWT using jti
const storedJwt = await redis.get(sessionId);
const payload = await verify(storedJwt, publicKey, "https://myapp.com");
```

### Why UUID v7 for JTI?

This library uses UUID v7 (time-ordered) for `jti`, which provides several benefits:

- **Sortable**: UUIDs are time-ordered, making them efficient for database indexing
- **K-sorted**: Improves database performance by reducing index fragmentation
- **Timestamp component**: Can extract creation time from the UUID
- **Collision-resistant**: Cryptographically random with timestamp prefix

### Size Comparison: Cookie Storage

| Approach | Cookie Size | Storage Location |
|----------|-------------|------------------|
| **Classical JWT in cookie** | ~300 bytes | Client |
| **PQ JWT in cookie** | ~4.5 KB ❌ (exceeds limits) | Client |
| **JTI in cookie** | 36 bytes ✅ | Client (jti) + Server (JWT) |

### Example: Full Web Application Flow with Bun

```typescript
// login.ts
import { Bun } from "bun";
import { generateKeypair, sign, MlDsaAlgo } from "@awth/pq-jwt";

const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);

Bun.serve({
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/login" && req.method === "POST") {
      // Authenticate user...

      const now = Math.floor(Date.now() / 1000);
      const { jwt, publicKey: pubKey, jti } = await sign(
        MlDsaAlgo.Dsa65,
        "https://myapp.com",
        now + 3600,
        privateKey
      );

      // Store in Redis with TTL
      await redis.setex(jti, 3600, jwt);

      // Return cookie with jti only (36 bytes vs 4.5 KB)
      return new Response("Logged in", {
        headers: {
          "Set-Cookie": `session_id=${jti}; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`,
        },
      });
    }

    if (url.pathname === "/protected") {
      // Get session_id from cookie
      const cookies = req.headers.get("Cookie") || "";
      const sessionId = cookies.split("session_id=")[1]?.split(";")[0];

      if (!sessionId) {
        return new Response("Unauthorized", { status: 401 });
      }

      // Lookup full JWT from Redis
      const jwt = await redis.get(sessionId);
      if (!jwt) {
        return new Response("Session not found", { status: 401 });
      }

      // Verify JWT
      try {
        const payload = await verify(jwt, publicKey, "https://myapp.com");
        return new Response(`Protected data: ${payload}`);
      } catch (error) {
        return new Response("Invalid token", { status: 401 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
  port: 3000,
});
```

## 🛠️ API Reference

### Simple API (Convenience Functions)

#### `generateKeypair(algo: MlDsaAlgo): Keypair`

Generates a new keypair for the specified algorithm.

**Returns**: `{ privateKey: string, publicKey: string }`

```typescript
import { generateKeypair, MlDsaAlgo } from "@awth/pq-jwt";

const { privateKey, publicKey } = generateKeypair(MlDsaAlgo.Dsa65);
```

#### `sign(algo: MlDsaAlgo, iss: string, exp: number, privateKeyHex: string): Promise<SignResult>`

Signs JWT claims and returns a JWT with the public key and JWT ID.

**Parameters**:
- `algo` - ML-DSA algorithm variant
- `iss` - Issuer (REQUIRED)
- `exp` - Expiration time as Unix timestamp in seconds (REQUIRED)
- `privateKeyHex` - Hex-encoded private key

**Returns**: `Promise<{ jwt: string, publicKey: string, jti: string }>`
- `jwt` - The signed JWT string
- `publicKey` - Hex-encoded public key (for verification)
- `jti` - JWT ID (UUID v7 format) - useful for session management

```typescript
import { sign, MlDsaAlgo } from "@awth/pq-jwt";

const now = Math.floor(Date.now() / 1000);
const { jwt, publicKey, jti } = await sign(
  MlDsaAlgo.Dsa65,
  "https://myapp.com",
  now + 3600,
  privateKey
);
console.log("JWT ID for session tracking:", jti);
```

#### `verify(jwt: string, publicKeyHex: string, expectedIssuer: string): Promise<string>`

Verifies a JWT and returns the decoded payload.

**Parameters**:
- `jwt` - The JWT string to verify
- `publicKeyHex` - Hex-encoded public key
- `expectedIssuer` - Expected issuer that must match the JWT's `iss` claim

**Returns**: `Promise<string>` - payload if valid, throws error otherwise

```typescript
import { verify } from "@awth/pq-jwt";

const payload = await verify(jwt, publicKey, "https://myapp.com");
const claims = JSON.parse(payload);
```

### Builder API (Advanced)

#### `SignerBuilder`

**Configuration Methods:**
- `.algorithm(algo: MlDsaAlgo)` - Set the algorithm variant (REQUIRED)
- `.setPrivateKey(privateKey: string)` - Set the private key (REQUIRED)
- `.setIssuer(iss: string)` - Set `iss` claim (REQUIRED)
- `.setExpiration(exp: number)` - Set `exp` claim as Unix timestamp (REQUIRED)
- `.setSubject(sub: string)` - Set `sub` claim (optional)
- `.setAudience(aud: string)` - Set `aud` claim (optional)
- `.setIssuedAt(iat: number)` - Set `iat` claim, defaults to signing time if not set (optional)
- `.setNotBefore(nbf: number)` - Set `nbf` claim as Unix timestamp (optional)
- `.setJwtId(jti: string)` - Override the auto-generated `jti` claim (UUID v7 by default)
- `.addCustomClaims(claims: Record<string, unknown>)` - Add custom claims (optional)
- `.skipIssuedAt()` - Skip the `iat` claim entirely

**Build Method:**
- `.build()` - Build and sign the JWT, returns `Promise<SignResult>`

```typescript
import { SignerBuilder, MlDsaAlgo } from "@awth/pq-jwt";

const now = Math.floor(Date.now() / 1000);

const { jwt, publicKey, jti } = await new SignerBuilder()
  .algorithm(MlDsaAlgo.Dsa65)
  .setPrivateKey(privateKey)
  .setIssuer("https://myapp.com")
  .setExpiration(now + 3600)
  .setSubject("user@example.com")
  .addCustomClaims({ role: "admin" })
  .build();
```

#### `VerifierBuilder`

**Required Configuration:**
- `.setPublicKey(publicKey: string)` - Set the public key (REQUIRED)
- `.setIssuer(issuer: string)` - Set expected issuer for validation (REQUIRED)

**Optional Claim Validations:**
- `.setAudience(audience: string)` - Set expected audience for validation
- `.setSubject(subject: string)` - Set expected subject for validation
- `.setLeeway(leeway: number)` - Set time leeway in seconds for clock skew (default: 0)

**Build Method:**
- `.build()` - Build Verifier instance, returns `Verifier`

**Verifier Methods:**
- `.verify(jwt: string)` - Verify JWT and return payload, returns `string`

```typescript
import { VerifierBuilder } from "@awth/pq-jwt";

const verifier = new VerifierBuilder()
  .setPublicKey(publicKey)
  .setIssuer("https://myapp.com")
  .setAudience("https://api.myapp.com")
  .setLeeway(60)
  .build();

const payload = verifier.verify(jwt);
```

## 🤔 Why Post-Quantum?

### The Quantum Threat

Quantum computers, when fully developed, will break current cryptographic systems:

- **RSA** - Vulnerable to Shor's algorithm
- **ECDSA** - Vulnerable to Shor's algorithm
- **Diffie-Hellman** - Vulnerable to quantum attacks

### Timeline

- **2024**: NIST releases FIPS 204 (ML-DSA standard)
- **2025-2030**: Quantum computers may break RSA-2048
- **2030+**: All systems must use post-quantum crypto

### "Harvest Now, Decrypt Later"

Attackers can:
1. Intercept and store encrypted data today
2. Wait for quantum computers to become available
3. Decrypt the data retroactively

**Solution**: Start using post-quantum crypto NOW to protect long-term secrets.

## 📄 License

MIT

## 👨‍💻 Author

**MKSingh** ([@MKSingh_Dev](https://x.com/MKSingh_Dev))

---

**Made with ❤️ for a quantum-safe future**
