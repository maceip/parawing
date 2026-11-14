// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import { AuthorityVaultAndChannel } from "../src/authority/authority-service.ts";
import {
  CAPSULE_PINNED_PAGE_SIZE,
  CapsuleAttestationAuthority,
  CapsuleAttestationError,
  OrderedPasskeyChain,
  signCapsuleAttestation,
  unwrapLeasedAesKey,
  verifyDbscJwtProof,
  wrappedKeyLeaseFromWire,
  wrappedKeyLeaseToWire,
  type CapsuleAttestationClaims,
  type ExternalPasskeyProvider,
} from "../src/authority/attestation.ts";
import {
  AuthorityWebAuthnAuthenticator,
  HostWebAuthnClient,
  WebAuthnSecurityError,
  base64UrlEncode,
} from "../src/authority/webauthn.ts";
import { encodeBase64Bytes } from "../src/state/key-lease.ts";
import { asSessionId, asUserId } from "../src/session/identities.ts";

describe("A4 OrderedPasskeyChain", () => {
  it("falls through unavailable Platform bridge to Own P-256 and skips CTAP when satisfied", async () => {
    let ctapCalled = false;
    const platformUnavailable: ExternalPasskeyProvider = {
      async create() {
        return { status: "unavailable", reason: "no OS passkey daemon" };
      },
      async get() {
        return { status: "unavailable", reason: "no OS passkey daemon" };
      },
    };
    const ctap: ExternalPasskeyProvider = {
      async create() {
        ctapCalled = true;
        return { status: "unavailable", reason: "no token" };
      },
      async get() {
        ctapCalled = true;
        return { status: "unavailable", reason: "no token" };
      },
    };
    const own = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => ({ verified: true }),
    });
    const chain = new OrderedPasskeyChain({
      platformBridge: platformUnavailable,
      ownAuthenticator: own,
      ctap,
    });

    const reg = await chain.create({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      userId: new TextEncoder().encode("u-1"),
      userName: "alice@example.com",
      challenge: "chal-reg-1",
    });
    expect(reg.provider).toBe("ownP256Authenticator");
    expect(reg.attemptedProviders).toEqual(["platformBridge", "ownP256Authenticator"]);
    expect(ctapCalled).toBe(false);

    const assertion = await chain.get({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      challenge: "chal-get-1",
    });
    expect(assertion.provider).toBe("ownP256Authenticator");
    expect(ctapCalled).toBe(false);
  });

  it("never falls through on biometric rejection or RP-ID mismatch", async () => {
    let ctapCalled = false;
    const ctap: ExternalPasskeyProvider = {
      async create() {
        ctapCalled = true;
        return { status: "unavailable", reason: "no token" };
      },
      async get() {
        ctapCalled = true;
        return { status: "unavailable", reason: "no token" };
      },
    };
    const ownAllowed = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => ({ verified: true }),
    });
    await new HostWebAuthnClient(ownAllowed).createCredential({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      userId: new TextEncoder().encode("u-1"),
      userName: "alice@example.com",
      challenge: "chal-seed",
    });

    const ownDenied = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => ({ verified: false }),
    });
    const chain = new OrderedPasskeyChain({ ownAuthenticator: ownDenied, ctap });

    await expect(
      chain.create({
        committedOrigin: "https://login.example.com",
        rpId: "example.com",
        userId: new TextEncoder().encode("u-2"),
        userName: "bob@example.com",
        challenge: "chal-bio-fail",
      }),
    ).rejects.toMatchObject({ code: "biometric-failed" });

    const chainRpMismatch = new OrderedPasskeyChain({ ownAuthenticator: ownAllowed, ctap });
    await expect(
      chainRpMismatch.get({
        committedOrigin: "https://login.example.com",
        rpId: "evil.org",
        challenge: "chal-rp-mismatch",
      }),
    ).rejects.toBeInstanceOf(WebAuthnSecurityError);
    expect(ctapCalled).toBe(false);
  });

  it("falls through to CTAP only when Own P-256 has no matching credential", async () => {
    const ownEmpty = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => ({ verified: true }),
    });
    const seedCtapAuth = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => ({ verified: true }),
    });
    const seedCtapClient = new HostWebAuthnClient(seedCtapAuth);
    await seedCtapClient.createCredential({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      userId: new TextEncoder().encode("u-ctap"),
      userName: "ctap@example.com",
      challenge: "chal-ctap-seed",
    });

    const ctapProvider: ExternalPasskeyProvider = {
      async create(params) {
        return { status: "completed", value: await seedCtapClient.createCredential(params) };
      },
      async get(params) {
        return { status: "completed", value: await seedCtapClient.getAssertion(params) };
      },
    };
    const chain = new OrderedPasskeyChain({ ownAuthenticator: ownEmpty, ctap: ctapProvider });
    const regCtap = await chain.create({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      userId: new TextEncoder().encode("u-ctap-create"),
      userName: "ctap@example.com",
      challenge: "chal-ctap-create",
      authenticatorAttachment: "cross-platform",
    });
    expect(regCtap.provider).toBe("ctapSecurityKey");
    expect(regCtap.attemptedProviders).toEqual([
      "platformBridge",
      "ownP256Authenticator",
      "ctapSecurityKey",
    ]);

    const res = await chain.get({
      committedOrigin: "https://login.example.com",
      rpId: "example.com",
      challenge: "chal-ctap-get",
    });
    expect(res.provider).toBe("ctapSecurityKey");
    expect(res.attemptedProviders).toEqual([
      "platformBridge",
      "ownP256Authenticator",
      "ctapSecurityKey",
    ]);
  });
});

describe("A5 CapsuleAttestationAuthority", () => {
  it("verifies Ed25519 + SHA-256 attestation before releasing wrapped lease and DBSC credential", async () => {
    const signer = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    if (!("privateKey" in signer) || !("publicKey" in signer)) {
      throw new Error("Expected Ed25519 keypair");
    }
    const signerSpki = await crypto.subtle.exportKey("spki", signer.publicKey);
    if (!(signerSpki instanceof ArrayBuffer)) throw new Error("Expected SPKI ArrayBuffer");
    const signerSpkiB64 = encodeBase64Bytes(new Uint8Array(signerSpki));

    const capsuleEcdh = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
    if (!("privateKey" in capsuleEcdh) || !("publicKey" in capsuleEcdh)) {
      throw new Error("Expected ECDH P-256 keypair");
    }
    const ephSpki = await crypto.subtle.exportKey("spki", capsuleEcdh.publicKey);
    if (!(ephSpki instanceof ArrayBuffer)) throw new Error("Expected ECDH SPKI");
    const ephSpkiB64 = encodeBase64Bytes(new Uint8Array(ephSpki));

    const expectedHash = "a".repeat(64);
    const authority = await CapsuleAttestationAuthority.create({
      expectedCapsuleHash: expectedHash,
      expectedRustTarget: "aarch64-unknown-linux-musl",
      expectedBaselineId: "armv8.0-a-baseline",
      trustedSignerSpkis: [signerSpkiB64],
    });

    const vault = await AuthorityVaultAndChannel.create({ now: () => 1_000 });
    const lease = await vault.issueKeyLease({
      userId: asUserId("user-a5"),
      sessionId: asSessionId("sess-a5"),
      ttlMs: 60_000,
    });

    const baseClaims: CapsuleAttestationClaims = {
      capsuleHash: expectedHash,
      rustTarget: "aarch64-unknown-linux-musl",
      baselineId: "armv8.0-a-baseline",
      pageSize: CAPSULE_PINNED_PAGE_SIZE,
      ephemeralP256PubkeySpkiB64: ephSpkiB64,
      nonce: "nonce-1",
      issuedAtMs: 1_000,
      expiresAtMs: 10_000,
    };
    const report1 = await signCapsuleAttestation({
      claims: baseClaims,
      ed25519PrivateKey: signer.privateKey,
      ed25519PublicKey: signer.publicKey,
    });

    const wrapped = await authority.releaseWrappedKeyLease(report1, lease, 2_000);
    const wrappedRoundtrip = wrappedKeyLeaseFromWire(wrappedKeyLeaseToWire(wrapped));
    const unwrappedKey = await unwrapLeasedAesKey(capsuleEcdh.privateKey, wrappedRoundtrip);
    expect(unwrappedKey).toEqual(lease.keyBytes);

    await expect(authority.verifyAttestation(report1, 2_000)).rejects.toMatchObject({
      code: "nonce-replayed",
    });

    const report2 = await signCapsuleAttestation({
      claims: { ...baseClaims, nonce: "nonce-2" },
      ed25519PrivateKey: signer.privateKey,
      ed25519PublicKey: signer.publicKey,
    });
    const dbsc = await authority.releaseDbscCredential(
      report2,
      { dbscSessionId: "dbsc-1", origin: "https://app.example", challenge: "chal-1" },
      2_000,
    );
    expect(await verifyDbscJwtProof(dbsc)).toBe(true);
    expect(await verifyDbscJwtProof({ ...dbsc, origin: "https://evil.example" })).toBe(false);
    expect(await verifyDbscJwtProof({ ...dbsc, challenge: "wrong-chal" })).toBe(false);
    expect(await verifyDbscJwtProof({ ...dbsc, dbscSessionId: "wrong-sub" })).toBe(false);
    expect(await verifyDbscJwtProof({ ...dbsc, claimsSha256Hex: "f".repeat(64) })).toBe(false);

    const wrongTypKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    if (!("privateKey" in wrongTypKey) || !("publicKey" in wrongTypKey)) {
      throw new Error("Expected P-256 keypair");
    }
    const wrongPubSpki = await crypto.subtle.exportKey("spki", wrongTypKey.publicKey);
    if (!(wrongPubSpki instanceof ArrayBuffer)) throw new Error("Expected SPKI");
    const enc = new TextEncoder();
    const forgedHdr = base64UrlEncode(enc.encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
    const forgedPay = base64UrlEncode(
      enc.encode(
        JSON.stringify({
          aud: "https://app.example",
          jti: "chal-1",
          sub: "dbsc-1",
          iat: 2,
          capsuleClaimsSha256: dbsc.claimsSha256Hex,
          capsuleHash: expectedHash,
        }),
      ),
    );
    const forgedSig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      wrongTypKey.privateKey,
      enc.encode(`${forgedHdr}.${forgedPay}`),
    );
    expect(
      await verifyDbscJwtProof({
        ...dbsc,
        devicePubkeySpkiB64: encodeBase64Bytes(new Uint8Array(wrongPubSpki)),
        jwtProof: `${forgedHdr}.${forgedPay}.${base64UrlEncode(new Uint8Array(forgedSig))}`,
      }),
    ).toBe(false);

    const drifted = await signCapsuleAttestation({
      claims: { ...baseClaims, capsuleHash: "b".repeat(64), nonce: "nonce-3" },
      ed25519PrivateKey: signer.privateKey,
      ed25519PublicKey: signer.publicKey,
    });
    await expect(authority.verifyAttestation(drifted, 2_000)).rejects.toBeInstanceOf(
      CapsuleAttestationError,
    );

    const expired = await signCapsuleAttestation({
      claims: { ...baseClaims, nonce: "nonce-4" },
      ed25519PrivateKey: signer.privateKey,
      ed25519PublicKey: signer.publicKey,
    });
    await expect(authority.verifyAttestation(expired, 20_000)).rejects.toMatchObject({
      code: "expired",
    });

    const gatedVault = await AuthorityVaultAndChannel.create({
      now: () => 2_000,
      attestationAuthority: authority,
    });
    await expect(
      gatedVault.issueKeyLease({
        userId: asUserId("u-gated"),
        sessionId: asSessionId("s-gated"),
        ttlMs: 30_000,
      }),
    ).rejects.toMatchObject({ code: "invalid-input" });

    const validAtt = await signCapsuleAttestation({
      claims: { ...baseClaims, nonce: "nonce-gated-ok" },
      ed25519PrivateKey: signer.privateKey,
      ed25519PublicKey: signer.publicKey,
    });
    const issued = await gatedVault.issueAttestedKeyLease({
      attestation: validAtt,
      userId: asUserId("u-gated"),
      sessionId: asSessionId("s-gated"),
      ttlMs: 30_000,
      nowMs: 2_000,
    });
    const unwrappedGated = await unwrapLeasedAesKey(capsuleEcdh.privateKey, issued.wrappedRelease);
    expect(unwrappedGated).toEqual(issued.signedLease.keyBytes);
  });
});
