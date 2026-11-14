// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it } from "vitest";
import {
  AuthorityWebAuthnAuthenticator,
  HostWebAuthnClient,
  WebAuthnSecurityError,
  base64UrlEncode,
  buildAuthenticatorData,
  buildClientDataJsonBytes,
  derToP1363Ecdsa,
  p1363ToDerEcdsa,
  validateRpIdAgainstOrigin,
  verifyWebAuthnAssertion,
  type BiometricVerificationContext,
} from "../src/authority/webauthn.ts";

function concatArrays(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(a.byteLength + b.byteLength));
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

describe("A3 WebAuthn rpId validation", () => {
  it("accepts exact HTTPS hosts, registrable parent suffixes, and loopback origins", () => {
    expect(validateRpIdAgainstOrigin("https://app.example.com:8443")).toEqual({
      origin: "https://app.example.com:8443",
      rpId: "app.example.com",
    });
    expect(validateRpIdAgainstOrigin("https://login.app.example.com", "example.com")).toEqual({
      origin: "https://login.app.example.com",
      rpId: "example.com",
    });
    expect(validateRpIdAgainstOrigin("https://shop.acme.co.uk", "acme.co.uk")).toEqual({
      origin: "https://shop.acme.co.uk",
      rpId: "acme.co.uk",
    });
    expect(validateRpIdAgainstOrigin("http://localhost:8787")).toEqual({
      origin: "http://localhost:8787",
      rpId: "localhost",
    });
    expect(validateRpIdAgainstOrigin("http://127.0.0.1:9000")).toEqual({
      origin: "http://127.0.0.1:9000",
      rpId: "127.0.0.1",
    });
    expect(validateRpIdAgainstOrigin("http://[::1]:9000")).toEqual({
      origin: "http://[::1]:9000",
      rpId: "[::1]",
    });
  });

  it("rejects opaque/insecure origins, public suffixes, IP suffixing, and cross-site rpIds", () => {
    const cases: Array<[string, string | undefined, WebAuthnSecurityError["code"]]> = [
      ["null", "example.com", "invalid-origin"],
      ["about:blank", undefined, "invalid-origin"],
      ["http://example.com", undefined, "invalid-origin"],
      ["https://app.example.com", "https://app.example.com", "invalid-rpid"],
      ["https://app.example.com", "example.com:8443", "invalid-rpid"],
      ["https://app.example.com", "com", "public-suffix-rpid"],
      ["https://shop.acme.co.uk", "co.uk", "public-suffix-rpid"],
      ["https://user.github.io", "github.io", "public-suffix-rpid"],
      ["https://evil-example.com", "example.com", "rpid-origin-mismatch"],
      ["https://a.example.com", "other.example.com", "rpid-origin-mismatch"],
      ["http://127.0.0.1:8787", "localhost", "rpid-origin-mismatch"],
    ];
    for (const [origin, rpId, expectedCode] of cases) {
      let caught: unknown = null;
      try {
        validateRpIdAgainstOrigin(origin, rpId);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(WebAuthnSecurityError);
      expect((caught as WebAuthnSecurityError).code).toBe(expectedCode);
    }
  });
});

describe("A3 WebAuthn canonical clientDataJSON, authenticatorData, and DER ECDSA", () => {
  it("builds canonical clientDataJSON and authenticatorData flags/signCount", async () => {
    const challenge = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const clientData = buildClientDataJsonBytes({
      type: "webauthn.get",
      challenge,
      origin: "https://bank.example.com",
    });
    expect(JSON.parse(new TextDecoder().decode(clientData))).toEqual({
      type: "webauthn.get",
      challenge: base64UrlEncode(challenge),
      origin: "https://bank.example.com",
      crossOrigin: false,
    });

    const authData = await buildAuthenticatorData({
      rpId: "example.com",
      userPresent: true,
      userVerified: true,
      signCount: 0x01020304,
    });
    expect(authData.byteLength).toBe(37);
    const expectedRpHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode("example.com")),
    );
    expect(authData.subarray(0, 32)).toEqual(expectedRpHash);
    expect(authData[32]).toBe(0x05);
    expect(new DataView(authData.buffer).getUint32(33, false)).toBe(0x01020304);
  });

  it("round-trips P-256 P1363 signatures through ASN.1 DER encoding", () => {
    const sample = new Uint8Array(64);
    sample[0] = 0x80;
    sample[31] = 0x11;
    sample[32] = 0x00;
    sample[33] = 0x7f;
    sample[63] = 0x22;
    const der = p1363ToDerEcdsa(sample);
    expect(der[0]).toBe(0x30);
    expect(derToP1363Ecdsa(der)).toEqual(sample);
  });
});

describe("A3 AuthorityWebAuthnAuthenticator & HostWebAuthnClient", () => {
  it("requires a mandatory onBiometricVerify callback", () => {
    let caught: unknown = null;
    try {
      Reflect.construct(AuthorityWebAuthnAuthenticator, [{}]);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(WebAuthnSecurityError);
    expect((caught as WebAuthnSecurityError).code).toBe("biometric-required");
  });

  it("issues non-exportable P-256 keys, gates operations on biometric approval, and verifies via crypto.subtle.verify", async () => {
    let allowBiometric = true;
    const seenPrompts: BiometricVerificationContext[] = [];
    const authenticator = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async (ctx) => {
        seenPrompts.push(ctx);
        return allowBiometric;
      },
    });
    const client = new HostWebAuthnClient(authenticator);

    const origin = "https://vault.example.com";
    const rpId = "example.com";
    const createChallenge = crypto.getRandomValues(new Uint8Array(32));
    const userId = new TextEncoder().encode("user-42");

    const reg = await client.createCredential({
      committedOrigin: origin,
      rpId,
      userId,
      userName: "alice@example.com",
      challenge: createChallenge,
    });
    expect(reg.privateKeyExtractable).toBe(false);
    expect(reg.signCount).toBe(0);
    expect(reg.rpId).toBe(rpId);
    expect(reg.origin).toBe(origin);
    expect((reg.authenticatorData[32] ?? 0) & 0x45).toBe(0x45);
    expect(seenPrompts).toHaveLength(1);
    expect(seenPrompts[0]?.operation).toBe("create");

    // Public key exports via SPKI so servers/relying parties can verify assertions independently.
    const importedSpkiKey = await crypto.subtle.importKey(
      "spki",
      reg.publicKeySpkiBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    const getChallenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion1 = await client.getAssertion({
      committedOrigin: origin,
      rpId,
      challenge: getChallenge,
      allowCredentialIds: [reg.rawId],
    });
    expect(assertion1.signCount).toBe(1);
    expect((assertion1.authenticatorData[32] ?? 0) & 0x05).toBe(0x05);
    expect(new TextDecoder().decode(assertion1.userHandle)).toBe("user-42");
    expect(seenPrompts).toHaveLength(2);
    expect(seenPrompts[1]).toMatchObject({
      operation: "get",
      rpId,
      origin,
      credentialIdBase64Url: reg.id,
    });

    const verified1 = await verifyWebAuthnAssertion({
      publicKey: importedSpkiKey,
      expectedRpId: rpId,
      expectedOrigin: origin,
      expectedChallenge: getChallenge,
      clientDataJSON: assertion1.clientDataJSON,
      authenticatorData: assertion1.authenticatorData,
      signature: assertion1.signature,
    });
    expect(verified1).toEqual({ verified: true, signCount: 1 });

    // Direct crypto.subtle.verify against imported SPKI public key and SHA-256(clientDataJSON).
    const clientHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", assertion1.clientDataJSON),
    );
    const directOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      importedSpkiKey,
      derToP1363Ecdsa(assertion1.signature),
      concatArrays(assertion1.authenticatorData, clientHash),
    );
    expect(directOk).toBe(true);

    // Denied biometric check blocks assertion and preserves signCount.
    allowBiometric = false;
    const blockedChallenge = crypto.getRandomValues(new Uint8Array(32));
    await expect(
      client.getAssertion({ committedOrigin: origin, rpId, challenge: blockedChallenge }),
    ).rejects.toMatchObject({ code: "biometric-failed" });

    allowBiometric = true;
    const assertion2 = await client.getAssertion({
      committedOrigin: origin,
      rpId,
      challenge: blockedChallenge,
    });
    expect(assertion2.signCount).toBe(2);

    // Negative checks: wrong challenge, wrong rpId, or tampered signature fail verification.
    await expect(
      verifyWebAuthnAssertion({
        publicKey: importedSpkiKey,
        expectedRpId: rpId,
        expectedOrigin: origin,
        expectedChallenge: createChallenge,
        clientDataJSON: assertion2.clientDataJSON,
        authenticatorData: assertion2.authenticatorData,
        signature: assertion2.signature,
      }),
    ).rejects.toMatchObject({ code: "verification-failed" });

    const tamperedSig = new Uint8Array(assertion2.signature);
    tamperedSig[tamperedSig.length - 1] = (tamperedSig[tamperedSig.length - 1] ?? 0) ^ 0xff;
    await expect(
      verifyWebAuthnAssertion({
        publicKey: importedSpkiKey,
        expectedRpId: rpId,
        expectedOrigin: origin,
        expectedChallenge: blockedChallenge,
        clientDataJSON: assertion2.clientDataJSON,
        authenticatorData: assertion2.authenticatorData,
        signature: tamperedSig,
      }),
    ).rejects.toMatchObject({ code: "verification-failed" });
  });

  it("isolates per-site keys and fails credential lookup on a different origin", async () => {
    const authenticator = new AuthorityWebAuthnAuthenticator({
      onBiometricVerify: async () => true,
    });
    const client = new HostWebAuthnClient(authenticator);

    const regA = await client.createCredential({
      committedOrigin: "https://site-a.example",
      userId: new TextEncoder().encode("u1"),
      userName: "alice",
      challenge: crypto.getRandomValues(new Uint8Array(16)),
    });
    const regB = await client.createCredential({
      committedOrigin: "https://site-b.example",
      userId: new TextEncoder().encode("u1"),
      userName: "alice",
      challenge: crypto.getRandomValues(new Uint8Array(16)),
    });
    expect(regA.publicKeySpkiBytes).not.toEqual(regB.publicKeySpkiBytes);

    await expect(
      client.getAssertion({
        committedOrigin: "https://site-b.example",
        challenge: crypto.getRandomValues(new Uint8Array(16)),
        allowCredentialIds: [regA.rawId],
      }),
    ).rejects.toMatchObject({ code: "credential-not-found" });
  });
});
