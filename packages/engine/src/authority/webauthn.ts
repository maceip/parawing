// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// A3 WebAuthn host client and non-exportable P-256 biometric-gated authenticator.

import { isIpHost, isPublicSuffix, siteKey } from "../public-suffix.ts";
import { normalizeStrictOrigin } from "./authority-service.ts";

export class WebAuthnSecurityError extends Error {
  readonly code:
    | "invalid-origin"
    | "invalid-rpid"
    | "public-suffix-rpid"
    | "rpid-origin-mismatch"
    | "biometric-required"
    | "biometric-failed"
    | "credential-not-found"
    | "verification-failed";

  constructor(code: WebAuthnSecurityError["code"], message: string) {
    super(message);
    this.name = "WebAuthnSecurityError";
    this.code = code;
  }
}

export interface BiometricVerificationContext {
  readonly operation: "create" | "get";
  readonly rpId: string;
  readonly origin: string;
  readonly userName?: string;
  readonly credentialIdBase64Url?: string;
}

export type BiometricVerifyCallback = (
  ctx: BiometricVerificationContext,
) => Promise<boolean | { readonly verified: boolean }>;

export interface WebAuthnCredentialRecord {
  readonly credentialId: Uint8Array<ArrayBuffer>;
  readonly credentialIdBase64Url: string;
  readonly rpId: string;
  readonly origin: string;
  readonly userHandle: Uint8Array<ArrayBuffer>;
  readonly publicKey: CryptoKey;
  readonly publicKeySpkiBytes: Uint8Array<ArrayBuffer>;
  readonly cosePublicKey: Uint8Array<ArrayBuffer>;
  signCount: number;
  readonly extractable: false;
}

export interface CreateWebAuthnCredentialParams {
  readonly committedOrigin: string;
  readonly rpId?: string;
  readonly rpName?: string;
  readonly userId: Uint8Array;
  readonly userName: string;
  readonly challenge: Uint8Array | string;
}

export interface WebAuthnRegistrationResult {
  readonly id: string;
  readonly rawId: Uint8Array<ArrayBuffer>;
  readonly rpId: string;
  readonly origin: string;
  readonly clientDataJSON: Uint8Array<ArrayBuffer>;
  readonly authenticatorData: Uint8Array<ArrayBuffer>;
  readonly attestationObject: Uint8Array<ArrayBuffer>;
  readonly publicKey: CryptoKey;
  readonly publicKeySpkiBytes: Uint8Array<ArrayBuffer>;
  readonly signCount: number;
  readonly privateKeyExtractable: false;
}

export interface GetWebAuthnAssertionParams {
  readonly committedOrigin: string;
  readonly rpId?: string;
  readonly challenge: Uint8Array | string;
  readonly allowCredentialIds?: ReadonlyArray<Uint8Array | string>;
}

export interface WebAuthnAssertionResult {
  readonly id: string;
  readonly rawId: Uint8Array<ArrayBuffer>;
  readonly rpId: string;
  readonly origin: string;
  readonly clientDataJSON: Uint8Array<ArrayBuffer>;
  readonly authenticatorData: Uint8Array<ArrayBuffer>;
  readonly signature: Uint8Array<ArrayBuffer>;
  readonly signatureP1363: Uint8Array<ArrayBuffer>;
  readonly userHandle: Uint8Array<ArrayBuffer>;
  readonly signCount: number;
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const P256_COORD_BYTES = 32;

function toBufferBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  const padded =
    text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(parts: ReadonlyArray<Uint8Array>): Uint8Array<ArrayBuffer> {
  let total = 0;
  for (const part of parts) total += part.byteLength;
  const out = new Uint8Array(new ArrayBuffer(total));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

function normalizeChallenge(challenge: Uint8Array | string): string {
  if (typeof challenge === "string") return challenge;
  return base64UrlEncode(challenge);
}

export function validateRpIdAgainstOrigin(
  committedOrigin: string,
  requestedRpId?: string,
): { readonly origin: string; readonly rpId: string } {
  const strictOrigin = normalizeStrictOrigin(committedOrigin);
  if (!strictOrigin) {
    throw new WebAuthnSecurityError(
      "invalid-origin",
      `Opaque or invalid origin: ${committedOrigin}`,
    );
  }
  const parsed = new URL(strictOrigin);
  const originHost = parsed.hostname.toLowerCase().replace(/\.$/, "");
  const isLoopback =
    originHost === "localhost" ||
    originHost.endsWith(".localhost") ||
    originHost === "127.0.0.1" ||
    originHost === "[::1]" ||
    originHost === "::1";
  if (parsed.protocol !== "https:" && !isLoopback) {
    throw new WebAuthnSecurityError(
      "invalid-origin",
      `WebAuthn requires https or loopback origin, got ${strictOrigin}`,
    );
  }
  const candidate = (requestedRpId ?? originHost).trim().toLowerCase().replace(/\.$/, "");
  const isIpv6LoopbackCandidate = candidate === "[::1]" || candidate === "::1";
  if (!candidate || (!isIpv6LoopbackCandidate && /[:/?#\s@\\[\]]/.test(candidate))) {
    throw new WebAuthnSecurityError(
      "invalid-rpid",
      `Malformed WebAuthn rpId: ${String(requestedRpId)}`,
    );
  }
  if (isIpHost(originHost) || isIpHost(candidate)) {
    if (candidate !== originHost) {
      throw new WebAuthnSecurityError(
        "rpid-origin-mismatch",
        `IP-literal origin ${originHost} cannot use rpId ${candidate}`,
      );
    }
    return { origin: strictOrigin, rpId: candidate };
  }
  if (!(isLoopback && candidate === originHost) && isPublicSuffix(candidate)) {
    throw new WebAuthnSecurityError(
      "public-suffix-rpid",
      `rpId "${candidate}" is a public suffix and cannot claim WebAuthn credentials`,
    );
  }
  const matchesDomain = originHost === candidate || originHost.endsWith(`.${candidate}`);
  if (!matchesDomain || siteKey(originHost) !== siteKey(candidate)) {
    throw new WebAuthnSecurityError(
      "rpid-origin-mismatch",
      `rpId "${candidate}" is not a registrable suffix within origin "${originHost}"`,
    );
  }
  return { origin: strictOrigin, rpId: candidate };
}

export function buildClientDataJsonBytes(params: {
  readonly type: "webauthn.create" | "webauthn.get";
  readonly challenge: Uint8Array | string;
  readonly origin: string;
  readonly crossOrigin?: boolean;
}): Uint8Array<ArrayBuffer> {
  const payload = JSON.stringify({
    type: params.type,
    challenge: normalizeChallenge(params.challenge),
    origin: params.origin,
    crossOrigin: params.crossOrigin ?? false,
  });
  return toBufferBytes(TEXT_ENCODER.encode(payload));
}

function encodeCborBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const len = bytes.byteLength;
  const header = len < 24 ? [0x40 | len] : [0x58, len];
  return concatBytes([new Uint8Array(header), bytes]);
}

function encodeCborText(text: string): Uint8Array<ArrayBuffer> {
  const utf8 = TEXT_ENCODER.encode(text);
  const len = utf8.byteLength;
  const header = len < 24 ? [0x60 | len] : [0x78, len];
  return concatBytes([new Uint8Array(header), utf8]);
}

function encodeCborInt(value: number): Uint8Array<ArrayBuffer> {
  if (value >= 0 && value < 24) return new Uint8Array([value]);
  if (value < 0 && value >= -24) return new Uint8Array([0x20 | (-1 - value)]);
  throw new RangeError(`Unsupported CBOR small integer: ${value}`);
}

export async function encodeCoseEs256PublicKey(
  publicKey: CryptoKey,
): Promise<Uint8Array<ArrayBuffer>> {
  const exported = await crypto.subtle.exportKey("jwk", publicKey);
  if (exported instanceof ArrayBuffer) {
    throw new WebAuthnSecurityError("verification-failed", "Expected JWK public key export");
  }
  const jwk = exported;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new WebAuthnSecurityError("verification-failed", "Public key is not ECDSA P-256");
  }
  const x = base64UrlDecode(jwk.x);
  const y = base64UrlDecode(jwk.y);
  if (x.byteLength !== P256_COORD_BYTES || y.byteLength !== P256_COORD_BYTES) {
    throw new WebAuthnSecurityError("verification-failed", "Unexpected P-256 coordinate length");
  }
  return concatBytes([
    new Uint8Array([0xa5]),
    encodeCborInt(1),
    encodeCborInt(2),
    encodeCborInt(3),
    encodeCborInt(-7),
    encodeCborInt(-1),
    encodeCborInt(1),
    encodeCborInt(-2),
    encodeCborBytes(x),
    encodeCborInt(-3),
    encodeCborBytes(y),
  ]);
}

export async function buildAuthenticatorData(params: {
  readonly rpId: string;
  readonly userPresent: boolean;
  readonly userVerified: boolean;
  readonly signCount: number;
  readonly attestedCredentialData?: {
    readonly aaguid: Uint8Array;
    readonly credentialId: Uint8Array;
    readonly cosePublicKey: Uint8Array;
  };
}): Promise<Uint8Array<ArrayBuffer>> {
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toBufferBytes(TEXT_ENCODER.encode(params.rpId))),
  );
  let flags = 0;
  if (params.userPresent) flags |= FLAG_UP;
  if (params.userVerified) flags |= FLAG_UV;
  if (params.attestedCredentialData) flags |= FLAG_AT;

  const fixed = new Uint8Array(new ArrayBuffer(37));
  fixed.set(rpIdHash, 0);
  fixed[32] = flags;
  new DataView(fixed.buffer).setUint32(33, params.signCount >>> 0, false);

  if (!params.attestedCredentialData) return fixed;

  const { aaguid, credentialId, cosePublicKey } = params.attestedCredentialData;
  if (aaguid.byteLength !== 16) {
    throw new TypeError("WebAuthn aaguid must be 16 bytes");
  }
  const lenBuf = new Uint8Array(new ArrayBuffer(2));
  new DataView(lenBuf.buffer).setUint16(0, credentialId.byteLength, false);
  return concatBytes([fixed, aaguid, lenBuf, credentialId, cosePublicKey]);
}

function buildNoneAttestationObject(authData: Uint8Array): Uint8Array<ArrayBuffer> {
  const header = new Uint8Array([0xa3]);
  const authLen = authData.byteLength;
  const authPrefix =
    authLen < 24
      ? new Uint8Array([0x40 | authLen])
      : authLen < 256
        ? new Uint8Array([0x58, authLen])
        : new Uint8Array([0x59, (authLen >> 8) & 0xff, authLen & 0xff]);
  return concatBytes([
    header,
    encodeCborText("fmt"),
    encodeCborText("none"),
    encodeCborText("attStmt"),
    new Uint8Array([0xa0]),
    encodeCborText("authData"),
    authPrefix,
    authData,
  ]);
}

function encodeDerInt(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  let start = 0;
  while (start < raw.byteLength - 1 && raw[start] === 0) start++;
  const slice = raw.subarray(start);
  const needsZeroPad = (slice[0] ?? 0) >= 0x80;
  const out = new Uint8Array(new ArrayBuffer(2 + slice.byteLength + (needsZeroPad ? 1 : 0)));
  out[0] = 0x02;
  out[1] = slice.byteLength + (needsZeroPad ? 1 : 0);
  if (needsZeroPad) {
    out[2] = 0x00;
    out.set(slice, 3);
  } else {
    out.set(slice, 2);
  }
  return out;
}

export function p1363ToDerEcdsa(sig: Uint8Array): Uint8Array<ArrayBuffer> {
  if (sig.byteLength !== P256_COORD_BYTES * 2) {
    throw new WebAuthnSecurityError("verification-failed", "Invalid P-256 signature length");
  }
  const r = encodeDerInt(sig.subarray(0, P256_COORD_BYTES));
  const s = encodeDerInt(sig.subarray(P256_COORD_BYTES));
  const totalLen = r.byteLength + s.byteLength;
  return concatBytes([new Uint8Array([0x30, totalLen]), r, s]);
}

function copyPadCoord(slice: Uint8Array): Uint8Array<ArrayBuffer> {
  const trimmed =
    slice.length > P256_COORD_BYTES ? slice.subarray(slice.length - P256_COORD_BYTES) : slice;
  const out = new Uint8Array(new ArrayBuffer(P256_COORD_BYTES));
  out.set(trimmed, P256_COORD_BYTES - trimmed.length);
  return out;
}

export function derToP1363Ecdsa(der: Uint8Array): Uint8Array<ArrayBuffer> {
  if (der.byteLength === P256_COORD_BYTES * 2 && der[0] !== 0x30) {
    return toBufferBytes(der);
  }
  if (der[0] !== 0x30 || der.byteLength < 8) {
    throw new WebAuthnSecurityError("verification-failed", "Malformed DER ECDSA signature");
  }
  let pos = 2;
  if (der[1] === 0x81) pos = 3;
  if (pos + 2 > der.byteLength || der[pos] !== 0x02) {
    throw new WebAuthnSecurityError("verification-failed", "Malformed DER r integer");
  }
  const rLen = der[pos + 1] ?? 0;
  if (rLen === 0 || pos + 2 + rLen + 2 > der.byteLength) {
    throw new WebAuthnSecurityError("verification-failed", "Malformed DER r length");
  }
  const r = copyPadCoord(der.subarray(pos + 2, pos + 2 + rLen));
  pos += 2 + rLen;
  if (der[pos] !== 0x02) {
    throw new WebAuthnSecurityError("verification-failed", "Malformed DER s integer");
  }
  const sLen = der[pos + 1] ?? 0;
  if (sLen === 0 || pos + 2 + sLen > der.byteLength) {
    throw new WebAuthnSecurityError("verification-failed", "Malformed DER s length");
  }
  const s = copyPadCoord(der.subarray(pos + 2, pos + 2 + sLen));
  return concatBytes([r, s]);
}

export class AuthorityWebAuthnAuthenticator {
  private readonly aaguid: Uint8Array<ArrayBuffer>;
  private readonly onBiometricVerify: BiometricVerifyCallback;
  private readonly credentials = new Map<
    string,
    { readonly record: WebAuthnCredentialRecord; readonly privateKey: CryptoKey }
  >();

  constructor(options: {
    readonly onBiometricVerify: BiometricVerifyCallback;
    readonly aaguid?: Uint8Array;
  }) {
    if (typeof options?.onBiometricVerify !== "function") {
      throw new WebAuthnSecurityError(
        "biometric-required",
        "AuthorityWebAuthnAuthenticator requires a mandatory onBiometricVerify callback",
      );
    }
    this.onBiometricVerify = options.onBiometricVerify;
    if (options.aaguid) {
      if (options.aaguid.byteLength !== 16) throw new TypeError("aaguid must be 16 bytes");
      this.aaguid = toBufferBytes(options.aaguid);
    } else {
      const aaguid = new Uint8Array(new ArrayBuffer(16));
      aaguid.set(TEXT_ENCODER.encode("PARAWING-AUTHN-3"));
      this.aaguid = aaguid;
    }
  }

  private async requireBiometric(ctx: BiometricVerificationContext): Promise<void> {
    const verdict = await this.onBiometricVerify(ctx);
    const verified = typeof verdict === "boolean" ? verdict : verdict?.verified === true;
    if (!verified) {
      throw new WebAuthnSecurityError(
        "biometric-failed",
        `Biometric verification rejected for ${ctx.operation} on ${ctx.rpId}`,
      );
    }
  }

  async makeCredential(params: {
    readonly rpId: string;
    readonly origin: string;
    readonly userId: Uint8Array;
    readonly userName: string;
    readonly clientDataJSON: Uint8Array;
  }): Promise<WebAuthnRegistrationResult> {
    await this.requireBiometric({
      operation: "create",
      rpId: params.rpId,
      origin: params.origin,
      userName: params.userName,
    });

    const generated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    if (!("privateKey" in generated) || !("publicKey" in generated)) {
      throw new WebAuthnSecurityError("verification-failed", "Expected ECDSA P-256 key pair");
    }
    const keyPair = generated;
    if (keyPair.privateKey.extractable !== false) {
      throw new WebAuthnSecurityError(
        "verification-failed",
        "Authenticator private key must be non-extractable",
      );
    }
    const spkiBuf = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    if (!(spkiBuf instanceof ArrayBuffer)) {
      throw new WebAuthnSecurityError("verification-failed", "Expected SPKI public key buffer");
    }
    const publicKeySpkiBytes = new Uint8Array(spkiBuf);
    const cosePublicKey = await encodeCoseEs256PublicKey(keyPair.publicKey);
    const credId = new Uint8Array(new ArrayBuffer(32));
    crypto.getRandomValues(credId);
    const credIdB64Url = base64UrlEncode(credId);

    const authData = await buildAuthenticatorData({
      rpId: params.rpId,
      userPresent: true,
      userVerified: true,
      signCount: 0,
      attestedCredentialData: {
        aaguid: this.aaguid,
        credentialId: credId,
        cosePublicKey,
      },
    });
    const attestationObject = buildNoneAttestationObject(authData);

    const record: WebAuthnCredentialRecord = {
      credentialId: credId,
      credentialIdBase64Url: credIdB64Url,
      rpId: params.rpId,
      origin: params.origin,
      userHandle: toBufferBytes(params.userId),
      publicKey: keyPair.publicKey,
      publicKeySpkiBytes,
      cosePublicKey,
      signCount: 0,
      extractable: false,
    };
    this.credentials.set(credIdB64Url, { record, privateKey: keyPair.privateKey });

    return {
      id: credIdB64Url,
      rawId: credId,
      rpId: params.rpId,
      origin: params.origin,
      clientDataJSON: toBufferBytes(params.clientDataJSON),
      authenticatorData: authData,
      attestationObject,
      publicKey: keyPair.publicKey,
      publicKeySpkiBytes,
      signCount: 0,
      privateKeyExtractable: false,
    };
  }

  async getAssertion(params: {
    readonly rpId: string;
    readonly origin: string;
    readonly clientDataJSON: Uint8Array;
    readonly allowCredentialIds?: ReadonlyArray<Uint8Array | string>;
  }): Promise<WebAuthnAssertionResult> {
    const match = this.findMatchingCredential(
      params.rpId,
      params.origin,
      params.allowCredentialIds,
    );
    await this.requireBiometric({
      operation: "get",
      rpId: params.rpId,
      origin: params.origin,
      credentialIdBase64Url: match.record.credentialIdBase64Url,
    });

    match.record.signCount += 1;
    const authData = await buildAuthenticatorData({
      rpId: params.rpId,
      userPresent: true,
      userVerified: true,
      signCount: match.record.signCount,
    });
    const clientHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", toBufferBytes(params.clientDataJSON)),
    );
    const signedInput = concatBytes([authData, clientHash]);
    const p1363Sig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, match.privateKey, signedInput),
    );
    const derSig = p1363ToDerEcdsa(p1363Sig);

    return {
      id: match.record.credentialIdBase64Url,
      rawId: toBufferBytes(match.record.credentialId),
      rpId: params.rpId,
      origin: params.origin,
      clientDataJSON: toBufferBytes(params.clientDataJSON),
      authenticatorData: authData,
      signature: derSig,
      signatureP1363: p1363Sig,
      userHandle: toBufferBytes(match.record.userHandle),
      signCount: match.record.signCount,
    };
  }

  private findMatchingCredential(
    rpId: string,
    origin: string,
    allowList?: ReadonlyArray<Uint8Array | string>,
  ): { readonly record: WebAuthnCredentialRecord; readonly privateKey: CryptoKey } {
    const allowedIds = allowList
      ? new Set(allowList.map((id) => (typeof id === "string" ? id : base64UrlEncode(id))))
      : null;
    for (const entry of this.credentials.values()) {
      if (entry.record.rpId !== rpId || entry.record.origin !== origin) continue;
      if (allowedIds && !allowedIds.has(entry.record.credentialIdBase64Url)) continue;
      return entry;
    }
    throw new WebAuthnSecurityError(
      "credential-not-found",
      `No WebAuthn credential bound to rpId=${rpId} origin=${origin}`,
    );
  }
}

export class HostWebAuthnClient {
  private readonly authenticator: AuthorityWebAuthnAuthenticator;

  constructor(authenticator: AuthorityWebAuthnAuthenticator) {
    this.authenticator = authenticator;
  }

  async createCredential(
    params: CreateWebAuthnCredentialParams,
  ): Promise<WebAuthnRegistrationResult> {
    const { origin, rpId } = validateRpIdAgainstOrigin(params.committedOrigin, params.rpId);
    const clientDataJSON = buildClientDataJsonBytes({
      type: "webauthn.create",
      challenge: params.challenge,
      origin,
    });
    return this.authenticator.makeCredential({
      rpId,
      origin,
      userId: params.userId,
      userName: params.userName,
      clientDataJSON,
    });
  }

  async getAssertion(params: GetWebAuthnAssertionParams): Promise<WebAuthnAssertionResult> {
    const { origin, rpId } = validateRpIdAgainstOrigin(params.committedOrigin, params.rpId);
    const clientDataJSON = buildClientDataJsonBytes({
      type: "webauthn.get",
      challenge: params.challenge,
      origin,
    });
    return this.authenticator.getAssertion({
      rpId,
      origin,
      clientDataJSON,
      allowCredentialIds: params.allowCredentialIds,
    });
  }
}

export async function verifyWebAuthnAssertion(params: {
  readonly publicKey: CryptoKey;
  readonly expectedRpId: string;
  readonly expectedOrigin: string;
  readonly expectedChallenge: Uint8Array | string;
  readonly clientDataJSON: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
}): Promise<{ readonly verified: true; readonly signCount: number }> {
  const clientText = TEXT_DECODER.decode(params.clientDataJSON);
  let parsed: { type?: unknown; challenge?: unknown; origin?: unknown };
  try {
    parsed = JSON.parse(clientText) as { type?: unknown; challenge?: unknown; origin?: unknown };
  } catch {
    throw new WebAuthnSecurityError("verification-failed", "Invalid clientDataJSON");
  }
  if (
    parsed.type !== "webauthn.get" ||
    parsed.origin !== params.expectedOrigin ||
    parsed.challenge !== normalizeChallenge(params.expectedChallenge)
  ) {
    throw new WebAuthnSecurityError("verification-failed", "clientDataJSON claims mismatch");
  }
  if (params.authenticatorData.byteLength < 37) {
    throw new WebAuthnSecurityError("verification-failed", "authenticatorData too short");
  }
  const expectedHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toBufferBytes(TEXT_ENCODER.encode(params.expectedRpId))),
  );
  for (let i = 0; i < 32; i++) {
    if (params.authenticatorData[i] !== expectedHash[i]) {
      throw new WebAuthnSecurityError("verification-failed", "rpIdHash mismatch");
    }
  }
  const flags = params.authenticatorData[32] ?? 0;
  if ((flags & FLAG_UP) === 0 || (flags & FLAG_UV) === 0) {
    throw new WebAuthnSecurityError("verification-failed", "UP/UV flags missing");
  }
  const signCount = new DataView(
    params.authenticatorData.buffer,
    params.authenticatorData.byteOffset + 33,
    4,
  ).getUint32(0, false);

  const clientHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toBufferBytes(params.clientDataJSON)),
  );
  const signedInput = concatBytes([params.authenticatorData, clientHash]);
  const p1363Sig = derToP1363Ecdsa(params.signature);
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    params.publicKey,
    p1363Sig,
    signedInput,
  );
  if (!ok) {
    throw new WebAuthnSecurityError("verification-failed", "ECDSA P-256 signature invalid");
  }
  return { verified: true, signCount };
}
