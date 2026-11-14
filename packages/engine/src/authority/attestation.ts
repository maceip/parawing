// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// A4 ordered passkey resolution chain; re-exports A5 capsule attestation types.

import type {
  AuthorityWebAuthnAuthenticator,
  CreateWebAuthnCredentialParams,
  GetWebAuthnAssertionParams,
  WebAuthnAssertionResult,
  WebAuthnRegistrationResult,
} from "./webauthn.ts";
import {
  HostWebAuthnClient,
  WebAuthnSecurityError,
  validateRpIdAgainstOrigin,
} from "./webauthn.ts";

export {
  CAPSULE_PINNED_PAGE_SIZE,
  CapsuleAttestationAuthority,
  CapsuleAttestationError,
  canonicalAttestationClaimsBytes,
  signCapsuleAttestation,
  unwrapLeasedAesKey,
  verifyDbscJwtProof,
  wrappedKeyLeaseFromWire,
  wrappedKeyLeaseToWire,
  type AttestationFailureCode,
  type CapsuleAttestationClaims,
  type DbscSessionCredential,
  type SignedCapsuleAttestation,
  type WrappedKeyLeaseRelease,
  type WrappedKeyLeaseReleaseWire,
} from "./capsule-attestation.ts";

export type PasskeyProviderKind = "platformBridge" | "ownP256Authenticator" | "ctapSecurityKey";

export type PasskeyCreateParams = CreateWebAuthnCredentialParams & {
  readonly authenticatorAttachment?: "platform" | "cross-platform";
};

export class PasskeyProviderUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasskeyProviderUnavailableError";
  }
}

export type ProviderAttempt<T> =
  | { readonly status: "completed"; readonly value: T }
  | { readonly status: "unavailable"; readonly reason: string }
  | { readonly status: "security-error"; readonly error: Error };

export interface ExternalPasskeyProvider {
  create(
    params: CreateWebAuthnCredentialParams,
  ): Promise<ProviderAttempt<WebAuthnRegistrationResult>>;
  get(params: GetWebAuthnAssertionParams): Promise<ProviderAttempt<WebAuthnAssertionResult>>;
}

export interface ChainRegistrationResult {
  readonly provider: PasskeyProviderKind;
  readonly result: WebAuthnRegistrationResult;
  readonly attemptedProviders: readonly PasskeyProviderKind[];
}

export interface ChainAssertionResult {
  readonly provider: PasskeyProviderKind;
  readonly result: WebAuthnAssertionResult;
  readonly attemptedProviders: readonly PasskeyProviderKind[];
}

// A4 ordered passkey chain: Platform bridge -> Own P-256 Authenticator -> CTAP key.
export class OrderedPasskeyChain {
  private readonly platformBridge: ExternalPasskeyProvider | undefined;
  private readonly ownClient: HostWebAuthnClient | undefined;
  private readonly ctap: ExternalPasskeyProvider | undefined;

  constructor(options: {
    readonly platformBridge?: ExternalPasskeyProvider;
    readonly ownAuthenticator?: AuthorityWebAuthnAuthenticator | HostWebAuthnClient;
    readonly ctap?: ExternalPasskeyProvider;
  }) {
    this.platformBridge = options.platformBridge;
    if (options.ownAuthenticator) {
      this.ownClient =
        options.ownAuthenticator instanceof HostWebAuthnClient
          ? options.ownAuthenticator
          : new HostWebAuthnClient(options.ownAuthenticator);
    } else {
      this.ownClient = undefined;
    }
    this.ctap = options.ctap;
  }

  async create(params: PasskeyCreateParams): Promise<ChainRegistrationResult> {
    const attempted: PasskeyProviderKind[] = [];
    const reasons: string[] = [];

    attempted.push("platformBridge");
    if (this.platformBridge) {
      const attempt = await this.platformBridge.create(params);
      if (attempt.status === "completed") {
        return { provider: "platformBridge", result: attempt.value, attemptedProviders: attempted };
      }
      if (attempt.status === "security-error") throw attempt.error;
      reasons.push(`platform: ${attempt.reason}`);
    } else {
      reasons.push("platform: bridge unavailable");
    }

    attempted.push("ownP256Authenticator");
    const ownAttempt = await this.tryOwnCreate(params);
    if (ownAttempt.status === "completed") {
      return {
        provider: "ownP256Authenticator",
        result: ownAttempt.value,
        attemptedProviders: attempted,
      };
    }
    if (ownAttempt.status === "security-error") throw ownAttempt.error;
    reasons.push(`own-p256: ${ownAttempt.reason}`);

    attempted.push("ctapSecurityKey");
    if (this.ctap) {
      const ctapAttempt = await this.ctap.create(params);
      if (ctapAttempt.status === "completed") {
        return {
          provider: "ctapSecurityKey",
          result: ctapAttempt.value,
          attemptedProviders: attempted,
        };
      }
      if (ctapAttempt.status === "security-error") throw ctapAttempt.error;
      reasons.push(`ctap: ${ctapAttempt.reason}`);
    } else {
      reasons.push("ctap: no hardware token connected");
    }
    throw new WebAuthnSecurityError(
      "credential-not-found",
      `No passkey provider succeeded: ${reasons.join("; ")}`,
    );
  }

  async get(params: GetWebAuthnAssertionParams): Promise<ChainAssertionResult> {
    const attempted: PasskeyProviderKind[] = [];
    const reasons: string[] = [];

    attempted.push("platformBridge");
    if (this.platformBridge) {
      const attempt = await this.platformBridge.get(params);
      if (attempt.status === "completed") {
        return { provider: "platformBridge", result: attempt.value, attemptedProviders: attempted };
      }
      if (attempt.status === "security-error") throw attempt.error;
      reasons.push(`platform: ${attempt.reason}`);
    } else {
      reasons.push("platform: bridge unavailable");
    }

    attempted.push("ownP256Authenticator");
    const ownAttempt = await this.tryOwnGet(params);
    if (ownAttempt.status === "completed") {
      return {
        provider: "ownP256Authenticator",
        result: ownAttempt.value,
        attemptedProviders: attempted,
      };
    }
    if (ownAttempt.status === "security-error") throw ownAttempt.error;
    reasons.push(`own-p256: ${ownAttempt.reason}`);

    attempted.push("ctapSecurityKey");
    if (this.ctap) {
      const ctapAttempt = await this.ctap.get(params);
      if (ctapAttempt.status === "completed") {
        return {
          provider: "ctapSecurityKey",
          result: ctapAttempt.value,
          attemptedProviders: attempted,
        };
      }
      if (ctapAttempt.status === "security-error") throw ctapAttempt.error;
      reasons.push(`ctap: ${ctapAttempt.reason}`);
    } else {
      reasons.push("ctap: no hardware token connected");
    }
    throw new WebAuthnSecurityError(
      "credential-not-found",
      `No passkey provider succeeded: ${reasons.join("; ")}`,
    );
  }

  private async tryOwnCreate(
    params: PasskeyCreateParams,
  ): Promise<ProviderAttempt<WebAuthnRegistrationResult>> {
    try {
      validateRpIdAgainstOrigin(params.committedOrigin, params.rpId);
      if (params.authenticatorAttachment === "cross-platform") {
        return { status: "unavailable", reason: "cross-platform attachment requested" };
      }
      if (!this.ownClient) {
        return { status: "unavailable", reason: "own P-256 authenticator unavailable" };
      }
      const value = await this.ownClient.createCredential(params);
      return { status: "completed", value };
    } catch (err) {
      if (err instanceof PasskeyProviderUnavailableError) {
        return { status: "unavailable", reason: err.message };
      }
      if (err instanceof DOMException && err.name === "NotSupportedError") {
        return { status: "unavailable", reason: err.message };
      }
      const normalized = err instanceof Error ? err : new Error(String(err));
      return { status: "security-error", error: normalized };
    }
  }

  private async tryOwnGet(
    params: GetWebAuthnAssertionParams,
  ): Promise<ProviderAttempt<WebAuthnAssertionResult>> {
    try {
      validateRpIdAgainstOrigin(params.committedOrigin, params.rpId);
      if (!this.ownClient) {
        return { status: "unavailable", reason: "own P-256 authenticator unavailable" };
      }
      const value = await this.ownClient.getAssertion(params);
      return { status: "completed", value };
    } catch (err) {
      if (err instanceof WebAuthnSecurityError && err.code === "credential-not-found") {
        return { status: "unavailable", reason: err.message };
      }
      if (err instanceof PasskeyProviderUnavailableError) {
        return { status: "unavailable", reason: err.message };
      }
      const normalized = err instanceof Error ? err : new Error(String(err));
      return { status: "security-error", error: normalized };
    }
  }
}
