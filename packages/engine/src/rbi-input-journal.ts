// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// 8.8 Client Input Journal: AES-256-GCM encrypted buffer keyed by (inputSeq, StableFieldKey)
// with strict exclusion of password, credential, card, OTP, and submit inputs.

export interface StableFieldKey {
  origin: string;
  documentUrl?: string;
  formId?: string;
  formAction?: string;
  fieldName?: string;
  fieldId?: string;
  tagName: string;
  inputType?: string;
  autocomplete?: string;
  domPath?: string;
  nodeId?: number;
}

export type RejectionReason =
  | "password-field"
  | "credential-field"
  | "payment-card-field"
  | "otp-field"
  | "hidden-or-file-field"
  | "submit-action-excluded"
  | "invalid-sequence";

export interface FieldSensitivityResult {
  sensitive: boolean;
  reason?: RejectionReason;
}

export interface JournalRecordInput {
  inputSeq: number;
  field: StableFieldKey;
  value: string;
  selectionStart?: number;
  selectionEnd?: number;
  timestampMs?: number;
  isSubmitAction?: boolean;
}

export interface EncryptedJournalRecord {
  inputSeq: number;
  fieldKeyCanonical: string;
  origin: string;
  formId: string;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  createdAtMs: number;
}

export interface ReplayedInputEntry {
  inputSeq: number;
  field: StableFieldKey;
  value: string;
  selectionStart: number;
  selectionEnd: number;
  timestampMs: number;
}

export interface RecordJournalOutcome {
  recorded: boolean;
  reason?: RejectionReason;
}

const SENSITIVE_AUTOCOMPLETE_PASSWORD = new Set(["current-password", "new-password"]);
const SENSITIVE_AUTOCOMPLETE_CREDENTIAL = new Set(["username", "webauthn"]);
const SENSITIVE_AUTOCOMPLETE_OTP = new Set(["one-time-code"]);
const SENSITIVE_INPUT_TYPES = new Set(["hidden", "file"]);
const SUBMIT_INPUT_TYPES = new Set(["submit", "button", "image", "reset"]);

const PASSWORD_IDENT_RE =
  /(?:^|[^a-z0-9])(password|passwd|passphrase|passcode|pwd|pin)(?:[^a-z0-9]|$)/i;
const CREDENTIAL_IDENT_RE =
  /(?:^|[^a-z0-9])(credential|secret|token|csrf|xsrf|apikey|api_key|access_key|private_key|bearer|ssn|social_security|auth_key)(?:[^a-z0-9]|$)/i;
const CARD_IDENT_RE =
  /(?:^|[^a-z0-9])(cardnumber|card_number|ccnumber|cc_number|ccnum|cvv|cvc|csc|ccv|iban|creditcard|credit_card|debit_card|card_exp|expiry|exp_date|expdate|pan)(?:[^a-z0-9]|$)/i;
const OTP_IDENT_RE =
  /(?:^|[^a-z0-9])(otp|totp|mfa|2fa|twofactor|two_factor|one_time_code|verification_code|authcode|sms_code)(?:[^a-z0-9]|$)/i;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function asBufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (
    bytes.buffer instanceof ArrayBuffer &&
    bytes.byteOffset === 0 &&
    bytes.byteLength === bytes.buffer.byteLength
  ) {
    return bytes as Uint8Array<ArrayBuffer>;
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function classifyAutocompleteTokens(autocompleteRaw: string): RejectionReason | null {
  const tokens = autocompleteRaw.toLowerCase().trim().split(/\s+/);
  for (const tok of tokens) {
    if (!tok) continue;
    if (SENSITIVE_AUTOCOMPLETE_PASSWORD.has(tok)) return "password-field";
    if (SENSITIVE_AUTOCOMPLETE_CREDENTIAL.has(tok)) return "credential-field";
    if (SENSITIVE_AUTOCOMPLETE_OTP.has(tok)) return "otp-field";
    if (tok.startsWith("cc-")) return "payment-card-field";
  }
  return null;
}

function classifyIdentifiers(field: StableFieldKey): RejectionReason | null {
  const joined = [field.fieldName ?? "", field.fieldId ?? "", field.domPath ?? ""].join(" ");
  if (PASSWORD_IDENT_RE.test(joined)) return "password-field";
  if (OTP_IDENT_RE.test(joined)) return "otp-field";
  if (CARD_IDENT_RE.test(joined)) return "payment-card-field";
  if (CREDENTIAL_IDENT_RE.test(joined)) return "credential-field";
  return null;
}

export function classifyFieldSensitivity(field: StableFieldKey): FieldSensitivityResult {
  const inputType = (field.inputType ?? "").trim().toLowerCase();
  if (inputType === "password") return { sensitive: true, reason: "password-field" };
  if (SUBMIT_INPUT_TYPES.has(inputType)) {
    return { sensitive: true, reason: "submit-action-excluded" };
  }
  if (SENSITIVE_INPUT_TYPES.has(inputType)) {
    return { sensitive: true, reason: "hidden-or-file-field" };
  }
  if (field.autocomplete) {
    const autoReason = classifyAutocompleteTokens(field.autocomplete);
    if (autoReason) return { sensitive: true, reason: autoReason };
  }
  const identReason = classifyIdentifiers(field);
  if (identReason) return { sensitive: true, reason: identReason };
  return { sensitive: false };
}

export function matchesStableFieldKey(
  expected: StableFieldKey,
  candidate: StableFieldKey,
): boolean {
  if (classifyFieldSensitivity(expected).sensitive) return false;
  if (classifyFieldSensitivity(candidate).sensitive) return false;
  if (expected.origin !== candidate.origin) return false;
  if (expected.tagName.toUpperCase() !== candidate.tagName.toUpperCase()) return false;
  if ((expected.inputType ?? "").toLowerCase() !== (candidate.inputType ?? "").toLowerCase()) {
    return false;
  }
  if (expected.formId && candidate.formId !== expected.formId) return false;
  if (expected.formAction && candidate.formAction && candidate.formAction !== expected.formAction) {
    return false;
  }
  if (expected.fieldId && candidate.fieldId && expected.fieldId !== candidate.fieldId) {
    return false;
  }
  if (expected.fieldName && candidate.fieldName && expected.fieldName !== candidate.fieldName) {
    return false;
  }
  if (expected.domPath && candidate.domPath && expected.domPath === candidate.domPath) return true;
  if (expected.fieldId && candidate.fieldId === expected.fieldId) return true;
  if (expected.fieldName && candidate.fieldName === expected.fieldName) return true;
  const noStableTextKeys = !expected.domPath && !expected.fieldId && !expected.fieldName;
  return noStableTextKeys && expected.nodeId !== undefined && candidate.nodeId === expected.nodeId;
}

export function canonicalFieldKey(field: StableFieldKey): string {
  return JSON.stringify([
    field.origin,
    field.formId ?? "",
    field.formAction ?? "",
    field.tagName.toUpperCase(),
    (field.inputType ?? "").toLowerCase(),
    field.fieldName ?? "",
    field.fieldId ?? "",
    field.domPath ?? "",
  ]);
}

function buildAadBytes(
  origin: string,
  inputSeq: number,
  fieldKeyCanonical: string,
): Uint8Array<ArrayBuffer> {
  return asBufferSource(
    textEncoder.encode(`KSV2_JOURNAL_V1|${origin}|${inputSeq}|${fieldKeyCanonical}`),
  );
}

function wipeRecordBuffers(record: EncryptedJournalRecord): void {
  record.iv.fill(0);
  record.ciphertext.fill(0);
}

function expectSymmetricAesKey(generated: CryptoKey | CryptoKeyPair): CryptoKey {
  if ("privateKey" in generated) {
    throw new Error("Expected symmetric AES-256-GCM CryptoKey");
  }
  return generated;
}

interface SerializedPayload {
  inputSeq: number;
  field: StableFieldKey;
  value: string;
  selectionStart: number;
  selectionEnd: number;
  timestampMs: number;
}

export class ClientInputJournal {
  private key: CryptoKey | null;
  private readonly records: Map<string, EncryptedJournalRecord> = new Map();

  private constructor(key: CryptoKey | null) {
    this.key = key;
  }

  static async create(rawKeyBytes?: Uint8Array): Promise<ClientInputJournal> {
    if (rawKeyBytes) {
      if (rawKeyBytes.byteLength !== 32) {
        throw new Error(`AES-256-GCM requires 32-byte key, got ${rawKeyBytes.byteLength}`);
      }
      const key = await crypto.subtle.importKey(
        "raw",
        asBufferSource(rawKeyBytes),
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
      return new ClientInputJournal(key);
    }
    const generated = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    return new ClientInputJournal(expectSymmetricAesKey(generated));
  }

  private entryMapKey(inputSeq: number, fieldKeyCanonical: string): string {
    return `${inputSeq}\u0000${fieldKeyCanonical}`;
  }

  private async ensureKey(): Promise<CryptoKey> {
    if (!this.key) {
      const generated = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
        "encrypt",
        "decrypt",
      ]);
      this.key = expectSymmetricAesKey(generated);
    }
    return this.key;
  }

  async recordInput(input: JournalRecordInput): Promise<RecordJournalOutcome> {
    if (input.isSubmitAction) {
      return { recorded: false, reason: "submit-action-excluded" };
    }
    if (!Number.isInteger(input.inputSeq) || input.inputSeq < 0) {
      return { recorded: false, reason: "invalid-sequence" };
    }
    const sensitivity = classifyFieldSensitivity(input.field);
    if (sensitivity.sensitive) {
      return { recorded: false, reason: sensitivity.reason };
    }
    const fieldKeyCanonical = canonicalFieldKey(input.field);
    const mapKey = this.entryMapKey(input.inputSeq, fieldKeyCanonical);
    const existing = this.records.get(mapKey);
    if (existing) {
      wipeRecordBuffers(existing);
      this.records.delete(mapKey);
    }

    const key = await this.ensureKey();
    const iv = asBufferSource(new Uint8Array(12));
    crypto.getRandomValues(iv);
    const payload: SerializedPayload = {
      inputSeq: input.inputSeq,
      field: input.field,
      value: input.value,
      selectionStart: input.selectionStart ?? input.value.length,
      selectionEnd: input.selectionEnd ?? input.value.length,
      timestampMs: input.timestampMs ?? Date.now(),
    };
    const plaintext = asBufferSource(textEncoder.encode(JSON.stringify(payload)));
    const additionalData = buildAadBytes(input.field.origin, input.inputSeq, fieldKeyCanonical);
    try {
      const cipherBuf = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData, tagLength: 128 },
        key,
        plaintext,
      );
      this.records.set(mapKey, {
        inputSeq: input.inputSeq,
        fieldKeyCanonical,
        origin: input.field.origin,
        formId: input.field.formId ?? "",
        iv: new Uint8Array(iv),
        ciphertext: new Uint8Array(cipherBuf),
        createdAtMs: payload.timestampMs,
      });
    } finally {
      plaintext.fill(0);
    }
    return { recorded: true };
  }

  acknowledgeServerSeq(ackedInputSeq: number): number {
    let removed = 0;
    for (const [mapKey, rec] of this.records) {
      if (rec.inputSeq <= ackedInputSeq) {
        wipeRecordBuffers(rec);
        this.records.delete(mapKey);
        removed++;
      }
    }
    return removed;
  }

  async replayUnacked(targetOrigin: string): Promise<ReplayedInputEntry[]> {
    return this.decryptEntries(targetOrigin);
  }

  async replayDeltaAfter(
    targetOrigin: string,
    checkpointSeq: number,
  ): Promise<ReplayedInputEntry[]> {
    return this.decryptEntries(targetOrigin, checkpointSeq);
  }

  private async decryptEntries(
    targetOrigin: string,
    minExclusiveSeq?: number,
  ): Promise<ReplayedInputEntry[]> {
    const key = this.key;
    if (!key) return [];
    const candidates = Array.from(this.records.values())
      .filter(
        (r) =>
          r.origin === targetOrigin &&
          (minExclusiveSeq === undefined || r.inputSeq > minExclusiveSeq),
      )
      .sort((a, b) => a.inputSeq - b.inputSeq);

    const out: ReplayedInputEntry[] = [];
    for (const rec of candidates) {
      const additionalData = buildAadBytes(rec.origin, rec.inputSeq, rec.fieldKeyCanonical);
      const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: asBufferSource(rec.iv), additionalData, tagLength: 128 },
        key,
        asBufferSource(rec.ciphertext),
      );
      const plainBytes = new Uint8Array(plainBuf);
      try {
        const parsed = JSON.parse(textDecoder.decode(plainBytes)) as SerializedPayload;
        if (parsed.inputSeq !== rec.inputSeq) {
          throw new Error("Decrypted journal inputSeq mismatch");
        }
        if (canonicalFieldKey(parsed.field) !== rec.fieldKeyCanonical) {
          throw new Error("Decrypted journal fieldKey mismatch");
        }
        if (classifyFieldSensitivity(parsed.field).sensitive) continue;
        out.push({
          inputSeq: parsed.inputSeq,
          field: parsed.field,
          value: parsed.value,
          selectionStart: parsed.selectionStart,
          selectionEnd: parsed.selectionEnd,
          timestampMs: parsed.timestampMs,
        });
      } finally {
        plainBytes.fill(0);
      }
    }
    return out;
  }

  encryptedSnapshot(): EncryptedJournalRecord[] {
    return Array.from(this.records.values());
  }

  clearOnSubmit(scope?: { origin?: string; formId?: string }): number {
    let cleared = 0;
    for (const [mapKey, rec] of this.records) {
      const originMatch = scope?.origin === undefined || rec.origin === scope.origin;
      const formMatch = scope?.formId === undefined || rec.formId === scope.formId;
      if (originMatch && formMatch) {
        wipeRecordBuffers(rec);
        this.records.delete(mapKey);
        cleared++;
      }
    }
    return cleared;
  }

  clearOnNavigation(rotateKey = true): number {
    const cleared = this.records.size;
    for (const rec of this.records.values()) {
      wipeRecordBuffers(rec);
    }
    this.records.clear();
    if (rotateKey) this.key = null;
    return cleared;
  }

  size(): number {
    return this.records.size;
  }
}
