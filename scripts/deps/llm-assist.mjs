// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Optional embedded (local GGUF/llama-cli or loopback server) and remote LLM triage assistant.
// Strictly advisory: never relied upon for pass/fail gates, waivers, or patch verification.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";

const SYSTEM_PROMPT =
  "You are a dependency security and patch reviewer for Parawing. " +
  "Respond ONLY with a JSON object matching " +
  '{"summary":string,"reachability":string,"recommendedAction":string,"candidatePatchPlan":string}. ' +
  "Stick strictly to empirical facts in the prompt.";

function extractJsonObject(rawText) {
  if (typeof rawText !== "string") return null;
  const start = rawText.indexOf("{");
  const end = rawText.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    const parsed = JSON.parse(rawText.slice(start, end + 1));
    if (
      typeof parsed.summary !== "string" ||
      typeof parsed.reachability !== "string" ||
      typeof parsed.recommendedAction !== "string"
    ) {
      return null;
    }
    return {
      summary: parsed.summary,
      reachability: parsed.reachability,
      recommendedAction: parsed.recommendedAction,
      candidatePatchPlan:
        typeof parsed.candidatePatchPlan === "string" ? parsed.candidatePatchPlan : "",
    };
  } catch {
    return null;
  }
}

function runEmbeddedCli(prompt, env, timeoutMs) {
  const bin = env.PARAWING_DEPS_LLM_BIN || "";
  const modelPath = env.PARAWING_DEPS_LLM_MODEL_PATH || "";
  if (!bin || !modelPath || !existsSync(bin) || !existsSync(modelPath)) {
    return { ok: false, reason: "embedded GGUF CLI/model path not configured" };
  }
  try {
    const fullPrompt = `${SYSTEM_PROMPT}\n\n${prompt}\n`;
    const stdout = execFileSync(
      bin,
      ["-m", modelPath, "--temp", "0", "-n", "512", "--no-display-prompt", "-p", fullPrompt],
      { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] },
    );
    const parsed = extractJsonObject(stdout);
    if (!parsed) return { ok: false, reason: "embedded CLI output did not match JSON schema" };
    return { ok: true, backend: `embedded-cli:${bin}`, analysis: parsed };
  } catch (err) {
    return { ok: false, reason: `embedded CLI failed: ${err.message}` };
  }
}

async function callChatCompletions(url, apiKey, model, prompt, timeoutMs) {
  const headers = { "content-type": "application/json" };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      temperature: 0,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: prompt },
      ],
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  const body = await res.json();
  const content = body?.choices?.[0]?.message?.content ?? body?.message?.content ?? "";
  const parsed = extractJsonObject(content);
  if (!parsed) throw new Error("LLM response did not match required JSON schema");
  return parsed;
}

async function runEmbeddedLoopback(prompt, env, timeoutMs) {
  const url = env.PARAWING_DEPS_EMBEDDED_URL || "http://127.0.0.1:11434/v1/chat/completions";
  const model = env.PARAWING_DEPS_EMBEDDED_MODEL || "";
  if (!model) return { ok: false, reason: "PARAWING_DEPS_EMBEDDED_MODEL not configured" };
  try {
    const analysis = await callChatCompletions(url, "", model, prompt, timeoutMs);
    return { ok: true, backend: `embedded-loopback:${url}`, analysis };
  } catch (err) {
    return { ok: false, reason: `embedded loopback unavailable: ${err.message}` };
  }
}

async function runRemoteEndpoint(prompt, env, timeoutMs) {
  const url = env.PARAWING_DEPS_LLM_URL || "";
  const key = env.PARAWING_DEPS_LLM_KEY || "";
  const model = env.PARAWING_DEPS_LLM_MODEL || "";
  if (!url || !model) {
    return { ok: false, reason: "PARAWING_DEPS_LLM_URL or PARAWING_DEPS_LLM_MODEL not configured" };
  }
  try {
    const analysis = await callChatCompletions(url, key, model, prompt, timeoutMs);
    return { ok: true, backend: `remote:${url}`, analysis };
  } catch (err) {
    return { ok: false, reason: `remote LLM unavailable: ${err.message}` };
  }
}

/** @param {{ mode?: string, prompt: string, env?: Record<string, string | undefined>, timeoutMs?: number }} opts
 * @returns {Promise<{ status: string, reliedUpon: false, authority: "advisory-only", verified: false, backend: string | null, reason?: string, analysis?: any }>} */
export async function runOptionalLlmTriage(opts) {
  const mode = opts.mode || "none";
  const env = opts.env || process.env;
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const base = { reliedUpon: false, authority: "advisory-only", verified: false };
  if (mode === "none") {
    return { ...base, status: "disabled", backend: null, reason: "LLM assist disabled (default)" };
  }
  if (mode === "embedded" || mode === "auto") {
    const cliRes = runEmbeddedCli(opts.prompt, env, timeoutMs);
    if (cliRes.ok) {
      return { ...base, status: "completed", backend: cliRes.backend, analysis: cliRes.analysis };
    }
    const loopRes = await runEmbeddedLoopback(opts.prompt, env, timeoutMs);
    if (loopRes.ok) {
      return { ...base, status: "completed", backend: loopRes.backend, analysis: loopRes.analysis };
    }
    if (mode === "embedded") {
      return {
        ...base,
        status: "unavailable",
        backend: null,
        reason: `${cliRes.reason}; ${loopRes.reason}`,
      };
    }
  }
  if (mode === "remote" || mode === "auto") {
    const remoteRes = await runRemoteEndpoint(opts.prompt, env, timeoutMs);
    if (remoteRes.ok) {
      return {
        ...base,
        status: "completed",
        backend: remoteRes.backend,
        analysis: remoteRes.analysis,
      };
    }
    return { ...base, status: "unavailable", backend: null, reason: remoteRes.reason };
  }
  return { ...base, status: "unavailable", backend: null, reason: `Unknown LLM mode: ${mode}` };
}
