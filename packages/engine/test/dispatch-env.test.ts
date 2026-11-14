// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { describe, expect, it, vi } from "vitest";
import {
  createWorkersCapabilities,
  type WorkersCapabilitiesEnv,
} from "../src/workers-capabilities.ts";
import type { Tracer } from "../src/tracing.ts";

describe("createWorkersCapabilities", () => {
  it("maps env config, limits, assets, web-bot-auth, workerCompat, and tasks", async () => {
    const waited: Promise<unknown>[] = [];
    const customAssets = { fetch: vi.fn(async () => new Response("ok")) };
    const env: WorkersCapabilitiesEnv = {
      FONT_ASSETS: customAssets,
      PARAWING_ENV: "staging",
      PARAWING_VERSION: "1.2.3",
      PARAWING_SIMULATE_PROD_EVAL: "1",
      PARAWING_RESOURCE_DRAIN_QUIET_TURNS: "3",
      PARAWING_LAG_WATCHDOG: "1",
      PARAWING_PAGE_CPU_MS_CAP: "4000",
      PARAWING_PAGE_WALL_MS_CAP: "9000",
      PARAWING_ALLOW_PRIVATE_NETWORK: "1",
      PARAWING_DISABLE_PARTIAL_RASTER: "1",
      PARAWING_INSPECTOR_BASE_URL: "https://inspector.example/",
      PARAWING_INSPECTOR_FALLBACK_URL: "https://fallback.example/",
      PARAWING_OTLP_ENDPOINT: "https://otlp.example/v1/traces",
      PARAWING_TRACE_ALL: "1",
      WEB_BOT_AUTH_JWK: '{"kty":"OKP"}',
      WEB_BOT_AUTH_SIGNATURE_AGENT: "https://agent.example",
    };

    const caps = createWorkersCapabilities(
      env,
      { waitUntil: (promise) => waited.push(promise) },
      { workerCompat: { compatibilityDate: "2026-01-01", compatibilityFlags: ["nodejs_compat"] } },
    );

    expect(caps.assets).toBe(customAssets);
    expect(caps.limits).toEqual({ pageCpuMsCap: 4000, pageWallMsCap: 9000 });
    expect(caps.config).toEqual({
      environment: "staging",
      buildVersion: "1.2.3",
      simulateProdEval: true,
      resourceDrainQuietTurns: "3",
      lagWatchdog: true,
      allowPrivateNetwork: true,
      disablePartialRaster: true,
      inspectorBaseUrl: "https://inspector.example/",
      inspectorFallbackUrl: "https://fallback.example/",
      otlpEndpoint: "https://otlp.example/v1/traces",
      traceAll: true,
      webBotAuth: {
        jwkJson: '{"kty":"OKP"}',
        signatureAgent: "https://agent.example",
      },
      workerCompat: { compatibilityDate: "2026-01-01", compatibilityFlags: ["nodejs_compat"] },
    });
    expect(caps.tracer).toBeUndefined();

    const p = Promise.resolve("done");
    caps.tasks.run(p);
    expect(waited).toEqual([p]);
  });

  it("preserves literal undefined tracer when HOST_TRACER is absent and forwards it when set", () => {
    const absent = createWorkersCapabilities({}, { waitUntil: () => {} });
    expect(absent.tracer).toBeUndefined();
    expect(Object.is(absent.tracer, undefined)).toBe(true);

    const fakeTracer: Tracer = {
      enterSpan: (name, span, ...args) =>
        span(
          {
            addLogs: () => {},
            end: () => {},
            setTags: () => {},
            isRecording: false,
          },
          ...args,
        ),
      getSpanContext: () => null,
      runWithSpanContext: (_spanContext, callback, ...args) => callback(...args),
    };
    const present = createWorkersCapabilities({ HOST_TRACER: fakeTracer }, { waitUntil: () => {} });
    expect(present.tracer).toBe(fakeTracer);
  });

  it("ignores non-positive ms caps and exposes valid HOST_CLOCK monotonic clock", () => {
    const monotonic = { timeOrigin: 1000, now: () => 42 };
    const caps = createWorkersCapabilities(
      {
        PARAWING_PAGE_CPU_MS_CAP: "0",
        PARAWING_PAGE_WALL_MS_CAP: "-5",
        HOST_CLOCK: monotonic,
      },
      { waitUntil: () => {} },
    );

    expect(caps.limits).toEqual({ pageCpuMsCap: null, pageWallMsCap: null });
    expect(caps.clock.monotonic).toBe(monotonic);
    expect(caps.clock.now()).toBe(1042);
  });
});
