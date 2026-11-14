// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Cloudflare Workers implementation of HostCapabilities backed by Env and ExecutionContext.

import { isHostClock, makeWallClock, type HostClock } from "./eval/host-clock.ts";
import {
  type AssetCapability,
  type HostCapabilities,
  type WorkerCompatConfig,
  parsePositiveMsCap,
} from "./host-capabilities.ts";
import type { Tracer } from "./tracing.ts";

export interface WorkersCapabilitiesEnv {
  FONT_ASSETS?: AssetCapability;
  HOST_TRACER?: Tracer;
  HOST_CLOCK?: HostClock;
  PARAWING_ENV?: string;
  PARAWING_VERSION?: string;
  PARAWING_SIMULATE_PROD_EVAL?: string;
  PARAWING_RESOURCE_DRAIN_QUIET_TURNS?: string;
  PARAWING_LAG_WATCHDOG?: string;
  PARAWING_PAGE_CPU_MS_CAP?: string;
  PARAWING_PAGE_WALL_MS_CAP?: string;
  PARAWING_ALLOW_PRIVATE_NETWORK?: string;
  PARAWING_DISABLE_PARTIAL_RASTER?: string;
  PARAWING_INSPECTOR_BASE_URL?: unknown;
  PARAWING_INSPECTOR_FALLBACK_URL?: unknown;
  PARAWING_OTLP_ENDPOINT?: string;
  PARAWING_TRACE_ALL?: string;
  WEB_BOT_AUTH_JWK?: string;
  WEB_BOT_AUTH_SIGNATURE_AGENT?: string;
}

export interface WorkersCapabilitiesOptions {
  workerCompat?: WorkerCompatConfig;
}

/** Builds HostCapabilities backed by Cloudflare Workers Env and ExecutionContext. */
export function createWorkersCapabilities(
  env: WorkersCapabilitiesEnv,
  ctx: Pick<ExecutionContext, "waitUntil">,
  options: WorkersCapabilitiesOptions = {},
): HostCapabilities {
  const defaultAssets: AssetCapability = {
    fetch: async () => new Response("Not Found", { status: 404 }),
  };
  const wallNow = makeWallClock(env);
  const monotonic = isHostClock(env.HOST_CLOCK) ? env.HOST_CLOCK : undefined;
  const webBotAuth =
    env.WEB_BOT_AUTH_JWK !== undefined || env.WEB_BOT_AUTH_SIGNATURE_AGENT !== undefined
      ? {
          jwkJson: env.WEB_BOT_AUTH_JWK,
          signatureAgent: env.WEB_BOT_AUTH_SIGNATURE_AGENT,
        }
      : undefined;
  return {
    assets: env.FONT_ASSETS ?? defaultAssets,
    tasks: {
      run: (promise: Promise<unknown>) => ctx.waitUntil(promise),
    },
    clock: {
      now: wallNow,
      ...(monotonic ? { monotonic } : {}),
    },
    limits: {
      pageCpuMsCap: parsePositiveMsCap(env.PARAWING_PAGE_CPU_MS_CAP),
      pageWallMsCap: parsePositiveMsCap(env.PARAWING_PAGE_WALL_MS_CAP),
    },
    config: {
      environment: env.PARAWING_ENV ?? "",
      buildVersion: env.PARAWING_VERSION ?? "",
      simulateProdEval: env.PARAWING_SIMULATE_PROD_EVAL === "1",
      resourceDrainQuietTurns: env.PARAWING_RESOURCE_DRAIN_QUIET_TURNS,
      lagWatchdog: env.PARAWING_LAG_WATCHDOG === "1",
      allowPrivateNetwork: env.PARAWING_ALLOW_PRIVATE_NETWORK === "1",
      disablePartialRaster: env.PARAWING_DISABLE_PARTIAL_RASTER === "1",
      inspectorBaseUrl:
        typeof env.PARAWING_INSPECTOR_BASE_URL === "string"
          ? env.PARAWING_INSPECTOR_BASE_URL
          : undefined,
      inspectorFallbackUrl:
        typeof env.PARAWING_INSPECTOR_FALLBACK_URL === "string"
          ? env.PARAWING_INSPECTOR_FALLBACK_URL
          : undefined,
      otlpEndpoint: env.PARAWING_OTLP_ENDPOINT,
      traceAll: env.PARAWING_TRACE_ALL === "1",
      webBotAuth,
      workerCompat: options.workerCompat,
    },
    // Preserve literal undefined when HOST_TRACER is absent (never wrap with a Proxy).
    tracer: env.HOST_TRACER,
  };
}
