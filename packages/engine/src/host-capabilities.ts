// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Host capability contracts decouple the engine core from Cloudflare Workers globals.

import type { Tracer } from "./tracing.ts";

export interface AssetCapability {
  fetch(request: Request): Promise<Response>;
}

export interface TaskCapability {
  run(promise: Promise<unknown>): void;
}

export interface ClockCapability {
  /** Wall-clock epoch milliseconds (Date.now() or HOST_CLOCK epoch time). */
  now(): number;
  /** Optional monotonic clock for performance spans when supplied by the host. */
  monotonic?: {
    readonly timeOrigin: number;
    now(): number;
  };
}

export interface LimitsCapability {
  /** Per-page-isolate CPU budget in milliseconds, or null to use the engine default. */
  pageCpuMsCap: number | null;
  /** Per-generation wall-clock kill budget in milliseconds, or null when uncapped. */
  pageWallMsCap: number | null;
}

export interface WebBotAuthConfig {
  jwkJson?: string;
  signatureAgent?: string;
}

export interface WorkerCompatConfig {
  compatibilityDate: string;
  compatibilityFlags: readonly string[];
}

export interface ConfigCapability {
  environment: string;
  buildVersion: string;
  simulateProdEval: boolean;
  resourceDrainQuietTurns: string | undefined;
  lagWatchdog: boolean;
  allowPrivateNetwork: boolean;
  disablePartialRaster: boolean;
  inspectorBaseUrl?: string;
  inspectorFallbackUrl?: string;
  otlpEndpoint?: string;
  traceAll?: boolean;
  webBotAuth?: WebBotAuthConfig;
  workerCompat?: WorkerCompatConfig;
}

export interface HostCapabilities {
  assets: AssetCapability;
  tasks: TaskCapability;
  clock: ClockCapability;
  limits: LimitsCapability;
  config: ConfigCapability;
  /** Tracer hook; must be literal undefined (never a Proxy) when tracing is inactive. */
  tracer: Tracer | undefined;
}

export interface MemoryHostCapabilitiesOptions {
  assets?: AssetCapability;
  tasks?: TaskCapability;
  clock?: ClockCapability;
  limits?: Partial<LimitsCapability>;
  config?: Partial<ConfigCapability>;
  tracer?: Tracer | undefined;
}

/** Parses an optional positive integer millisecond budget; returns null when unset or invalid. */
export function parsePositiveMsCap(raw: string | undefined): number | null {
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : null;
}

/** Builds an in-memory HostCapabilities instance for embedded hosts and unit tests. */
export function createMemoryHostCapabilities(
  options: MemoryHostCapabilitiesOptions = {},
): HostCapabilities {
  const defaultAssets: AssetCapability = {
    fetch: async () => new Response("Not Found", { status: 404 }),
  };
  const defaultTasks: TaskCapability = {
    run: (promise: Promise<unknown>) => {
      void promise.catch(() => {});
    },
  };
  const defaultClock: ClockCapability = {
    now: () => Date.now(),
  };
  return {
    assets: options.assets ?? defaultAssets,
    tasks: options.tasks ?? defaultTasks,
    clock: options.clock ?? defaultClock,
    limits: {
      pageCpuMsCap: options.limits?.pageCpuMsCap ?? null,
      pageWallMsCap: options.limits?.pageWallMsCap ?? null,
    },
    config: {
      environment: options.config?.environment ?? "",
      buildVersion: options.config?.buildVersion ?? "",
      simulateProdEval: options.config?.simulateProdEval ?? false,
      resourceDrainQuietTurns: options.config?.resourceDrainQuietTurns,
      lagWatchdog: options.config?.lagWatchdog ?? false,
      allowPrivateNetwork: options.config?.allowPrivateNetwork ?? false,
      disablePartialRaster: options.config?.disablePartialRaster ?? false,
      inspectorBaseUrl: options.config?.inspectorBaseUrl,
      inspectorFallbackUrl: options.config?.inspectorFallbackUrl,
      otlpEndpoint: options.config?.otlpEndpoint,
      traceAll: options.config?.traceAll,
      webBotAuth: options.config?.webBotAuth,
      workerCompat: options.config?.workerCompat,
    },
    tracer: options.tracer,
  };
}
