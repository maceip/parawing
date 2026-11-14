// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Cloudflare Workers HostIsolateLoader backed by env.LOADER and ctx.exports bindings.

import { attributionTails, type AttributionTailExports } from "./eval/attribution-tail.ts";
import type { OutboundProps } from "./eval/outbound.ts";
import type { HostCapabilities } from "./host-capabilities.ts";
import type {
  HostIsolateLoader,
  IsolateLoadSpec,
  IsolateModule,
  LoadedIsolate,
} from "./isolate-loader.ts";
import type { SpanContext } from "./tracing.ts";

export interface WorkersIsolateLoaderEnv {
  LOADER: WorkerLoader;
}

type WorkersExports = AttributionTailExports & {
  SandboxOutbound(opts: { props: OutboundProps }): Fetcher;
  DeniedOutbound(opts: Record<string, never>): Fetcher;
  PageScriptTail(opts: {
    props: {
      scriptName: string;
      pageDomain?: string;
      ksErrToken?: string;
      sessionId?: string;
    };
  }): Fetcher;
  SpanSink(opts: {
    props: {
      kind: string;
      localTraceParent?: SpanContext;
    };
  }): unknown;
};

function toArrayBuffer(bytes: Uint8Array | ArrayBuffer): ArrayBuffer {
  if (bytes instanceof ArrayBuffer) return bytes;
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

function toWorkerModule(mod: IsolateModule): string | WorkerLoaderModule {
  if (typeof mod === "string") return mod;
  if ("js" in mod) return { js: mod.js };
  if ("cjs" in mod) return { cjs: mod.cjs };
  if ("json" in mod) return { json: mod.json };
  if ("wasm" in mod) return { wasm: mod.wasm };
  if ("text" in mod) return { text: mod.text };
  return { data: toArrayBuffer(mod.data) };
}

function toWorkerModules(
  modules: Record<string, IsolateModule>,
): Record<string, string | WorkerLoaderModule> {
  const out: Record<string, string | WorkerLoaderModule> = {};
  for (const [name, mod] of Object.entries(modules)) {
    out[name] = toWorkerModule(mod);
  }
  return out;
}

/** Creates a HostIsolateLoader that instantiates dynamic Cloudflare Workers via env.LOADER. */
export function createWorkersIsolateLoader(
  env: WorkersIsolateLoaderEnv,
  ctx: Pick<ExecutionContext, "exports">,
  capabilities: HostCapabilities,
): HostIsolateLoader {
  // Embedders may attach optional AttributionTail alongside the engine's exports on ctx.exports.
  const exports = ctx.exports as Cloudflare.Exports & AttributionTailExports;
  const loaderExports: WorkersExports = exports;

  return {
    load<T = unknown>(spec: IsolateLoadSpec): LoadedIsolate<T> {
      const globalOutbound =
        spec.outbound.mode === "denied"
          ? loaderExports.DeniedOutbound({})
          : loaderExports.SandboxOutbound({ props: spec.outbound.props as OutboundProps });

      const tails: Fetcher[] = [];
      if (spec.tail) {
        tails.push(loaderExports.PageScriptTail({ props: spec.tail }));
        if (spec.attributionHeaders) {
          const attrName = spec.attributionScriptName ?? spec.tail.scriptName;
          tails.push(...attributionTails(loaderExports, spec.attributionHeaders, attrName));
        }
      }

      const workerEnv: Record<string, unknown> = { ...(spec.env ?? {}) };
      if (spec.spanSink && capabilities.tracer) {
        workerEnv.KS_SPAN_SINK = loaderExports.SpanSink({
          props: {
            kind: spec.spanSink.kind,
            ...(spec.spanSink.localTraceParent
              ? { localTraceParent: spec.spanSink.localTraceParent }
              : {}),
          },
        });
      }

      const compat = capabilities.config.workerCompat;
      const compatibilityDate = compat?.compatibilityDate ?? spec.compatibilityDate;
      const compatibilityFlags = [...(compat?.compatibilityFlags ?? spec.compatibilityFlags)];

      const code: WorkerLoaderWorkerCode = {
        compatibilityDate,
        compatibilityFlags,
        mainModule: spec.mainModule,
        modules: toWorkerModules(spec.modules),
        env: workerEnv,
        globalOutbound,
        ...(tails.length > 0 ? { tails } : {}),
        ...(spec.limits ? { limits: spec.limits } : {}),
      };

      const stub = env.LOADER.load(code);
      const entrypoint = (
        spec.entrypointProps !== undefined
          ? stub.getEntrypoint(spec.entrypoint, { props: spec.entrypointProps })
          : stub.getEntrypoint(spec.entrypoint)
      ) as T;

      let terminated = false;
      return {
        kind: spec.kind,
        entrypoint,
        async terminate(reason = "isolate terminated"): Promise<void> {
          if (terminated) return;
          terminated = true;
          const candidate = entrypoint as { killIsolate?: (reason?: string) => unknown } | null;
          if (candidate && typeof candidate.killIsolate === "function") {
            try {
              await Promise.resolve(candidate.killIsolate(reason));
            } catch {}
          }
        },
        [Symbol.dispose](): void {
          const disposable = entrypoint as { [Symbol.dispose]?: () => void } | null;
          try {
            disposable?.[Symbol.dispose]?.();
          } catch {}
        },
      };
    },
  };
}
