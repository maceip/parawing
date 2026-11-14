// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Host isolate-loading contract decouples engine eval orchestration from WorkerLoader.

import type { SpanContext } from "./tracing.ts";

export type IsolateKind = "page-script" | "oopif-frame" | "page-renderer" | "dedicated-worker";

export type IsolateModule =
  | string
  | { js: string }
  | { cjs: string }
  | { json: unknown }
  | { wasm: Uint8Array | ArrayBuffer }
  | { text: string }
  | { data: Uint8Array | ArrayBuffer };

export interface IsolateTailSpec {
  scriptName: string;
  pageDomain?: string;
  ksErrToken?: string;
  sessionId?: string;
}

export type IsolateOutboundSpec =
  | {
      mode: "sandbox";
      props: object;
    }
  | {
      mode: "denied";
    };

export interface IsolateLoadSpec {
  kind: IsolateKind;
  /** Entrypoint class exported by the loaded worker bundle. */
  entrypoint: string;
  /** Optional props passed to getEntrypoint(entrypoint, { props }). */
  entrypointProps?: object;
  /** Default compatibility date unless HostCapabilities.config.workerCompat overrides it. */
  compatibilityDate: string;
  /** Default compat flags unless HostCapabilities.config.workerCompat overrides them. */
  compatibilityFlags: readonly string[];
  mainModule: string;
  modules: Record<string, IsolateModule>;
  /** Serializable env values supplied to the isolate. */
  env?: Record<string, unknown>;
  /** Requests a host SpanSink binding (`KS_SPAN_SINK`) when tracing is active. */
  spanSink?: {
    kind: string;
    localTraceParent?: SpanContext;
  };
  limits?: {
    cpuMs?: number;
    wallMs?: number;
    subRequests?: number;
  };
  outbound: IsolateOutboundSpec;
  tail?: IsolateTailSpec;
  attributionHeaders?: Record<string, string>;
  /** Script name passed to AttributionTail when different from tail.scriptName. */
  attributionScriptName?: string;
}

export interface LoadedIsolate<T = unknown> {
  readonly kind: IsolateKind;
  readonly entrypoint: T;
  terminate(reason?: string): Promise<void>;
  [Symbol.dispose](): void;
}

export interface HostIsolateLoader {
  load<T = unknown>(spec: IsolateLoadSpec): LoadedIsolate<T>;
}
