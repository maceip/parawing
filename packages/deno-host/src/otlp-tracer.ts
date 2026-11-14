// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Host Tracer implementation exporting OpenTelemetry JSON spans over OTLP/HTTP.

import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import type { Span, SpanContext, SpanTags, Tracer } from "@parawing/engine/tracing";

export interface OtlpHttpTracerOptions {
  endpoint?: string;
  serviceName?: string;
  scopeName?: string;
  flushDelayMs?: number;
  exportTimeoutMs?: number;
  fetchFn?: typeof globalThis.fetch;
}

type OtlpValue = { stringValue: string } | { boolValue: boolean } | { doubleValue: number };

interface OtlpAttribute {
  key: string;
  value: OtlpValue;
}

interface OtlpEvent {
  timeUnixNano: string;
  name: string;
  attributes: OtlpAttribute[];
}

export interface RecordedOtlpSpan {
  traceId: string;
  spanId: string;
  parentSpanId: string;
  name: string;
  kind: 1;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtlpAttribute[];
  events: OtlpEvent[];
}

const DEFAULT_SERVICE_NAME = "parawing-deno-host";
const DEFAULT_SCOPE_NAME = "parawing-engine";
const DEFAULT_FLUSH_DELAY_MS = 100;
const DEFAULT_EXPORT_TIMEOUT_MS = 5_000;
const NS_PER_MS = 1_000_000n;

function randHex(byteLen: number): string {
  return randomBytes(byteLen).toString("hex");
}

function nowUnixNano(): string {
  return (BigInt(Date.now()) * NS_PER_MS).toString();
}

function toOtlpValue(value: SpanTags[string]): OtlpValue {
  if (typeof value === "boolean") return { boolValue: value };
  if (typeof value === "number") return { doubleValue: Number.isFinite(value) ? value : 0 };
  return { stringValue: value };
}

function toAttributes(tags: SpanTags): OtlpAttribute[] {
  return Object.entries(tags).map(([key, val]) => ({ key, value: toOtlpValue(val) }));
}

export class OtlpHttpTracer implements Tracer {
  readonly #als = new AsyncLocalStorage<SpanContext | null>();
  readonly #endpoint: string | undefined;
  readonly #serviceName: string;
  readonly #scopeName: string;
  readonly #flushDelayMs: number;
  readonly #exportTimeoutMs: number;
  readonly #fetchFn: typeof globalThis.fetch;
  readonly #queue: RecordedOtlpSpan[] = [];
  #flushTimer: ReturnType<typeof setTimeout> | null = null;
  #inflightFlush: Promise<void> = Promise.resolve();
  #exportedCount = 0;

  constructor(options: OtlpHttpTracerOptions = {}) {
    this.#endpoint = options.endpoint;
    this.#serviceName = options.serviceName ?? DEFAULT_SERVICE_NAME;
    this.#scopeName = options.scopeName ?? DEFAULT_SCOPE_NAME;
    this.#flushDelayMs = options.flushDelayMs ?? DEFAULT_FLUSH_DELAY_MS;
    this.#exportTimeoutMs = options.exportTimeoutMs ?? DEFAULT_EXPORT_TIMEOUT_MS;
    this.#fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  getSpanContext(): SpanContext | null {
    return this.#als.getStore() ?? null;
  }

  runWithSpanContext<T extends unknown[], R = void>(
    spanContext: SpanContext | null,
    callback: (...args: T) => R,
    ...args: T
  ): R {
    return this.#als.run(spanContext, callback, ...args);
  }

  enterSpan<T extends unknown[], R = void>(
    name: string,
    fn: (span: Span, ...args: T) => R,
    ...args: T
  ): R {
    const parent = this.getSpanContext();
    const traceId = parent?.traceId || randHex(16);
    const parentSpanId = parent?.spanId || "";
    const spanId = randHex(8);
    const spanCtx: SpanContext = {
      traceId,
      spanId,
      parentSpanId,
      traceFlags: parent?.traceFlags ?? 1,
    };

    const startTimeUnixNano = nowUnixNano();
    const attrs = new Map<string, OtlpValue>();
    const events: OtlpEvent[] = [];
    let ended = false;

    const finalize = (): void => {
      if (ended) return;
      ended = true;
      const recorded: RecordedOtlpSpan = {
        traceId,
        spanId,
        parentSpanId,
        name,
        kind: 1,
        startTimeUnixNano,
        endTimeUnixNano: nowUnixNano(),
        attributes: [...attrs.entries()].map(([key, value]) => ({ key, value })),
        events,
      };
      this.#enqueue(recorded);
    };

    const span: Span = {
      isRecording: true,
      setTags: (tags: SpanTags): void => {
        if (ended) return;
        for (const [k, v] of Object.entries(tags)) {
          attrs.set(k, toOtlpValue(v));
        }
      },
      addLogs: (logs: SpanTags): void => {
        if (ended) return;
        events.push({
          timeUnixNano: nowUnixNano(),
          name: "log",
          attributes: toAttributes(logs),
        });
      },
      end: finalize,
    };

    return this.#als.run(spanCtx, () => {
      try {
        const result = fn(span, ...args);
        if (result instanceof Promise) {
          return result.finally(finalize) as R;
        }
        finalize();
        return result;
      } catch (err) {
        attrs.set("error", { boolValue: true });
        attrs.set("error.message", {
          stringValue: err instanceof Error ? err.message : String(err),
        });
        finalize();
        throw err;
      }
    });
  }

  pendingSpanCount(): number {
    return this.#queue.length;
  }

  exportedSpanCount(): number {
    return this.#exportedCount;
  }

  async flush(): Promise<void> {
    if (this.#flushTimer) {
      clearTimeout(this.#flushTimer);
      this.#flushTimer = null;
    }
    this.#inflightFlush = this.#inflightFlush.then(() => this.#postBatch());
    await this.#inflightFlush;
  }

  #enqueue(span: RecordedOtlpSpan): void {
    this.#queue.push(span);
    if (!this.#endpoint || this.#flushTimer) return;
    this.#flushTimer = setTimeout(() => {
      this.#flushTimer = null;
      void this.flush();
    }, this.#flushDelayMs);
    this.#flushTimer.unref?.();
  }

  async #postBatch(): Promise<void> {
    if (this.#queue.length === 0) return;
    if (!this.#endpoint) {
      this.#exportedCount += this.#queue.length;
      this.#queue.length = 0;
      return;
    }
    const batch = this.#queue.splice(0, this.#queue.length);
    const payload = {
      resourceSpans: [
        {
          resource: {
            attributes: [{ key: "service.name", value: { stringValue: this.#serviceName } }],
          },
          scopeSpans: [
            {
              scope: { name: this.#scopeName },
              spans: batch,
            },
          ],
        },
      ],
    };
    try {
      const resp = await this.#fetchFn(this.#endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.#exportTimeoutMs),
      });
      await resp.body?.cancel().catch(() => {});
      this.#exportedCount += batch.length;
    } catch {
      // Do not crash request execution if a local collector is temporarily unreachable.
    }
  }
}
