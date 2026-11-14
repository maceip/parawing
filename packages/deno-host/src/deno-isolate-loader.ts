// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Spawns zero-permission Deno subprocesses and bridges PRWP capabilities and watchdogs.

import { spawn, type ChildProcessByStdio } from "node:child_process";
import { existsSync } from "node:fs";
import { Writable, Readable } from "node:stream";
import { createRpcSession, markRpcTarget, type RpcSession } from "@parawing/rpc-transport";
import type { HostCapabilities } from "@parawing/engine/host-capabilities";
import type {
  HostIsolateLoader,
  IsolateLoadSpec,
  IsolateModule,
  LoadedIsolate,
} from "@parawing/engine/isolate-loader";
import type { SessionOutboundRequest } from "@parawing/jsrpc-types/page-script";
import { CHILD_BOOTSTRAP_SOURCE } from "../dist/child-bootstrap.js";
import {
  createSpanSinkTarget,
  dispatchTailEvent,
  invokeSandboxOutbound,
  notifyIsolateLimit,
  traceSpan,
  type TailExceptionEntry,
  type TailLogEntry,
  type TailProps,
} from "../dist/engine-bundle.mjs";

export interface DenoIsolateLoaderOptions {
  denoBin?: string;
  maxOldSpaceSizeMb?: number;
  gracefulDisposeTimeoutMs?: number;
  executionBackend?: "boa" | "v8";
}

const DEFAULT_GRACEFUL_DISPOSE_MS = 250;
const BOOTSTRAP_DATA_URL = `data:text/javascript;base64,${Buffer.from(
  CHILD_BOOTSTRAP_SOURCE,
  "utf8",
).toString("base64")}`;

export function resolveDenoBinary(explicit?: string): string {
  if (explicit && explicit.trim().length > 0) return explicit;
  const fromEnv = process.env["PARAWING_DENO_BIN"];
  if (fromEnv && fromEnv.trim().length > 0) return fromEnv;
  const home = process.env["HOME"];
  if (home) {
    const userDeno = `${home}/.deno/bin/deno`;
    if (existsSync(userDeno)) return userDeno;
  }
  for (const candidate of ["/usr/local/bin/deno", "/opt/homebrew/bin/deno", "/usr/bin/deno"]) {
    if (existsSync(candidate)) return candidate;
  }
  return "deno";
}

function serializeModule(mod: IsolateModule): IsolateModule {
  if (typeof mod === "string") return mod;
  if ("wasm" in mod) {
    return { wasm: mod.wasm instanceof Uint8Array ? mod.wasm : new Uint8Array(mod.wasm) };
  }
  if ("data" in mod) {
    return { data: mod.data instanceof Uint8Array ? mod.data : new Uint8Array(mod.data) };
  }
  return mod;
}

function serializeModules(modules: Record<string, IsolateModule>): Record<string, IsolateModule> {
  const out: Record<string, IsolateModule> = {};
  for (const [key, mod] of Object.entries(modules)) {
    out[key] = serializeModule(mod);
  }
  return out;
}

export function buildDenoRunArgs(maxOldSpaceSizeMb?: number): string[] {
  const v8Flags = ["--disallow-code-generation-from-strings"];
  if (typeof maxOldSpaceSizeMb === "number" && maxOldSpaceSizeMb > 0) {
    v8Flags.push(`--max-old-space-size=${Math.floor(maxOldSpaceSizeMb)}`);
  }
  return [
    "run",
    "--no-prompt",
    "--no-config",
    "--no-lock",
    "--no-code-cache",
    `--v8-flags=${v8Flags.join(",")}`,
    BOOTSTRAP_DATA_URL,
  ];
}

function toSafeStreams(child: ChildProcessByStdio<Writable, Readable, Readable>): {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
} {
  child.stdin.on("error", () => {});
  child.stdout.on("error", () => {});
  const nodeReadable = Readable.toWeb(child.stdout);
  const readable = new ReadableStream<Uint8Array>({
    start(controller): void {
      const reader = nodeReadable.getReader();
      const pump = (): void => {
        reader
          .read()
          .then(({ done, value }) => {
            if (done) {
              try {
                controller.close();
              } catch {}
              return;
            }
            if (value) controller.enqueue(new Uint8Array(value));
            pump();
          })
          .catch(() => {
            try {
              controller.close();
            } catch {}
          });
      };
      pump();
    },
  });
  const nodeWritable = Writable.toWeb(child.stdin);
  const writer = nodeWritable.getWriter();
  const writable = new WritableStream<Uint8Array>({
    async write(chunk): Promise<void> {
      try {
        await writer.write(chunk);
      } catch {}
    },
    async close(): Promise<void> {
      try {
        await writer.close();
      } catch {}
    },
    async abort(reason): Promise<void> {
      try {
        await writer.abort(reason);
      } catch {}
    },
  });
  return { readable, writable };
}

type DuplexRequestInit = RequestInit & { duplex?: "half" };

function buildOutboundHandler(
  host: HostCapabilities,
  props: object,
): (req: SessionOutboundRequest) => Promise<Response> {
  return (req: SessionOutboundRequest): Promise<Response> => {
    const headers = new Headers();
    for (const [k, v] of req.headers) {
      headers.append(k, v);
    }
    const init: DuplexRequestInit = {
      method: req.method,
      headers,
      body: req.body,
      redirect: "manual",
    };
    if (req.body !== null) {
      init.duplex = "half";
    }
    const request = new Request(req.url, init);
    return invokeSandboxOutbound(host, props, request);
  };
}

function buildTailBridge(
  host: HostCapabilities,
  tailProps: TailProps | undefined,
): {
  log(level: string, message: unknown[], timestamp: number): void;
  exception(ex: { name: string; message: string; stack?: string; timestamp: number }): void;
} {
  return markRpcTarget({
    log(level: string, message: unknown[], timestamp: number): void {
      if (!tailProps) return;
      const entry: TailLogEntry = { level, message, timestamp };
      dispatchTailEvent(host, tailProps, {
        logs: [entry],
        exceptions: [],
        outcome: "ok",
        cpuTime: 0,
        wallTime: 0,
      });
    },
    exception(ex: { name: string; message: string; stack?: string; timestamp: number }): void {
      if (!tailProps) return;
      const entry: TailExceptionEntry = {
        timestamp: ex.timestamp,
        name: ex.name,
        message: ex.message,
        ...(ex.stack ? { stack: ex.stack } : {}),
      };
      dispatchTailEvent(host, tailProps, {
        logs: [],
        exceptions: [entry],
        outcome: "exception",
        cpuTime: 0,
        wallTime: 0,
      });
    },
  });
}

export function createDenoIsolateLoader(
  host: HostCapabilities,
  options: DenoIsolateLoaderOptions = {},
): HostIsolateLoader {
  const denoBin = resolveDenoBinary(options.denoBin);
  const gracefulTimeoutMs = options.gracefulDisposeTimeoutMs ?? DEFAULT_GRACEFUL_DISPOSE_MS;

  return {
    load<T = unknown>(spec: IsolateLoadSpec): LoadedIsolate<T> {
      const startedAt = host.clock.now();
      const child = spawn(denoBin, buildDenoRunArgs(options.maxOldSpaceSizeMb), {
        stdio: ["pipe", "pipe", "pipe"],
        env: { DENO_DIR: "/nonexistent-parawing-deno-dir" },
      });

      const { readable, writable } = toSafeStreams(child);
      let stderrTail = "";
      child.stderr.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        stderrTail = (stderrTail + text).slice(-4096);
      });

      const session: RpcSession = createRpcSession({
        readable,
        writable,
        role: "client",
        onError: (err): void => {
          console.debug(`[deno-host] PRWP error (${spec.kind}):`, err.message);
        },
      });

      let exited = false;
      let exitCode: number | null = null;
      let exitSignal: NodeJS.Signals | null = null;
      let killOutcome: string | null = null;
      let resolveExit!: () => void;
      const exitPromise = new Promise<void>((resolve) => {
        resolveExit = resolve;
      });

      let wallTimer: ReturnType<typeof setTimeout> | null = null;
      const clearWatchdogs = (): void => {
        if (wallTimer) {
          clearTimeout(wallTimer);
          wallTimer = null;
        }
      };

      const finalizeClose = (code: number | null, sig: NodeJS.Signals | null): void => {
        if (exited) return;
        exited = true;
        exitCode = exitCode ?? code;
        exitSignal = exitSignal ?? sig;
        clearWatchdogs();
        session.close();
        if (spec.tail && killOutcome) {
          dispatchTailEvent(host, spec.tail, {
            logs: [],
            exceptions: [],
            outcome: killOutcome,
            cpuTime: 0,
            wallTime: Math.max(0, host.clock.now() - startedAt),
          });
        }
        resolveExit();
      };

      child.once("exit", (code, sig) => {
        exitCode = code;
        exitSignal = sig;
        clearWatchdogs();
      });
      child.once("close", (code, sig) => {
        finalizeClose(code, sig);
      });
      child.once("error", (err) => {
        stderrTail = (stderrTail + `\nspawn error: ${err.message}`).slice(-4096);
        finalizeClose(1, null);
      });

      let terminatePromise: Promise<void> | null = null;
      const terminate = (reason = "isolate terminated"): Promise<void> => {
        if (terminatePromise) return terminatePromise;
        terminatePromise = (async (): Promise<void> => {
          clearWatchdogs();
          if (exited) {
            session.close();
            return exitPromise;
          }
          const graceful = session
            .call("__ks_dispose", [])
            .then(() => undefined)
            .catch(() => undefined);
          await Promise.race([
            exitPromise,
            graceful,
            new Promise<void>((r) => setTimeout(r, gracefulTimeoutMs)),
          ]);
          if (!exited) {
            try {
              child.kill("SIGKILL");
            } catch {}
          }
          await exitPromise;
          session.close();
          if (reason && exitSignal && exitCode === null) {
            console.debug(`[deno-host] killed ${spec.kind} (${exitSignal}): ${reason}`);
          }
        })();
        return terminatePromise;
      };

      const wallMs = spec.limits?.wallMs;
      if (typeof wallMs === "number" && wallMs > 0) {
        wallTimer = setTimeout(() => {
          killOutcome = "exceededCpu";
          if (spec.tail?.scriptName) {
            notifyIsolateLimit(spec.tail.scriptName, {
              kind: "wall",
              capMs: wallMs,
            });
          }
          void terminate(`wallMs timeout after ${wallMs}ms`);
        }, wallMs);
        wallTimer.unref?.();
      }

      const initEnv: Record<string, unknown> = { ...(spec.env ?? {}) };
      if (spec.spanSink && host.tracer) {
        initEnv["KS_SPAN_SINK"] = markRpcTarget(createSpanSinkTarget(host, spec.spanSink));
      }

      const payload = {
        kind: spec.kind,
        entrypoint: spec.entrypoint,
        mainModule: spec.mainModule,
        modules: serializeModules(spec.modules),
        networkMode: spec.outbound.mode,
        ...(options.executionBackend ? { executionBackend: options.executionBackend } : {}),
        env: initEnv,
        ...(spec.entrypointProps ? { entrypointProps: spec.entrypointProps } : {}),
        ...(spec.outbound.mode === "sandbox"
          ? { globalOutbound: buildOutboundHandler(host, spec.outbound.props) }
          : {}),
        tailSink: buildTailBridge(host, spec.tail),
      };

      const initPromise = traceSpan(host.tracer, `deno.init.${spec.kind}`, () =>
        session.call("__ks_init_isolate", [payload]),
      );
      void initPromise.catch((err: unknown) => {
        if (!terminatePromise && !exited) {
          console.error(
            `[deno-host] failed to initialize ${spec.kind}:`,
            err instanceof Error ? err.message : String(err),
            stderrTail,
          );
        }
      });

      return {
        kind: spec.kind,
        entrypoint: session.proxy<T & object>(),
        terminate,
        [Symbol.dispose](): void {
          void terminate("disposed");
        },
      };
    },
  };
}
