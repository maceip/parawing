// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Cloudflare Workers API compatibility shim for standalone Node/Deno execution.

import { markRpcTarget } from "@parawing/rpc-transport";

export interface WorkerCompatContext<TProps = unknown> {
  readonly props: TProps;
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

type AbortIsolateHandler = (reason: string) => never;

let abortHandler: AbortIsolateHandler | null = null;

export function setAbortIsolateHandler(handler: AbortIsolateHandler): void {
  abortHandler = handler;
}

export class RpcTarget {
  constructor() {
    markRpcTarget(this);
  }
}

markRpcTarget(RpcTarget.prototype);

export class WorkerEntrypoint<TEnv = unknown, TProps = unknown> {
  protected readonly ctx: WorkerCompatContext<TProps>;
  protected readonly env: TEnv;

  constructor(ctx: WorkerCompatContext<TProps>, env: TEnv) {
    this.ctx = ctx;
    this.env = env;
  }
}

export function abortIsolate(reason = "isolate aborted"): never {
  if (abortHandler) {
    return abortHandler(reason);
  }
  throw new Error(reason);
}
