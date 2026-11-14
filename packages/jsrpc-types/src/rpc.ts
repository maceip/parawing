// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Host-neutral RPC branding and stub helper types without @cloudflare/workers-types coupling.

export type RpcTargetBrand = "__RPC_TARGET_BRAND";

export interface RpcTargetBranded {
  ["__RPC_TARGET_BRAND"]: never;
}

export interface WorkerEntrypointBranded {
  ["__WORKER_ENTRYPOINT_BRAND"]: never;
}

export interface DisposableStub {
  [Symbol.dispose](): void;
  dup?(): this;
}

export type AsyncMethod<F> = F extends (...args: infer Args) => infer R
  ? (
      ...args: Args
    ) => Promise<Awaited<R> extends RpcTargetBranded ? RpcStub<Awaited<R>> : Awaited<R>>
  : F;

export type RpcStub<T> = (T extends (...args: infer Args) => infer R
  ? (
      ...args: Args
    ) => Promise<Awaited<R> extends RpcTargetBranded ? RpcStub<Awaited<R>> : Awaited<R>>
  : { [K in Exclude<keyof T, symbol | RpcTargetBrand>]: AsyncMethod<T[K]> }) &
  DisposableStub;

export type RemoteFetcher<T> = {
  [K in Exclude<keyof T, symbol | "__WORKER_ENTRYPOINT_BRAND" | "fetch" | "connect">]: AsyncMethod<
    T[K]
  >;
} & {
  [Symbol.dispose]?(): void;
  dup?(): RemoteFetcher<T>;
};
