// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Indexes raw Wasm bytes alongside their compiled WebAssembly.Module for child transfer.

const bundledWasmBytes = new WeakMap<WebAssembly.Module, Uint8Array>();

export function registerBundledWasmBytes(mod: WebAssembly.Module, bytes: Uint8Array): void {
  bundledWasmBytes.set(mod, bytes);
}

export function getBundledWasmBytes(mod: WebAssembly.Module): Uint8Array | undefined {
  return bundledWasmBytes.get(mod);
}
