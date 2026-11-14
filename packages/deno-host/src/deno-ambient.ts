// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Ambient Deno runtime surface for TypeScript without `.d.ts` files (`//:no_dts_test`).

export interface DenoRuntime {
  readonly stdin: {
    readonly readable: ReadableStream<Uint8Array>;
  };
  readonly stdout: {
    readonly writable: WritableStream<Uint8Array>;
  };
  readonly stderr: {
    writeSync(p: Uint8Array): number;
  };
  exit(code?: number): never;
}

declare global {
  var Deno: DenoRuntime | undefined;
}
