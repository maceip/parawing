// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Browser-worker stub for Vivari's headless-test-only `node:module` import in `wasi-net.js`.

/** @returns {() => never} */
export function createRequire() {
  return () => {
    throw new Error("node:module createRequire is unused inside browser Web Workers");
  };
}

export default { createRequire };
