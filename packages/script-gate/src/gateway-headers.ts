// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Defines gateway headers that carry nosniff and CORS results across the isolate boundary.

export const PARAWING_NOSNIFF_HEADER = "x-parawing-nosniff";

export const PARAWING_CORS_VERDICT_HEADER = "x-parawing-cors";

export function responseIsOpaque(corsVerdict: string | null): boolean {
  return corsVerdict !== "clean";
}
