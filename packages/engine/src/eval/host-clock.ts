// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Builds an epoch-millisecond clock from HostCapabilities, HOST_CLOCK, or Date.now.

export interface HostClock {
  timeOrigin: number;
  now(): number;
}

export function isHostClock(value: unknown): value is HostClock {
  if (!value || typeof value !== "object") return false;
  const clock = value as Partial<HostClock>;
  return typeof clock.now === "function" && typeof clock.timeOrigin === "number";
}

type ClockSource = { clock?: { now(): number } } | { HOST_CLOCK?: unknown } | null | undefined;

/** Returns an epoch-ms clock from `HostCapabilities.clock`, `HOST_CLOCK`, or `Date.now`. */
export function makeWallClock(source?: ClockSource): () => number {
  if (source && typeof source === "object" && "clock" in source && source.clock) {
    const cap = source.clock;
    return () => cap.now();
  }
  const clock = (source as { HOST_CLOCK?: HostClock } | null | undefined)?.HOST_CLOCK;
  if (isHostClock(clock)) {
    return () => clock.timeOrigin + clock.now();
  }
  return () => Date.now();
}
