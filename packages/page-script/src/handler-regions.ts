// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Tracks non-passive wheel and touch event listener regions for client compositor interception.

import type { HandlerRegionInfo } from "@parawing/jsrpc-types/page-script";

export const HANDLER_WHEEL = 1 << 0;
export const HANDLER_TOUCH_START = 1 << 1;
export const HANDLER_TOUCH_MOVE = 1 << 2;

const MAX_ANCESTOR_HOPS = 128;

export interface HandlerRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface NodeScrollDims {
  clientWidth?: number;
  clientHeight?: number;
  scrollWidth?: number;
  scrollHeight?: number;
}

export interface HandlerGeometrySource {
  documentNodeId: number;
  documentElementNodeId?: number;
  viewportWidth: number;
  viewportHeight: number;
  getBoundingRect(nodeId: number): HandlerRect | null | undefined;
  getScrollInfo(nodeId: number): NodeScrollDims | null | undefined;
  parentNodeId(nodeId: number): number;
}

interface ListenerCounts {
  wheelNonPassive: number;
  touchStartNonPassive: number;
  touchMoveNonPassive: number;
}

function emptyCounts(): ListenerCounts {
  return { wheelNonPassive: 0, touchStartNonPassive: 0, touchMoveNonPassive: 0 };
}

function countsToMask(c: ListenerCounts): number {
  let mask = 0;
  if (c.wheelNonPassive > 0) mask |= HANDLER_WHEEL;
  if (c.touchStartNonPassive > 0) mask |= HANDLER_TOUCH_START;
  if (c.touchMoveNonPassive > 0) mask |= HANDLER_TOUCH_MOVE;
  return mask;
}

function isScrollableInfo(info: NodeScrollDims | null | undefined): boolean {
  if (!info) return false;
  const cw = Number(info.clientWidth) || 0;
  const ch = Number(info.clientHeight) || 0;
  const sw = Number(info.scrollWidth) || 0;
  const sh = Number(info.scrollHeight) || 0;
  return sw > cw + 0.5 || sh > ch + 0.5;
}

function resolveScrollAncestor(
  source: HandlerGeometrySource,
  targetNodeId: number,
): { connected: boolean; scrollNodeId: number } {
  const docId = source.documentNodeId;
  if (targetNodeId === docId) return { connected: true, scrollNodeId: docId };
  let cur = targetNodeId;
  let scrollNodeId = -1;
  const seen = new Set<number>();
  for (let hop = 0; hop < MAX_ANCESTOR_HOPS && cur >= 0; hop++) {
    if (seen.has(cur)) return { connected: false, scrollNodeId: docId };
    seen.add(cur);
    if (cur === docId) {
      return {
        connected: true,
        scrollNodeId: scrollNodeId >= 0 ? scrollNodeId : docId,
      };
    }
    if (scrollNodeId < 0 && isScrollableInfo(source.getScrollInfo(cur))) {
      scrollNodeId = cur;
    }
    cur = source.parentNodeId(cur);
  }
  return { connected: false, scrollNodeId: docId };
}

function documentScrollRect(
  source: HandlerGeometrySource,
  targetNodeId: number,
): HandlerRect | null {
  const docElId = source.documentElementNodeId ?? -1;
  const info =
    source.getScrollInfo(targetNodeId) ?? (docElId >= 0 ? source.getScrollInfo(docElId) : null);
  const w = Math.max(source.viewportWidth, Number(info?.scrollWidth) || 0);
  const h = Math.max(source.viewportHeight, Number(info?.scrollHeight) || 0);
  return w > 0 && h > 0 ? { x: 0, y: 0, width: w, height: h } : null;
}

function resolveRegionRect(
  source: HandlerGeometrySource,
  targetNodeId: number,
): HandlerRect | null {
  const docElId = source.documentElementNodeId ?? -1;
  const isDocEl = docElId >= 0 && targetNodeId === docElId;
  if (targetNodeId === source.documentNodeId) {
    return documentScrollRect(source, targetNodeId);
  }
  const raw = source.getBoundingRect(targetNodeId);
  if (!raw) return isDocEl ? documentScrollRect(source, targetNodeId) : null;
  const width = Number(raw.width) || 0;
  const height = Number(raw.height) || 0;
  if (width <= 0 || height <= 0) {
    return isDocEl ? documentScrollRect(source, targetNodeId) : null;
  }
  return {
    x: Number(raw.x) || 0,
    y: Number(raw.y) || 0,
    width,
    height,
  };
}

export class HandlerRegionTracker {
  private readonly nodes: Map<number, ListenerCounts> = new Map();

  recordMutation(targetNodeId: number, type: string, passive: boolean, added: boolean): void {
    if (passive || targetNodeId < 0) return;
    const isWheel = type === "wheel" || type === "mousewheel";
    const isTouchStart = type === "touchstart";
    const isTouchMove = type === "touchmove";
    if (!isWheel && !isTouchStart && !isTouchMove) return;

    const entry = this.nodes.get(targetNodeId) ?? emptyCounts();
    const delta = added ? 1 : -1;
    if (isWheel) entry.wheelNonPassive = Math.max(0, entry.wheelNonPassive + delta);
    if (isTouchStart) entry.touchStartNonPassive = Math.max(0, entry.touchStartNonPassive + delta);
    if (isTouchMove) entry.touchMoveNonPassive = Math.max(0, entry.touchMoveNonPassive + delta);

    if (countsToMask(entry) === 0) {
      this.nodes.delete(targetNodeId);
    } else {
      this.nodes.set(targetNodeId, entry);
    }
  }

  reset(): void {
    this.nodes.clear();
  }

  activeMasks(): Map<number, number> {
    const out = new Map<number, number>();
    for (const [nodeId, counts] of this.nodes) {
      const mask = countsToMask(counts);
      if (mask !== 0) out.set(nodeId, mask);
    }
    return out;
  }

  snapshotRegions(source: HandlerGeometrySource): HandlerRegionInfo[] {
    const regions: HandlerRegionInfo[] = [];
    const docElId = source.documentElementNodeId ?? -1;
    for (const [targetNodeId, counts] of this.nodes) {
      const eventMask = countsToMask(counts);
      if (eventMask === 0) continue;
      const ancestor = resolveScrollAncestor(source, targetNodeId);
      if (!ancestor.connected) continue;
      const rect = resolveRegionRect(source, targetNodeId);
      if (!rect) continue;
      const isDocTarget =
        targetNodeId === source.documentNodeId || (docElId >= 0 && targetNodeId === docElId);
      const coversScrollNode = isDocTarget || targetNodeId === ancestor.scrollNodeId;
      regions.push({
        targetNodeId,
        scrollNodeId: ancestor.scrollNodeId,
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height,
        eventMask,
        nonPassive: true,
        coversScrollNode,
      });
    }
    regions.sort((a, b) => a.targetNodeId - b.targetNodeId);
    return regions;
  }
}

const pageTracker = new HandlerRegionTracker();

export function recordListenerMutation(
  targetNodeId: number,
  type: string,
  passive: boolean,
  added: boolean,
): void {
  pageTracker.recordMutation(targetNodeId, type, passive, added);
}

export function resetHandlerRegions(): void {
  pageTracker.reset();
}

export function snapshotHandlerRegions(source: HandlerGeometrySource): HandlerRegionInfo[] {
  return pageTracker.snapshotRegions(source);
}

export function activeHandlerMaskMap(): Map<number, number> {
  return pageTracker.activeMasks();
}
