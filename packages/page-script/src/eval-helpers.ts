// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Runs CDP expressions through the native probe or Boa fallback and packs the result.

import type { EvalResult } from "@parawing/jsrpc-types/page-script";
import {
  AsyncFunction,
  boaEvalFallback,
  getExecutionBackend,
  packBoaResult,
  type RunExpressionOpts,
  SyncFunction,
} from "./exec-backend.ts";
import type { DomRect, ShimElement } from "./types.ts";

export { AsyncFunction, boaEvalFallback, packBoaResult, SyncFunction, type RunExpressionOpts };

const INPUT_ANCESTOR_DEPTH = 32;
const ANCHOR_SEARCH_DEPTH = 8;
const MAX_ANCHOR_WRAPPER_AREA_RATIO = 4;

export function findAnchorAncestor(el: ShimElement | null): ShimElement | null {
  let currentElement: ShimElement | null = el;
  for (let i = 0; currentElement && i < INPUT_ANCESTOR_DEPTH; i++) {
    const name = currentElement.tagName;
    if (typeof name === "string" && name.toUpperCase() === "A") return currentElement;
    currentElement =
      (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
  }
  return null;
}

const SVG_NAMESPACE = "http://www.w3.org/2000/svg";

export function anchorHrefAttribute(anchor: ShimElement): string | null {
  const href = anchor.getAttribute?.("href") ?? null;
  if (href !== null || anchor.namespaceURI !== SVG_NAMESPACE) return href;
  return anchor.getAttribute?.("xlink:href") ?? null;
}

export function findFocusableAncestor(el: ShimElement | null): ShimElement | null {
  let currentElement: ShimElement | null = el;
  for (let i = 0; currentElement && i < INPUT_ANCESTOR_DEPTH; i++) {
    const tag =
      typeof currentElement.tagName === "string" ? currentElement.tagName.toUpperCase() : "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || tag === "BUTTON") {
      if (currentElement.hasAttribute && currentElement.hasAttribute("disabled")) {
        currentElement =
          (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
        continue;
      }
      return currentElement;
    }
    if (tag === "A" && currentElement.hasAttribute && currentElement.hasAttribute("href"))
      return currentElement;
    if (currentElement.getAttribute) {
      const contentEditable = currentElement.getAttribute("contenteditable");
      if (contentEditable != null && contentEditable.toLowerCase() !== "false")
        return currentElement;
      const tabIndex = currentElement.getAttribute("tabindex");
      if (tabIndex != null) {
        const value = parseInt(tabIndex, 10);
        if (Number.isFinite(value) && value >= 0) return currentElement;
      }
    }
    currentElement =
      (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
  }
  return null;
}

export function findAnchorViaSingleChild(
  targetEl: ShimElement | null,
  x: number,
  y: number,
): ShimElement | null {
  if (targetEl) {
    const tag = typeof targetEl.tagName === "string" ? targetEl.tagName.toUpperCase() : "";
    if (
      tag === "INPUT" ||
      tag === "TEXTAREA" ||
      tag === "SELECT" ||
      tag === "OPTION" ||
      tag === "BUTTON" ||
      (tag === "LABEL" && !!(targetEl.getAttribute && targetEl.getAttribute("for"))) ||
      (typeof targetEl.isContentEditable === "boolean" && targetEl.isContentEditable)
    ) {
      return null;
    }
  }
  if (hasInteractiveNonAnchorAncestor(targetEl)) return null;

  const rectContains = (rect: DomRect | null | undefined, px: number, py: number) =>
    !!rect &&
    rect.width > 0 &&
    rect.height > 0 &&
    px >= rect.left &&
    px <= rect.right &&
    py >= rect.top &&
    py <= rect.bottom;
  const rectArea = (rect: DomRect | null | undefined) =>
    rect && rect.width > 0 && rect.height > 0 ? rect.width * rect.height : 0;
  let currentElement: ShimElement | null = targetEl;
  for (let i = 0; currentElement && i < ANCHOR_SEARCH_DEPTH; i++) {
    if (currentElement.querySelectorAll) {
      // `[href]` matches only a no-namespace href (Selectors 3 §6.3.4), so an
      // SVG <a> with only xlink:href needs `*|`. anchorHrefAttribute still
      // ignores namespaced hrefs on HTML anchors.
      const anchors = currentElement.querySelectorAll("a[*|href]");
      if (!anchors || anchors.length === 0) {
        currentElement =
          (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
        continue;
      }
      for (let k = 0; k < anchors.length; k++) {
        const anchor = anchors[k];
        if (!anchor.getBoundingClientRect) continue;
        const rect = anchor.getBoundingClientRect();
        if (!rectContains(rect, x, y)) continue;
        const href = anchorHrefAttribute(anchor);
        if (href && href !== "" && !/^javascript:/i.test(href)) return anchor;
      }
      for (let k = 0; k < anchors.length; k++) {
        const anchor = anchors[k];
        const parent =
          (anchor.parentElement as ShimElement | null) || (anchor.parentNode as ShimElement | null);
        if (!parent?.getBoundingClientRect || !anchor.getBoundingClientRect) continue;
        const parentRect = parent.getBoundingClientRect();
        if (!rectContains(parentRect, x, y)) continue;
        const anchorArea = rectArea(anchor.getBoundingClientRect());
        const parentArea = rectArea(parentRect);
        if (anchorArea <= 0 || parentArea > anchorArea * MAX_ANCHOR_WRAPPER_AREA_RATIO) continue;
        const href = anchorHrefAttribute(anchor);
        if (href && href !== "" && !/^javascript:/i.test(href)) return anchor;
      }
    }
    currentElement =
      (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
  }
  return null;
}

function hasInteractiveNonAnchorAncestor(el: ShimElement | null): boolean {
  let currentElement: ShimElement | null = el;
  for (let i = 0; currentElement && i < INPUT_ANCESTOR_DEPTH; i++) {
    const tag =
      typeof currentElement.tagName === "string" ? currentElement.tagName.toUpperCase() : "";
    if (tag === "BUTTON" || tag === "SUMMARY") return true;
    if (currentElement.getAttribute) {
      const role = currentElement.getAttribute("role");
      if (role) {
        const name = role.toLowerCase();
        if (
          name === "button" ||
          name === "tab" ||
          name === "link" ||
          name === "menuitem" ||
          name === "menuitemcheckbox" ||
          name === "menuitemradio" ||
          name === "switch" ||
          name === "checkbox" ||
          name === "radio" ||
          name === "option"
        ) {
          return true;
        }
      }
    }
    currentElement =
      (currentElement.parentNode as ShimElement | null) || currentElement.parentElement || null;
  }
  return false;
}

export type RunExpressionResult = EvalResult;

export async function runExpression(
  expression: string,
  options: RunExpressionOpts,
): Promise<RunExpressionResult> {
  return await getExecutionBackend().evalExpression(expression, options);
}
