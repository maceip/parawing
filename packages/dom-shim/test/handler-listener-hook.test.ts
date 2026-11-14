// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

import { expect, it } from "vitest";
import { DocumentImpl } from "../src/document.js";
import { cache } from "../src/registries.js";
import {
  DOCUMENT_ID,
  WINDOW_KEY,
  setDocumentId,
  setDocumentImpl,
  setNodeFor,
  setOnListenerMutation,
} from "../src/state.js";
import { addListener, dispatchTrustedOnKey, removeListener } from "../src/events/dispatch.js";
import { KsEvent } from "../src/events/event.js";

it("notifies onListenerMutation for wheel and touch listeners including once removal", () => {
  const events: Array<{ nodeId: number; type: string; passive: boolean; added: boolean }> = [];
  setDocumentId(42);
  const doc = new DocumentImpl();
  setDocumentImpl(doc);
  setNodeFor(() => doc);
  setOnListenerMutation((nodeId, type, passive, added) => {
    events.push({ nodeId, type, passive, added });
  });
  expect(DOCUMENT_ID).toBe(42);

  const elId = 77;
  cache.set(elId, doc);
  const wheelFn = (): void => {};
  const onceTouchFn = (): void => {};

  // Non-passive wheel on an element triggers added=true passive=false.
  addListener(elId, "wheel", wheelFn, { passive: false });
  // Window defaults wheel/touchstart to passive=true unless passive:false is given.
  addListener(WINDOW_KEY, "wheel", wheelFn, undefined);
  addListener(elId, "touchstart", onceTouchFn, { passive: false, once: true });
  // Non-scroll event types do not emit scroll/touch handler mutations.
  addListener(elId, "click", wheelFn, { passive: false });

  expect(events).toEqual([
    { nodeId: 77, type: "wheel", passive: false, added: true },
    { nodeId: 42, type: "wheel", passive: true, added: true },
    { nodeId: 77, type: "touchstart", passive: false, added: true },
  ]);

  // Firing the once listener auto-removes it and notifies added=false.
  dispatchTrustedOnKey(elId, new KsEvent("touchstart", { bubbles: false, cancelable: true }));
  removeListener(elId, "wheel", wheelFn, false);
  setOnListenerMutation(null);

  expect(events.slice(3)).toEqual([
    { nodeId: 77, type: "touchstart", passive: false, added: false },
    { nodeId: 77, type: "wheel", passive: false, added: false },
  ]);
});
