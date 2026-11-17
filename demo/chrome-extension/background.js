// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Manifest V3 service worker: opens the Parawing × Vivari workbench tab when the
// toolbar icon is clicked and resolves the user's most recent HTTP(S) browser tab.

chrome.action.onClicked.addListener(async () => {
  const url = chrome.runtime.getURL("workbench.html");
  const existing = await chrome.tabs.query({ url });
  if (existing.length > 0 && existing[0].id !== undefined) {
    await chrome.tabs.update(existing[0].id, { active: true });
    if (existing[0].windowId !== undefined) {
      await chrome.windows.update(existing[0].windowId, { focused: true });
    }
    return;
  }
  await chrome.tabs.create({ url });
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type !== "GET_LATEST_HTTP_TAB") return false;
  chrome.tabs
    .query({})
    .then((tabs) => {
      const candidate = tabs
        .filter((t) => typeof t.url === "string" && /^https?:\/\//i.test(t.url))
        .sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0))[0];
      sendResponse({ url: candidate?.url || "", title: candidate?.title || "" });
    })
    .catch((err) => {
      sendResponse({ url: "", error: err?.message || String(err) });
    });
  return true;
});
