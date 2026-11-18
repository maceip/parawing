// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Interactive Digital Agency Design System v2.18.2 vulnerability & patch ledger controller.
// Drives search highlighting, severity/ecosystem/mechanism filtering, removable Chip Tags,
// sortable Dense Data Table columns, and expandable Elevation-1 remediation proof drawers.

const SEVERITY_RANK = {
  Critical: 5,
  High: 4,
  Soundness: 3,
  Moderate: 2,
  Low: 1,
};

const ledger = globalThis.__PARAWING_SECURITY_LEDGER__ || {
  remediated: [],
  patchSeries: [],
  trackedUnmaintained: [],
  repoUrl: "https://github.com/maceip/parawing",
};

const state = {
  tab: "advisories",
  query: "",
  severity: "all",
  ecosystem: "all",
  mechanism: "all",
  sortKey: "severity",
  sortDir: "desc",
  expandedIds: new Set(),
};

const els = {
  tabAdvisories: document.getElementById("tab-advisories"),
  tabPatches: document.getElementById("tab-patches"),
  panelAdvisories: document.getElementById("panel-advisories"),
  panelPatches: document.getElementById("panel-patches"),
  searchInput: document.getElementById("search-input"),
  severitySelect: document.getElementById("severity-select"),
  ecosystemSelect: document.getElementById("ecosystem-select"),
  resetBtn: document.getElementById("reset-filters-btn"),
  activeFilters: document.getElementById("active-filters"),
  resultCount: document.getElementById("result-count"),
  advisoriesBody: document.getElementById("advisories-tbody"),
  sortButtons: Array.from(document.querySelectorAll("[data-sort-key]")),
};

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function highlightText(rawText, query) {
  const safe = escapeHtml(rawText);
  if (!query) return safe;
  const escapedQuery = escapeHtml(query).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!escapedQuery) return safe;
  return safe.replace(
    new RegExp(`(${escapedQuery})`, "gi"),
    '<mark class="dads-highlight">$1</mark>',
  );
}

function severityChipClass(severity) {
  if (severity === "Critical" || severity === "High") return "dads-chip-label dads-chip-red";
  if (severity === "Soundness" || severity === "Moderate")
    return "dads-chip-label dads-chip-orange";
  return "dads-chip-label dads-chip-yellow";
}

function matchesItem(item) {
  if (state.severity !== "all" && item.severity !== state.severity) return false;
  if (state.ecosystem !== "all" && item.ecosystem !== state.ecosystem) return false;
  if (!state.query) return true;
  const needle = state.query.toLowerCase();
  const hay = [
    item.id,
    ...(item.aliases || []),
    item.package,
    item.ecosystem,
    item.severity,
    item.mechanism,
    item.summary,
    item.patchPath,
    item.commitSha,
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(needle);
}

function compareItems(a, b) {
  const dir = state.sortDir === "asc" ? 1 : -1;
  if (state.sortKey === "severity") {
    const diff = (SEVERITY_RANK[a.severity] || 0) - (SEVERITY_RANK[b.severity] || 0);
    if (diff !== 0) return diff * dir;
    return b.commitDate.localeCompare(a.commitDate);
  }
  if (state.sortKey === "date") {
    const diff = a.commitDate.localeCompare(b.commitDate);
    if (diff !== 0) return diff * dir;
    return a.id.localeCompare(b.id);
  }
  const av = String(a[state.sortKey] || "");
  const bv = String(b[state.sortKey] || "");
  return av.localeCompare(bv) * dir;
}

function renderActiveFilterChips() {
  const chips = [];
  if (state.query) {
    chips.push({ key: "query", label: `Query: ${state.query}` });
  }
  if (state.severity !== "all") {
    chips.push({ key: "severity", label: `Severity: ${state.severity}` });
  }
  if (state.ecosystem !== "all") {
    chips.push({ key: "ecosystem", label: `Ecosystem: ${state.ecosystem}` });
  }
  if (chips.length === 0) {
    els.activeFilters.hidden = true;
    els.activeFilters.innerHTML = "";
    return;
  }
  const visible =
    chips.length <= 2
      ? chips
      : [chips[0], { key: "all", label: `+${chips.length - 1} more (Clear all)` }];
  els.activeFilters.hidden = false;
  els.activeFilters.innerHTML = visible
    .map(
      (c) =>
        `<button type="button" class="dads-chip-tag" data-clear-filter="${escapeHtml(c.key)}" aria-label="Remove filter ${escapeHtml(c.label)}">${escapeHtml(c.label)} <span aria-hidden="true">×</span></button>`,
    )
    .join("");
}

function renderSortHeaders() {
  for (const btn of els.sortButtons) {
    const th = btn.closest("th");
    const key = btn.getAttribute("data-sort-key");
    const indicator = btn.querySelector("[data-sort-indicator]");
    if (key === state.sortKey) {
      th?.setAttribute("aria-sort", state.sortDir === "asc" ? "ascending" : "descending");
      if (indicator) indicator.textContent = state.sortDir === "asc" ? "▲" : "▼";
    } else {
      th?.setAttribute("aria-sort", "none");
      if (indicator) indicator.textContent = "↕";
    }
  }
}

function renderAdvisoriesTable() {
  const filtered = ledger.remediated.filter(matchesItem).sort(compareItems);
  const totalDeps = ledger.counts?.total ?? 0;
  const totalPatches = ledger.patchSummary?.totalPatchFiles ?? 0;
  els.resultCount.textContent = `0 open · ${filtered.length}/${ledger.remediated.length} remediated · ${totalDeps} deps · ${totalPatches} patches`;
  renderActiveFilterChips();
  renderSortHeaders();

  if (filtered.length === 0) {
    els.advisoriesBody.innerHTML =
      '<tr><td colspan="7" class="dads-empty-state">No remediated advisories match the active filter criteria.</td></tr>';
    return;
  }

  const rowsHtml = filtered
    .map((item) => {
      const expanded = state.expandedIds.has(item.id);
      const detailId = `proof-${item.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
      const commitUrl = `${ledger.repoUrl}/commit/${encodeURIComponent(item.commitSha)}`;
      const aliasesText =
        item.aliases && item.aliases.length > 0 ? item.aliases.join(", ") : "None";
      const patchInfo = item.patchPath
        ? `<span class="dads-mono">${escapeHtml(item.patchPath)}</span> (sha256: <span class="dads-mono">${escapeHtml(item.patchSha256.slice(0, 16))}…</span>)`
        : `Lockfile floor enforced at <span class="dads-mono">${escapeHtml(item.remediatedVersion)}</span>`;
      return `
        <tr class="dads-data-row" data-advisory-id="${escapeHtml(item.id)}" data-expanded="${expanded}">
          <td class="dads-mono"><a href="${escapeHtml(item.advisoryUrl)}" target="_blank" rel="noopener noreferrer">${highlightText(item.id, state.query)}</a></td>
          <td class="dads-mono">${highlightText(`${item.package}@${item.remediatedVersion}`, state.query)}</td>
          <td>${escapeHtml(item.ecosystem)}</td>
          <td><span class="${severityChipClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
          <td><span class="dads-chip-label dads-chip-green">Remediated</span></td>
          <td>${highlightText(item.mechanism, state.query)} · <a class="dads-mono" href="${commitUrl}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.commitSha)}</a></td>
          <td>
            <button
              type="button"
              class="dads-btn dads-btn-outlined dads-btn-xs"
              data-toggle-proof="${escapeHtml(item.id)}"
              aria-expanded="${expanded}"
              aria-controls="${detailId}"
            >${expanded ? "Hide Proof" : "Proof"}</button>
          </td>
        </tr>
        <tr id="${detailId}" class="dads-detail-row" ${expanded ? "" : "hidden"}>
          <td colspan="7">
            <div class="dads-proof-card">
              <dl class="dads-proof-grid">
                <div>
                  <dt>Summary</dt>
                  <dd>${highlightText(item.summary, state.query)}</dd>
                </div>
                <div>
                  <dt>Vulnerable Range → Remediated Version</dt>
                  <dd class="dads-mono">${escapeHtml(item.vulnerableRange)} → ${escapeHtml(item.remediatedVersion)} (${escapeHtml(item.commitDate)})</dd>
                </div>
                <div>
                  <dt>Cryptographic / Lockfile Proof</dt>
                  <dd>${patchInfo}</dd>
                </div>
                <div>
                  <dt>Aliases &amp; Verification Gates</dt>
                  <dd class="dads-mono">${escapeHtml(aliasesText)} · ${(item.verificationTargets || []).map(escapeHtml).join(", ")}</dd>
                </div>
              </dl>
            </div>
          </td>
        </tr>`;
    })
    .join("");

  els.advisoriesBody.innerHTML = rowsHtml;
}

function setActiveTab(nextTab) {
  state.tab = nextTab;
  const map = [
    ["advisories", els.tabAdvisories, els.panelAdvisories],
    ["patches", els.tabPatches, els.panelPatches],
  ];
  for (const [name, tabEl, panelEl] of map) {
    const active = name === nextTab;
    tabEl?.setAttribute("aria-selected", String(active));
    if (panelEl) panelEl.hidden = !active;
  }
}

els.tabAdvisories?.addEventListener("click", () => setActiveTab("advisories"));
els.tabPatches?.addEventListener("click", () => setActiveTab("patches"));

els.searchInput?.addEventListener("input", (ev) => {
  state.query = ev.target.value.trim();
  renderAdvisoriesTable();
});

els.severitySelect?.addEventListener("change", (ev) => {
  state.severity = ev.target.value;
  renderAdvisoriesTable();
});

els.ecosystemSelect?.addEventListener("change", (ev) => {
  state.ecosystem = ev.target.value;
  renderAdvisoriesTable();
});

function clearAllFilters() {
  state.query = "";
  state.severity = "all";
  state.ecosystem = "all";
  if (els.searchInput) els.searchInput.value = "";
  if (els.severitySelect) els.severitySelect.value = "all";
  if (els.ecosystemSelect) els.ecosystemSelect.value = "all";
  renderAdvisoriesTable();
}

els.resetBtn?.addEventListener("click", clearAllFilters);

els.activeFilters?.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-clear-filter]");
  if (!btn) return;
  const key = btn.getAttribute("data-clear-filter");
  if (key === "all") {
    clearAllFilters();
    return;
  }
  if (key === "query") {
    state.query = "";
    if (els.searchInput) els.searchInput.value = "";
  } else if (key === "severity") {
    state.severity = "all";
    if (els.severitySelect) els.severitySelect.value = "all";
  } else if (key === "ecosystem") {
    state.ecosystem = "all";
    if (els.ecosystemSelect) els.ecosystemSelect.value = "all";
  }
  renderAdvisoriesTable();
});

for (const btn of els.sortButtons) {
  btn.addEventListener("click", () => {
    const key = btn.getAttribute("data-sort-key");
    if (!key) return;
    if (state.sortKey === key) {
      state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
    } else {
      state.sortKey = key;
      state.sortDir = key === "severity" || key === "date" ? "desc" : "asc";
    }
    renderAdvisoriesTable();
  });
}

els.advisoriesBody?.addEventListener("click", (ev) => {
  const btn = ev.target.closest("[data-toggle-proof]");
  if (!btn) return;
  const id = btn.getAttribute("data-toggle-proof");
  if (!id) return;
  if (state.expandedIds.has(id)) state.expandedIds.delete(id);
  else state.expandedIds.add(id);
  renderAdvisoriesTable();
});

renderAdvisoriesTable();
