// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deterministic OpenVEX v0.2.0, JSON, and Markdown dependency health and patch reporter.

/** @param {{ version: string, created?: string, resolvedAdvisories: Array<any> }} input @returns {any} */
export function buildOpenVexDocument(input) {
  const timestamp = input.created || new Date().toISOString();
  const statements = input.resolvedAdvisories.map((adv) => {
    const stmt = {
      vulnerability: {
        "@id": `https://osv.dev/vulnerability/${adv.id}`,
        name: adv.id,
        description: adv.summary,
        aliases: adv.aliases || [],
      },
      timestamp,
      products: [
        {
          "@id": `pkg:generic/parawing@${input.version}`,
          subcomponents: [{ "@id": adv.purl }],
        },
      ],
      status: adv.vexStatus || "under_investigation",
    };
    if (adv.vexStatus === "not_affected" && adv.vexJustification) {
      stmt.justification = adv.vexJustification;
      stmt.impact_statement = adv.mitigation || "";
    }
    if (adv.vexStatus === "fixed") {
      stmt.action_statement = adv.mitigation || "Patched in-tree and verified by Bazel tests";
    }
    return stmt;
  });
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": `https://github.com/maceip/parawing/vex/${input.version}/${timestamp.slice(0, 10)}`,
    author: "Parawing Dependency Integrity System",
    timestamp,
    version: 1,
    statements,
  };
}

function renderPatchesTable(manifest) {
  const lines = [
    "## Patched Vendor Crates",
    "",
    "| Crate | Version | Patches | Mitigates | Verification Targets |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const entry of manifest.cargoPatches || []) {
    const mit = (entry.mitigates || []).length > 0 ? entry.mitigates.join(", ") : "—";
    const targets =
      (entry.verificationTargets || []).length > 0
        ? entry.verificationTargets.map((t) => `\`${t}\``).join(", ")
        : "workspace build";
    lines.push(
      `| \`${entry.crate}\` | \`${entry.version}\` | ${entry.patches.length} | ${mit} | ${targets} |`,
    );
  }
  return lines;
}

function renderAdvisoriesSection(resolved) {
  const lines = ["", "## Known-Bug & Advisory Verification", ""];
  if (resolved.length === 0) {
    lines.push("Zero advisories matched any locked package.");
    return lines;
  }
  lines.push("| Advisory | Kind | Package | Status | Resolution |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const adv of resolved) {
    const pkg = `\`${adv.packageName}@${adv.packageVersion}\``;
    const note = (adv.mitigation || adv.summary || "").replace(/\|/g, "\\|");
    lines.push(`| \`${adv.id}\` | \`${adv.kind}\` | ${pkg} | \`${adv.status}\` | ${note} |`);
  }
  return lines;
}

function renderLlmSection(llmResult) {
  if (!llmResult || llmResult.status === "disabled") return [];
  const lines = [
    "",
    "## Optional LLM Triage Notes (Advisory-Only, Never Authoritative)",
    "",
    `- **Status**: \`${llmResult.status}\` (\`reliedUpon=${llmResult.reliedUpon}\`, \`verified=${llmResult.verified}\`)`,
  ];
  if (llmResult.backend) lines.push(`- **Backend**: \`${llmResult.backend}\``);
  if (llmResult.reason) lines.push(`- **Detail**: ${llmResult.reason}`);
  if (llmResult.analysis) {
    lines.push(`- **Summary**: ${llmResult.analysis.summary}`);
    lines.push(`- **Reachability**: ${llmResult.analysis.reachability}`);
    lines.push(`- **Recommended Action**: ${llmResult.analysis.recommendedAction}`);
  }
  return lines;
}

function formatEcosystemBreakdown(counts) {
  const parts = [`${counts.cargo} Cargo`, `${counts.npm} npm`];
  if (counts.go) parts.push(`${counts.go} Go`);
  if (counts.pypi) parts.push(`${counts.pypi} PyPI`);
  parts.push(`${counts.bazelAndToolchains} Bazel/toolchain`);
  return parts.join(", ");
}

/** @param {any} report @returns {string} */
export function renderMarkdownReport(report) {
  const statusWord = report.patchCheck.ok && report.advisoryCheck.ok ? "PASS" : "FAIL";
  const c = report.inventory.counts;
  const lines = [
    "# Parawing Dependency Patch, Bug & Integrity Report",
    "",
    `- **Gate Verdict**: **${statusWord}** (100% deterministic; LLM relied upon: \`false\`)`,
    `- **Parawing Version**: \`${report.version}\``,
    `- **Inventory Digest**: \`${report.inventory.digest}\``,
    `- **Locked Dependencies**: ${c.total} total (${formatEcosystemBreakdown(c)})`,
    `- **Verified Patch Files**: ${report.patchCheck.summary.totalPatchFiles} across ${report.patchCheck.summary.cargoSeries} Cargo series + ${report.patchCheck.summary.auxiliaryPatches} auxiliary patches`,
    `- **Active npm Security Overrides**: ${report.patchCheck.summary.npmSecurityOverrides}`,
    "",
    ...renderPatchesTable(report.manifest),
    ...renderAdvisoriesSection(report.advisoryCheck.resolved || []),
    ...renderLlmSection(report.llmResult),
    "",
  ];
  return lines.join("\n");
}
