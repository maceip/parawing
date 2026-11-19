---
name: dependency-integrity
description: >-
  Onboard, activate, and operate the deterministic Dependency Integrity System (OSV/RustSec/GHSA
  lockfile gate, SHA-256 patch verification, OpenVEX v0.2.0 waivers, and GitHub Pages ledger) in
  Parawing or any sibling repository (Nightfall, trap, conduit, Outrider).
---

# Dependency Integrity Skill

Use this skill whenever onboarding a repository to dependency security gating, upgrading Cargo/npm/Go/Python lockfiles, authoring or refreshing `.patch` files, triaging CVEs, or updating the OpenVEX / GitHub Pages vulnerability ledger.

## Core Invariant

All gates (`cli.mjs verify`, `cli.mjs audit`, `bazel test //:deps_check`, CI) are **100% deterministic** (`reliedUponLlm = false`). Optional `--llm` triage notes never waive advisories or alter exit codes.

## 1. Onboarding Another Repository (Zero Friction)

- **Zero-config instant audit (writes no files):**
  ```bash
  node /Users/mac/parawing/scripts/deps/cli.mjs audit --root <target-repo>
  ```
- **1-command full repo activation (scaffolds `deps/*` + `.github/workflows/dependency-integrity.yml`):**
  ```bash
  node /Users/mac/parawing/scripts/deps/cli.mjs init --root <target-repo> --ci
  ```
- **3-line GitHub Actions step in any repo:**
  ```yaml
  - uses: actions/checkout@v4
  - uses: maceip/parawing/.github/actions/dependency-integrity@main
  ```

## 2. Operating Inside an Onboarded Repo (`parawing`)

1. **Inspect current state:** `pnpm run deps:status` (or `node scripts/deps/cli.mjs status`).
2. **After editing any lockfile (`Cargo.lock`, `pnpm-lock.yaml`, `package-lock.json`, `go.sum`, `uv.lock`, `MODULE.bazel`):**
   Run `pnpm run deps:sync` to re-query `https://api.osv.dev/v1/querybatch` and update `deps/advisory-lock.json`.
3. **After adding or modifying any `.patch` file (`patches/*.patch` or `scripts/patches/<crate>-<ver>/*.patch`):**
   Run `pnpm run deps:refresh && pnpm run deps:sync` so `deps/patches-manifest.json` recomputes every patch SHA-256 and `seriesSha8` automatically. Never hand-compute SHA-256 digests.
4. **Recording a verified OpenVEX `not_affected` waiver (when vulnerable code is unreachable):**
   ```bash
   node scripts/deps/cli.mjs waive <ADVISORY_ID> \
     --package <pkg-name> \
     --justification vulnerable_code_not_in_execute_path \
     --reason "<empirical proof>" \
     --days 90
   ```
   Allowed OpenVEX v0.2.0 justifications: `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`. Use `--unmaintained` for informational `unmaintained` notices.
5. **Verify before committing:**
   Run `pnpm run deps:verify` (offline `<0.5s` check) and `pnpm run pages:build` if `deps/remediated-advisories.json` changed.
