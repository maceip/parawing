# Dependency Integrity System — Onboarding & Daily Usage

Deterministic, zero-LLM-authority supply-chain gate (`reliedUponLlm = false`) covering **Rust (`Cargo.lock`)**, **Node (`pnpm-lock.yaml`, `package-lock.json`)**, **Go (`go.sum`)**, **Python (`uv.lock`, `requirements.txt`)**, and **Bazel (`MODULE.bazel`)**, with SHA-256 in-tree patch verification and **OpenVEX v0.2.0** attestations.

---

## 1. Activate in Any Repository (3 Ways)

### Option A — 3-Line GitHub Action (Zero Files Required)

Add `.github/workflows/dependency-integrity.yml` to any repo (`Nightfall`, `trap`, `conduit`, `Outrider`, or external):

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: maceip/parawing/.github/actions/dependency-integrity@main
```

In `mode: auto` (default), the action runs a zero-config live OSV.dev + OpenVEX audit immediately, and automatically upgrades to full SHA-256 patch + lockfile digest enforcement once `deps/patches-manifest.json` is committed.

### Option B — Zero-Config Local CLI Audit (0 Files Written)

```bash
node /path/to/parawing/scripts/deps/cli.mjs audit --root /path/to/your-repo
```

### Option C — Full Hermetic Repo Onboarding (1 Command)

Locks the cryptographic `inventoryDigest`, hashes existing in-tree `.patch` files + `pnpm.overrides`, queries OSV.dev to create `deps/advisory-lock.json`, and writes `.github/workflows/dependency-integrity.yml`:

```bash
node /path/to/parawing/scripts/deps/cli.mjs init --root /path/to/your-repo --ci
```

---

## 2. Daily Developer & Agent Workflow (Inside Parawing or Any Onboarded Repo)

| Scenario                             | Command                                                                                                                    | What It Does                                                                                                                                |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Check current status**             | `pnpm run deps:status`                                                                                                     | Prints locked dependency count, SHA-256 digest, patch parity, and advisory/waiver counts.                                                   |
| **Run fast offline gate**            | `pnpm run deps:verify`                                                                                                     | Verifies lockfile digest + every `.patch` SHA-256 + `minSafeVersion` overrides offline (`<0.5s`, also run by `bazel test //:deps_check`).   |
| **Added or upgraded a package**      | `pnpm run deps:sync`                                                                                                       | Recomputes `inventoryDigest`, batch-queries live OSV/RustSec/GHSA, and updates `deps/advisory-lock.json`.                                   |
| **Added or edited a `.patch` file**  | `pnpm run deps:refresh && pnpm run deps:sync`                                                                              | Auto-computes SHA-256 digests + `seriesSha8` into `deps/patches-manifest.json` (including new `pnpm.patchedDependencies`) and re-locks OSV. |
| **Waive an unreachable CVE (VEX)**   | `pnpm run deps:waive -- <ID> --package <pkg> --justification vulnerable_code_not_in_execute_path --reason "..." --days 90` | Records a time-bounded OpenVEX v0.2.0 `not_affected` justification (fails closed once `expiresAt` passes).                                  |
| **Track an unmaintained crate**      | `pnpm run deps:waive -- <ID> --package <pkg> --unmaintained --reason "..." --days 180`                                     | Records a time-bounded review deadline in `trackedUnmaintained`.                                                                            |
| **Export OpenVEX / Markdown / JSON** | `pnpm run deps:report -- --vex-out out.openvex.json --md-out report.md`                                                    | Emits OpenVEX v0.2.0 statements and Markdown health report.                                                                                 |
| **Build GitHub Pages Ledger**        | `pnpm run pages:build`                                                                                                     | Verifies `deps/remediated-advisories.json` against live lockfiles/patches and emits static site to `dist-pages/`.                           |

---

## 3. Authoring an In-Tree Security Patch

1. **npm / pnpm (`patches/<pkg>@<ver>.patch`)**:
   - Add `"pnpm": { "patchedDependencies": { "<pkg>@<ver>": "patches/<pkg>@<ver>.patch" } }` to `package.json`.
   - Run `pnpm run deps:refresh` to enroll the patch and its SHA-256 digest in `deps/patches-manifest.json`.
   - Add `"mitigates": ["GHSA-..."]` and a regression test target (`"//scripts:helpers_test"`, `"npm:test"`, or `"file:tests/..."`) on that entry in `deps/patches-manifest.json`, then run `pnpm run deps:sync`.
2. **Rust / Cargo (`scripts/patches/<crate>-<ver>/*.patch`)**:
   - Materialize with `pnpm run vendor:apply`, commit fix inside `packages/core/target/vendor-patched/<crate>-<ver>`, and run `pnpm run vendor:regen <crate>`.
   - Run `pnpm run deps:refresh && pnpm run deps:sync` to update every patch SHA-256 and `seriesSha8` in `deps/patches-manifest.json`.
