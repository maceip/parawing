# AGENTS.md

Guidance for contributors and coding agents. It records the constraints that are not obvious from
the code. Keep it short: state protocols and invariants as comments at the code that owns them,
point at code instead of restating it, and fix or delete anything here that becomes wrong.

## What this is

Parawing is a performant, secure delegated agent co-browser engine. It parses HTML, runs page JS in
isolated sub-isolates, and renders frames with Blitz (Stylo, Taffy, Parley and vello_cpu).
The core engine (`packages/engine`) pairs with stock Deno V8 sub-isolates (`packages/deno-host`) over
framed `PRWP` RPC (`packages/rpc-transport`), a native Rust CDP/RBI host (`packages/rust-host`),
`KSC2` scene streaming (`packages/scene-host-wasm`, `packages/parawing-cli`), hardware-backed
Walkaway WebAuthn/CTAP2 device authority (`packages/device-authority`), and Tier 2 `CRIU 4.1.1`
capsule session freeze/thaw on Linux and macOS.

## Repository map

A pnpm and Cargo monorepo built with Bazel. One line per package; read the code for details.

- `packages/engine/`: host-neutral browser engine. CDP over WebSocket, session authority, `KSC2`
  scene server, `PageScript` orchestration, and WebAssembly glue. `src/index.ts` routes, `src/cdp/`
  holds CDP methods, `src/eval/` the sub-isolate and subresource machinery, and `src/tty/` terminal
  UA styles.
- `packages/rust-host/`: native Rust/Tokio host (`parawing_rust_host_bin`). Owns native Blitz DOM
  and paint pipelines, Deno sub-isolate spawning over `PRWP` stdio pipes, Walkaway `ControlHub` Unix
  socket, blind credential brokering, and Tier 2 `CRIU 4.1.1` / Tier 1 session freeze/thaw.
- `packages/deno-host/`: zero-permission Deno V8 isolate loader (`createDenoIsolateLoader`) and
  out-of-process egress broker enforcing outbound URL, private-network, and SSRF policy.
- `packages/rpc-transport/`: framed `PRWP` binary RPC transport, capability tables, credit flow
  control, and freeze/thaw coordination over stdio pipes or Unix domain sockets.
- `packages/device-authority/`: hardware-backed Walkaway key custody, macOS Keychain / encrypted
  vault storage, WebAuthn L2/L3 delegation, and supervision envelopes.
- `packages/page-script/`: the per-page runtime, bundled to a string and loaded through
  `HostIsolateLoader` (`createDenoIsolateLoader` or `env.LOADER`). Owns navigation, script execution
  and CDP DOM/eval routing. `state.ts` is the shared mutable state and holds `ksGlobal`, the
  package's typed view of `globalThis` (`PageScriptGlobals`, which extends dom-shim's
  `DomShimGlobals`). Declare a new page global there; computed keys go through `ksGlobalByKey`.
  Engine hooks go on the internals record instead (`ParawingInternals` in
  `page-script/src/internal-state.ts`).
- `packages/dom-shim/`: the in-sandbox DOM (`buildDocument` and the Element, Node, Event and CSSOM
  classes), bundled to a string.
- `packages/core/`: Rust browser core compiled to wasm (`parawing-core`) and native static/host
  libraries (`parawing_core_host`) on Blitz. `DomHandle`, paint and screenshots, PDF, boa eval, the
  network provider, `KSC2` display-list codec, and `tty_*` terminal renderer. `pkg/` is staged by
  `pnpm run build`.
- `packages/renderer-core/`: the renderer isolate's smaller wasm, the `SceneRasterizer` slice of
  core included with `#[path]`.
- `packages/page-renderer/`: the stateless raster isolate. It pulls scenes from PageScript over the
  render port and owns the wasm resource cache.
- `packages/worker-script/`: the loaded isolate that runs a page's `new Worker()`.
- `packages/script-gate/`: the shared script-execution policy (SRI, CSP `script-src`, JS MIME and
  `nosniff`, mixed content, the iframe sandbox capability set), so the engine and PageScript bundle
  one copy.
- `packages/jsrpc-types/`: type-only JSRPC contracts between the engine and its loaded isolates.
  Both ends of a call import from here; do not redeclare a wire shape on one side.
- `packages/scene-host-wasm/`: the CLI's local scene rasterizer, staged into
  `packages/engine/public/rbi/`. The scene protocol is documented in `packages/engine/src/rbi.ts`.
- `packages/parawing-cli/`: the native Rust terminal client, including Browser Run, `CompositorV2`
  0-RTT scene playback, and OAuth through public APIs, with its own Cargo workspace and lockfile.
- `packages/engine/test/fixtures-worker/`: the test fixtures service serving `/__fixtures/*` in
  dev and e2e tests only.
- `scripts/`: development and CI tooling, including the WPT runners, the lint rules and the
  vendored crate patch series. Each tool has a Bazel target in `scripts/BUILD.bazel`.
- `tests/`: the WPT allow-list, expectations and pinned revision. Bump the revision on purpose
  with `pnpm wpt:setup --update`; an unpinned corpus shows upstream changes as regressions.

## Architecture

Engine-wide invariants. The owning code carries the detail; keep these in sync with it.

- Runtime code generation (`Runtime.evaluate`, `eval`, `new Function`, computed `import()`) runs on
  boa inside the per-target PageScript isolate, in dev and production, never in the parent host.
  The loaded isolate runs with `--disallow-code-generation-from-strings` (Deno) and never receives
  native-eval flags.
- The CDP WebSocket bounds the session. Per-connection state lives in `handleWebSocket`'s closure;
  nothing persists across connections unless explicitly checkpointed by `Parawing.freezeSession`.
- Each `Page.navigate` loads a fresh anonymous PageScript isolate via `HostIsolateLoader.load`
  (`createDenoIsolateLoader` or `env.LOADER.load`) and kills the previous one.
- Wasm panics unwind (`packages/core/.cargo/config.toml`, symlinked into `renderer-core`), so the
  live DOM survives a panic. `scene-host-wasm` stays `abort`.
- The DevTools frontend is optional: `--config=devtools` stages Chrome's prebuilt one at
  `/inspector/`, and dev falls back to Chrome's hosted one without it (`resolveInspectorBaseUrl`,
  `packages/engine/src/inspector.ts`). Always send `devtoolsFrontendUrl`, or Chrome's **inspect**
  link does nothing.
- `/devtools/page/<id>` selects page mode, which never announces the page as a child target;
  Puppeteer must use `/devtools/browser`.
- CDP types come from `devtools-protocol`. Declare `Parawing.*` methods and extra fields in
  `cdp/protocol-extensions.ts`, and bump the root `pnpm.overrides` pin with the engine's version.
- A new target has a live `about:blank` document: `ensurePageScript` (`cdp/dom.ts`) starts a lazy
  isolate, because many clients evaluate without navigating.
- Layout is incremental. Work done at box construction needs explicit `CONSTRUCT_BOX` damage.
- Partial frames are composited in the renderer isolate (`SceneRasterizer`), so CDP clients
  never see one. The terminal scene stream is the exception; see `packages/engine/src/rbi.ts`.
- `history.pushState` stays in the document unless the navigate URL opts in with
  `?ks_refetch_on_pushstate=1`.

## Host & isolate runtime invariants

Do not undo these.

- The sandbox ships a pure-JS `MessagePort`; page JS must never reach the native one.
- Every outbound request needs a deadline, and an ignored response body must be cancelled.
- Deno child isolates (`packages/deno-host`) run without `--allow-*` permissions and pass V8/glibc
  flags masking host-specific SIMD so `CRIU 4.1.1` snapshots remain portable across hosts.

## Editing the in-isolate code

The loaded isolates (`dom-shim`, `page-script`, `page-renderer`, `worker-script`) are TypeScript
bundled to strings that the engine passes to `HostIsolateLoader.load`. All of them typecheck under
`pnpm run check`; do not add `@ts-nocheck`. Several page-script import specifiers
(`cloudflare:*`, `node:*`, `./wasm-glue.js`, `./core_bg.wasm`, `./dom-shim.js`) must survive
bundling unchanged: they are external and resolved by the loaded isolate's module map.

Changes under those packages, and under `packages/core/`, need `pnpm run build` (or a restart of
`pnpm run dev`), which rebuilds them with Bazel; `packages/engine/src` hot-reloads in dev.
`console.log` in the page isolate surfaces as CDP `Runtime.consoleAPICalled`.

## Building

Bazel builds and tests everything; the root `package.json` scripts are front ends to it. Add a
build step or check as a Bazel target, not as a pnpm script or a script that CI calls directly.
`pnpm run build` (`bazel run //packages/engine:dev_build`) copies the wasm, the loaded-isolate
bundles and the RBI files into the source tree, where dev harnesses and tools outside Bazel read
them. `bazel build //packages/rust-host:parawing_rust_host_bin` builds the native Rust host binary.
The exceptions run cargo through rustup: the vendor patch workflow and the memprof build
(`pnpm run dev:memprof`).

## Vendored crate patches

Bazel applies `scripts/patches/<crate>-<version>/` to the registry source itself, so it builds only
committed patch files. Cargo builds patched crates (blitz, parley, taffy, stylo, selectors, boa and others) through the
root `Cargo.toml`'s `[patch.crates-io]`, pointing at `packages/core/target/vendor-patched/`.
`pnpm run vendor:apply` materializes each crate as a git repository: the registry source tagged
`vendor-base`, then the series from `scripts/patches/<crate>-<version>/` applied with `git am`.

To change a patch, iterate with `cargo check` from `packages/core/`, commit inside the vendor
tree, then run `pnpm run vendor:regen -- <crate>`; Bazel sees the change only after the regen.
Uncommitted or unregenerated work is lost when the tree is rebuilt, which any patch-file change or
`rm -rf packages/core/target` causes. Full workflow: [scripts/patches/README.md](scripts/patches/README.md).

## Running

```bash
pnpm install                                           # first time
pnpm run build                                         # Bazel build and stage wasm/worker bundles
pnpm run check                                         # bazel test //:check, then tracked-file checks
bazel build //packages/rust-host:parawing_rust_host_bin
pnpm run dev                                           # Bazel build, then local engine on :8787
pnpm run test:e2e <file-substring>
pnpm run test:wpt --filter <substring>
pnpm run test:playwright --filter <substring>
pnpm run test:puppeteer --filter <substring>           # after pnpm run pptr:setup
```

Use an explicit `PARAWING_PORT` or `--port` when other engines may be running, and stop only the
engine processes you started.

- **Deploying:** Always `git push` committed work immediately; only run Cloudflare `pnpm run deploy` when asked.
- **Tracing:** send a `traceparent` header (or a bare trace id in it) with `pnpm dev:tracing` running.
- **WPT:** `test:wpt` starts, health-checks and stops its own engines every `--batch-size` tests.
  It refuses to start if a port in its range is taken. `-j N` runs N engines and uses ports
  `port` to `port+2N-1`. It fails on any deviation from `tests/wpt-expectations.json`, including
  unexpected passes; rebaseline with `--update-expectations` in a separate commit. Tests with
  variants are enrolled once per variant.
- **testdriver:** `test_driver.click`, `send_keys` and `Actions().send()` dispatch real CDP input.
  Other actions keep upstream's "not implemented" error, and `in_automation` stays `false`.

## Conventions

### Branches and commits

- Pull/rebase from an up-to-date `origin/main` before editing, commit continuously in small atomic commits, and push immediately (`git push`).
- Read `git log --oneline` first. Use a one-line imperative summary of about 70 characters, and a
  body that explains why.
- Keep commits atomic: one reason per commit. Squash work-in-progress commits before review.
- Sign off every commit (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md).
- Do not commit plans, findings, inventories or scratch reproductions. `PLAN.md`, `TODO.md` and
  `FINDINGS.md` are gitignored for that purpose. Keep durable findings as a code comment.
- Always push committed changes to `origin` immediately; never leave dangling local commits or diffs.

### Code style

- Put durable engine behavior (layout, geometry, parsing, traversal, other stateful work) in
  Rust. Keep TypeScript to API wiring, lifecycle and callback delivery, unless the logic owns
  page-realm semantics or Rust cannot observe the state it needs.
- TypeScript shim classes use explicit getters and setters, with closure-scoped helpers for shared
  state.
- In Rust, pair `borrow()` and `borrow_mut()` with an explicit `drop()` before returning, and
  validate node ids before passing them to Blitz.
- Comment blocks have at most four lines of at most 100 columns and no blank interior lines
  (`scripts/lint/comment-policy.mjs` lists the exemptions).
- Hand-written type declarations go in `.ts` files, never `.d.ts`: `skipLibCheck` would skip
  them. A declaration for a module supplied at runtime (`./wasm-glue.js`, `./__ks_*.js`) uses
  `export declare` and the `@ks-declaration-twin` marker, which fails the build if it is bundled.
- Every tracked TypeScript file must be covered by a typechecked tsconfig, and every tsconfig must
  set `types` (`scripts/check-ts-coverage.mjs`).
- In bundled packages, write a function inside a block as `const f = function …`. esbuild hoists
  block-level function declarations out of their block under `alwaysStrict`.

### Tests

- Never run a full suite unless asked; the runners are slow and memory-hungry. CI runs `//:check`,
  `//:rust_lint`, `core`/`cli` tests, Tier 2 CRIU capsule tests, and the hermetic e2e smoke gate
  in `.github/workflows/ci.yml`. Before reporting work complete, run `pnpm run check` and the
  smallest relevant e2e subset. Uncaught host runtime errors fail a run even if assertions pass.
- Do not put `--` before test arguments; pnpm forwards it and the runners misread it.
- Prefer a hermetic e2e test (`packages/engine/test/e2e/**.e2e.test.ts`) over a script or demo.
  They boot the engine in-process and drive it over CDP. Give each test its own markup with
  `setContent` (`test/e2e/set-content.ts`); add a `/__fixtures/*` route only when the page needs a
  real origin.
- For a WPT failure: reproduce the smallest failing unit in a scratch script, fix it, rerun the
  affected subtree with `--filter`, rebaseline in a separate commit, then add a hermetic e2e test.

## Out of scope unless asked

- Running iframe JS in the parent isolate. Iframes render, and script-free same-origin
  `contentDocument` supports a partial mutation subset.
- Service and shared workers. Dedicated workers work, except module workers and `importScripts`.
- A live SVG DOM. Inline `<svg>` is painted from a usvg snapshot that DOM mutations refresh;
  SVG-specific interfaces are `Element` aliases.
- Synchronous XHR. The isolate bridge does not block the JS thread on network I/O.
- A fake `crypto.subtle`; the Deno/JS host runtime provides the real one.
- WebGL, WebGPU, WebAudio, WebRTC, MediaStream and anti-bot fingerprinting.
- Persistent storage across connections outside explicit `Parawing.freezeSession` / `thawSession`
  checkpoints, and WebDriver; Parawing speaks CDP.
