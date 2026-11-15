<img width="200" src=".github/assets/parawing_logo.png" alt="Parawing" />

# Parawing

Parawing is a performant, secure agent co-browser built for humans and AI agents to share live
web sessions with hardware-backed passkey delegation, blind credential brokering, live human
handoff, and 0-RTT client-side scene compositing, forked from Kitesurf.

## Requirements

- [Bazelisk](https://github.com/bazelbuild/bazelisk), installed as `bazel`
- Node.js 22 or newer
- `pnpm` 9.15.4
- `deno` 2.x (sandboxed V8 isolate host runtime)
- Rust toolchain matching [rust-toolchain.toml](rust-toolchain.toml) (for `parawing-cli` and `parawing-rust-host`)
- On macOS: GNU tar (`brew install gnu-tar`), plus an optional local Linux hypervisor (OrbStack or Docker) for Tier 2 `CRIU 4.1.1` process freeze/thaw

## Architecture

- **`packages/core` (Blitz / Stylo / Taffy / Parley / Vello):** Rust browser core compiled to WebAssembly (`parawing-core`) and native static/host libraries (`parawing_core_host`). Owns HTML5 parsing, CSS cascade/layout, text shaping, 2D software rasterization, Boa JS fallback, and `KSC2` scene recording and client compositing.
- **`packages/deno-host`:** Zero-permission Deno/V8 child execution host (`--no-prompt --no-config --no-lock --no-code-cache` with no `--allow-*` permissions and `--v8-flags=--disallow-code-generation-from-strings`) with an embedded V8 page/realm evaluator and an out-of-process egress broker enforcing outbound URL policy, private-network blocking, and SSRF checks.
- **`packages/rpc-transport`:** Framed `PRWP` binary pipe (`0x50525750`, 16-byte header) with incremental frame decoding, streaming binary chunks, capability tables, credit flow control, and freeze/thaw coordination over stdio pipes or Unix domain sockets.
- **`packages/device-authority` + `packages/rust-host`:** Hardware-backed Walkaway `ControlHub` handoff, WebAuthn L2/L3 passkey delegation, tokenized (`pwtok_`) and sealed credential brokering, macOS Keychain / encrypted vault storage, and live `CRIU 4.1.1` (Linux or macOS local Linux capsule) or signed Tier 1 portable state freeze/thaw/roam checkpointing.
- **`KSC2` 0-RTT client compositor & encrypted input journal:** Binary vector/tile display-list deltas with tile-hash resynchronization (`rbi-v2`), speculative client-side scroll and pointer handling, and sealed local input journaling (`rbi-input-journal`).

## Build and Test

```bash
pnpm install
pnpm run build
pnpm run check
pnpm run test:unit
bazel test //packages/device-authority:lib_test //packages/rust-host:host_test
pnpm run test:e2e page-script-demo.e2e.test.ts
```

Before rebuilding or checking a branch change, stage native and WebAssembly outputs with `pnpm run build`. Keep individual Bazel test selections targeted rather than running full WPT or Playwright suites unintentionally.

## CLI and Protocol Endpoints

- **Native client:** Build and run the client in `packages/parawing-cli` (`cargo run --manifest-path packages/parawing-cli/Cargo.toml -- <url>`).
- **CDP WebSocket endpoints:** `/devtools/browser` (browser target discovery) and `/devtools/page/parawing` (page-mode CDP session).
- **RBI binary scene stream:** `/rbi/ws` (`KSC2` reliable scene frames, scroll/pointer datagrams, credit flow control, and tile-hash delta resync).
- **Host ControlHub socket:** `0600` Unix domain socket managed by `parawing-rust-host` for session handoff, credential fill approvals, WebAuthn assertion signing, and session roam.

## Packages

| Package                                                  | Role                                                                    |
| -------------------------------------------------------- | ----------------------------------------------------------------------- |
| [`packages/core`](packages/core)                         | Rust browser core (HTML, CSS, layout, paint, Boa, `KSC2` codec)         |
| [`packages/deno-host`](packages/deno-host)               | Zero-permission Deno/V8 child isolate host and egress broker            |
| [`packages/device-authority`](packages/device-authority) | Hardware-bound key custody, Keychain vault, WebAuthn signing            |
| [`packages/dom-shim`](packages/dom-shim)                 | In-isolate DOM, Event, CSSOM, and Generated WebIDL bindings             |
| [`packages/engine`](packages/engine)                     | CDP server, session authority, mandates, `KSC2` server, isolates        |
| [`packages/jsrpc-types`](packages/jsrpc-types)           | Shared TypeScript JSRPC contracts between host and isolates             |
| [`packages/page-renderer`](packages/page-renderer)       | Stateless scene rasterizer runtime with cached WebAssembly resources    |
| [`packages/page-script`](packages/page-script)           | Per-page isolate runtime, navigation, and DOM/eval dispatch             |
| [`packages/parawing-cli`](packages/parawing-cli)         | Native Rust terminal browser client and RBI scene viewer                |
| [`packages/renderer-core`](packages/renderer-core)       | Stripped `SceneRasterizer` WebAssembly slice of `packages/core`         |
| [`packages/rpc-transport`](packages/rpc-transport)       | Framed `PRWP` RPC codec, capability table, and pipe session             |
| [`packages/rust-host`](packages/rust-host)               | Native Tokio host, `ControlHub` socket, `CRIU 4.1.1`/Tier 1 freeze/thaw |
| [`packages/scene-host-wasm`](packages/scene-host-wasm)   | Local WebAssembly scene rasterizer staged for `parawing-cli`            |
| [`packages/script-gate`](packages/script-gate)           | Shared SRI, CSP `script-src`, MIME, mixed-content, sandbox gate         |
| [`packages/worker-script`](packages/worker-script)       | Isolated child runtime for page `new Worker()` execution                |

## License

Licensed under [Apache-2.0](LICENSE). Third-party attributions and notices live in [NOTICE](NOTICE) and [licenses/](licenses/).
