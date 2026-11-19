# Parawing × Vivari Chrome Extension & DigitalOcean Demo

This demo runs **Parawing's client-side `KSC2` / `CompositorV2` Wasm engine (`scene_host.wasm`) inside Vivari's in-browser Node.js VM** inside a **Manifest V3 Chrome Extension**, connected over a hardened Wisp WebSocket relay to **server-side `parawing-rust-host` (`v0.1.10`, Blitz + Deno V8 + CRIU)** on a **DigitalOcean Ubuntu 24.04 x86_64 droplet**.

## Architecture

1. **Chrome Extension (`demo/chrome-extension/`)**:
   - Manifest V3 unpacked extension (`sidePanel` + toolbar `action` + `tabs` + `storage`) with `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` (`SharedArrayBuffer` enabled).
   - Implements a resizable 3-pane workbench (`Left Controls` | `Center KSC2 Canvas` | `Right Vivari Node VM Inspector`).
   - Every control drives live state: epoch-fenced agent handoff (`Take Control` / `Hand Off to Agent` via `Parawing.transferOwnership`), remote URL navigation, active Chrome tab co-browsing, Deno V8 sub-isolate JS evaluation, 0-RTT client-side `scene_host.wasm` canvas hit-testing, P-256 capsule attestation & key lease issuance, and live CRIU/capsule session freeze & thaw on the DigitalOcean droplet.

2. **Vivari In-Browser Node.js Client (`demo/vivari-client/`)**:
   - Bundles `@vivari/core` (`Vivari.boot({ serviceWorkerUrl: false, netRelay })`) and stages `scene_host.wasm`.
   - Mounts `/parawing/scene_host.wasm` and `/parawing/client.mjs` (`guest-parawing-client.mjs`) into Vivari's virtual filesystem and spawns `node /parawing/client.mjs` directly inside the browser tab.
   - Inside Vivari's Node.js VM, `client.mjs` instantiates `scene_host.wasm` (`OP_V2_INGEST_FRAME`, `OP_V2_COMPOSITE`, `OP_V2_HIT_TEST`), dials `host.vivari.internal:8788` over Vivari's Wisp relay, streams binary `KV2\x01` `KSC2` vector display-lists (not server pixels), rasterizes them to RGBA client-side, and emits structured telemetry to the extension UI.

3. **DigitalOcean Server (`demo/digitalocean/`)**:
   - `provision-droplet.mjs`: Creates or inspects the `parawing-vivari-demo` Ubuntu 24.04 droplet (`167.99.170.67` / `https://167-99-170-67.sslip.io`).
   - `deploy-droplet.mjs`: Installs and verifies the GitHub-attested `parawing-v0.1.10-x86_64-unknown-linux-gnu.tar.gz` release binary, Deno `v2.9.8`, `criu`, `parawing-wisp-relay.mjs` (locked strictly to `127.0.0.1:8788` to prevent open-proxy abuse), and Caddy auto-TLS serving `/vivari/*` with `COOP`/`COEP`/`CORP` headers.

## Commands

```bash
# 1. Build Vivari client bundle + unpacked MV3 Chrome Extension (demo/chrome-extension/dist)
node demo/scripts/build.mjs

# 2. Provision & deploy server-side Parawing onto DigitalOcean
node demo/digitalocean/provision-droplet.mjs ensure
node demo/digitalocean/deploy-droplet.mjs

# 3. Run full Chromium --load-extension E2E verification against the live DigitalOcean droplet
node demo/e2e/verify-extension-e2e.mjs

# 4. Record the live epoch-fenced Agent Handoff GIF (.github/assets/agent_handoff_demo.gif)
node demo/e2e/record-agent-handoff.mjs
```

## Loading Unpacked in Chrome

1. Run `node demo/scripts/build.mjs`.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select `demo/chrome-extension/dist`.
3. Click the **Parawing × Vivari** toolbar icon (or open Chrome's Side Panel) to launch the live workbench connected to the DigitalOcean droplet.

## GitHub Pages Live Showcase (`parawing-aol-showcase`)

A separate dedicated DigitalOcean SFO2 droplet (`64.225.124.165` / `https://64-225-124-165.sslip.io`) powers the default GitHub Pages landing demo (`https://maceip.github.io/parawing/`, with the Security Ledger at `https://maceip.github.io/parawing/security.html`), rendering a high-contrast Parawing co-browser strictly locked to `aol.com` (`*.aol.com`) where an autonomous agent casually browses until the visitor clicks **Take Control**.

```bash
# 1. Provision & deploy the AOL-locked Parawing host onto DigitalOcean
node demo/digitalocean/provision-droplet.mjs ensure --name parawing-aol-showcase --state demo/.aol-droplet-state.json
node demo/digitalocean/deploy-aol-showcase.mjs

# 2. Build GitHub Pages (`dist-pages/index.html` + `dist-pages/security.html`) & run live Chromium E2E
node scripts/security-pages-e2e.mjs
node demo/e2e/verify-aol-showcase-e2e.mjs
```
