<img width="150" src=".github/assets/parawing_logo.png" alt="Parawing" />

# Parawing

Secure delegated agent co-browser for humans and AI agents to share live web sessions with passkey authority, blind credential brokering, epoch-fenced human handoff, and 0-RTT `KSC2` scene compositing (forked from Kitesurf). **[Live Co-Browser Demo](https://maceip.github.io/parawing/)** · **[Security & OpenVEX Ledger](https://maceip.github.io/parawing/security.html)** · **[Dependency Integrity](deps/README.md)**

## Live Browser Handoff

![Live Parawing browser demo: autonomous agent browsing aol.com and human Take Control handoff](.github/assets/agent_handoff_demo.gif)

An autonomous agent casually browses `aol.com` inside a server-side Rust/Blitz + zero-permission Deno V8 isolate until a human clicks **Take Control** to advance the monotonic epoch lease, verify the domain-locked egress gate, and hand back ([`record-browser-handoff.mjs`](demo/e2e/record-browser-handoff.mjs)).

## Architecture

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'background': '#faf6f0', 'lineColor': '#475569', 'edgeLabelBackground': '#faf6f0', 'tertiaryColor': '#f5efe6'}}}%%
flowchart TB
  subgraph Clients["Clients & 0-RTT Co-Browsers"]
    Agent(["AI Agent · CDP & Onboarding SDK"]):::client
    Human(["Human · Browser UI, CLI & Vivari KSC2"]):::client
  end
  subgraph Authority["Session Authority & Continuity (engine · rust-host)"]
    Hub["SessionManager · Epoch Leases & CDP / RBI Router"]:::hub
    Auth[["device-authority · WebAuthn L3 & Blind Vault"]]:::hub
    State[("Tier 0 Warm · Tier 1 Journal · Tier 2 CRIU 4.1.1")]:::gate
  end
  subgraph Sandbox["Zero-Permission Isolate & Blitz Core (PRWP 0x50525750)"]
    Deno["deno-host · V8 PageScript & Worker Sub-Isolates"]:::sandbox
    Core["core · Blitz HTML / Stylo / Taffy / Parley / Vello + KSC2"]:::sandbox
    Egress{{"Out-of-Process Egress & SSRF Broker"}}:::gate
  end
  Agent -->|"CDP WebSocket"| Hub
  Human <-->|"KSC2 Stream + Take Control"| Hub
  Hub <-->|"Blind Fill & Passkeys"| Auth
  Hub -.->|"Freeze / Thaw / Roam"| State
  Hub <-->|"Framed PRWP Pipes"| Deno
  Deno <-->|"DOM, Layout & Paint"| Core
  Deno -->|"Policy-Gated Fetch"| Egress
  classDef client fill:#e9f0f7,stroke:#2563eb,stroke-width:2px,color:#0f172a
  classDef hub fill:#0a0c10,stroke:#38bdf8,stroke-width:2px,color:#ffffff
  classDef sandbox fill:#e8f1eb,stroke:#059669,stroke-width:2px,color:#064e3b
  classDef gate fill:#f7f0dc,stroke:#d97706,stroke-width:2px,color:#451a03
  style Clients fill:#f4f8fc,stroke:#bfd4ea,stroke-width:1.5px,color:#0f172a
  style Authority fill:#f5efe6,stroke:#dfd5c8,stroke-width:1.5px,color:#2a2420
  style Sandbox fill:#f2f7f4,stroke:#c8ddd0,stroke-width:1.5px,color:#064e3b
```

## Quickstart

Requires [Bazelisk](https://github.com/bazelbuild/bazelisk) (`bazel`), Node 22+, `pnpm` 9.15.4, `deno` 2.x, and Rust ([`rust-toolchain.toml`](rust-toolchain.toml)). Licensed under [Apache-2.0](LICENSE) ([NOTICE](NOTICE), [licenses/](licenses/)).

```bash
pnpm install && pnpm run build              # Stage Blitz Wasm, isolate bundles & RBI assets
pnpm run check                              # Bazel type/unit/lint/lockfile + SHA-256 OSV gates
pnpm run browser:onboard https://aol.com/   # Spawn host, browse, disconnect & Tier 0 reconnect
```
