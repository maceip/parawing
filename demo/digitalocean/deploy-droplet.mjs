#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Deploys server-side Parawing (`parawing-rust-host` v0.1.10 + Deno 2.x + CRIU),
// the hardened Wisp loopback relay, Caddy auto-TLS (`sslip.io` with COOP/COEP),
// and the cross-origin-isolated Vivari client assets onto the DigitalOcean droplet.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const DEMO_ROOT = resolve(REPO_ROOT, "demo");
const STATE_PATH = resolve(DEMO_ROOT, ".droplet-state.json");
const VIVARI_DIST = resolve(DEMO_ROOT, "vivari-client/dist");
const RELAY_SCRIPT = resolve(DEMO_ROOT, "digitalocean/parawing-wisp-relay.mjs");
const LOCAL_LINUX_HOST_BIN = resolve(
  REPO_ROOT,
  "bazel-bin/packages/rust-host/parawing_rust_host_bin",
);
const RELEASE_TAG = process.env.PARAWING_RELEASE_TAG || "v0.1.10";
const RELEASE_BASE = `https://github.com/maceip/parawing/releases/download/${RELEASE_TAG}`;
const ARCHIVE_NAME = `parawing-${RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz`;

function resolveSshKey() {
  for (const name of ["id_ed25519", "nimbus_lambda"]) {
    const p = resolve(homedir(), ".ssh", name);
    if (existsSync(p)) return p;
  }
  throw new Error("No matching SSH private key found in ~/.ssh");
}

function sshArgs(keyPath) {
  return ["-i", keyPath, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15"];
}

function runSsh(ip, keyPath, script) {
  execFileSync("ssh", [...sshArgs(keyPath), `root@${ip}`, "bash -se"], {
    input: script,
    stdio: ["pipe", "inherit", "inherit"],
  });
}

function waitForSsh(ip, keyPath, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      execFileSync("ssh", [...sshArgs(keyPath), `root@${ip}`, "echo ssh-ready"], {
        stdio: "ignore",
      });
      return;
    } catch {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2000);
    }
  }
  throw new Error(`Timed out waiting for SSH on root@${ip}`);
}

function main() {
  if (!existsSync(STATE_PATH)) {
    throw new Error(
      `Missing ${STATE_PATH}; run node demo/digitalocean/provision-droplet.mjs first`,
    );
  }
  if (!existsSync(resolve(VIVARI_DIST, "index.html"))) {
    throw new Error(`Missing ${VIVARI_DIST}/index.html; run node demo/scripts/build.mjs first`);
  }
  const state = JSON.parse(readFileSync(STATE_PATH, "utf8"));
  const keyPath = resolveSshKey();
  console.log(`[demo:deploy] Connecting to DigitalOcean droplet ${state.name} (${state.ip})…`);
  waitForSsh(state.ip, keyPath);

  runSsh(
    state.ip,
    keyPath,
    `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v caddy >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq software-properties-common curl unzip ca-certificates caddy debian-keyring debian-archive-keyring apt-transport-https
fi
if ! command -v criu >/dev/null 2>&1; then
  add-apt-repository -y ppa:criu/ppa || true
  apt-get update -qq
  apt-get install -y -qq criu || true
fi

if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

if ! command -v /usr/local/bin/deno >/dev/null 2>&1; then
  curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh -s v2.9.8
fi

mkdir -p /opt/parawing/bin /opt/parawing/wisp /var/www/parawing-vivari /var/lib/parawing-home
if [ ! -f /opt/parawing/bin/rbi/scene_host.wasm ]; then
  cd /tmp
  curl -fsSL -O "${RELEASE_BASE}/${ARCHIVE_NAME}"
  curl -fsSL -O "${RELEASE_BASE}/${ARCHIVE_NAME}.sha256"
  sha256sum -c "${ARCHIVE_NAME}.sha256"
  tar -xzf "${ARCHIVE_NAME}" -C /opt/parawing/bin
  chmod +x /opt/parawing/bin/parawing-rust-host /opt/parawing/bin/parawing || true
  rm -f "${ARCHIVE_NAME}" "${ARCHIVE_NAME}.sha256"
fi
`,
  );

  const remoteVer = execFileSync(
    "ssh",
    [
      ...sshArgs(keyPath),
      `root@${state.ip}`,
      "/opt/parawing/bin/parawing-rust-host --version 2>/dev/null || true",
    ],
    { encoding: "utf8" },
  ).trim();
  if (!remoteVer.startsWith("parawing-rust-host ") && existsSync(LOCAL_LINUX_HOST_BIN)) {
    const magic = readFileSync(LOCAL_LINUX_HOST_BIN).subarray(0, 4);
    if (magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46) {
      console.log("[demo:deploy] Uploading Ubuntu 24.04 Linux x86_64 parawing-rust-host ELF…");
      execFileSync(
        "scp",
        [
          ...sshArgs(keyPath),
          LOCAL_LINUX_HOST_BIN,
          `root@${state.ip}:/opt/parawing/bin/parawing-rust-host.new`,
        ],
        { stdio: "inherit" },
      );
      runSsh(
        state.ip,
        keyPath,
        "chmod +x /opt/parawing/bin/parawing-rust-host.new && mv /opt/parawing/bin/parawing-rust-host.new /opt/parawing/bin/parawing-rust-host",
      );
    }
  }
  runSsh(state.ip, keyPath, "/opt/parawing/bin/parawing-rust-host --version");

  console.log("[demo:deploy] Uploading Vivari client dist and hardened Wisp relay…");
  execFileSync(
    "scp",
    [
      ...sshArgs(keyPath),
      RELAY_SCRIPT,
      `root@${state.ip}:/opt/parawing/wisp/parawing-wisp-relay.mjs`,
    ],
    { stdio: "inherit" },
  );
  execFileSync(
    "scp",
    [...sshArgs(keyPath), "-r", `${VIVARI_DIST}/.`, `root@${state.ip}:/var/www/parawing-vivari/`],
    { stdio: "inherit" },
  );

  const caddyfile = `${state.sslipHost} {
  encode zstd gzip

  @wisp path /parawing-demo-v1
  handle @wisp {
    reverse_proxy 127.0.0.1:7071
  }

  handle /status {
    rewrite * /json/version
    reverse_proxy 127.0.0.1:8788
  }

  handle_path /vivari/* {
    header Cross-Origin-Opener-Policy "same-origin"
    header Cross-Origin-Embedder-Policy "require-corp"
    header Cross-Origin-Resource-Policy "cross-origin"
    root * /var/www/parawing-vivari
    file_server
  }

  handle / {
    redir /vivari/index.html 302
  }
}
`;

  runSsh(
    state.ip,
    keyPath,
    `set -euo pipefail
cat >/etc/systemd/system/parawing-rust-host.service <<'UNIT'
[Unit]
Description=Parawing Native Rust Host (Blitz + Deno V8 + CRIU)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/parawing/bin
Environment=HOME=/var/lib/parawing-home
Environment=PARAWING_DENO_BIN=/usr/local/bin/deno
Environment=PARAWING_SCENE_HOST_DIR=/opt/parawing/bin/rbi
ExecStart=/opt/parawing/bin/parawing-rust-host --host 127.0.0.1 --port 8788
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/parawing-wisp-relay.service <<'UNIT'
[Unit]
Description=Parawing Hardened Wisp Relay for Vivari Guest Node VM
After=network.target parawing-rust-host.service

[Service]
Type=simple
WorkingDirectory=/opt/parawing/wisp
Environment=RELAY_PORT=7071
Environment=RELAY_TOKEN=parawing-demo-v1
Environment=PARAWING_PORT=8788
Environment=ALLOWED_ORIGIN=${state.httpsOrigin}
ExecStart=/usr/bin/node /opt/parawing/wisp/parawing-wisp-relay.mjs
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/caddy/Caddyfile <<'CADDY'
${caddyfile}
CADDY

systemctl daemon-reload
systemctl enable --now parawing-rust-host.service parawing-wisp-relay.service caddy.service
systemctl restart parawing-rust-host.service parawing-wisp-relay.service caddy.service

for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8788/health >/dev/null 2>&1 && curl -fsS http://127.0.0.1:7071/relay-health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS http://127.0.0.1:8788/json/version
echo ""
curl -fsS http://127.0.0.1:7071/relay-health
`,
  );

  console.log(`[demo:deploy] Deployed and verified at ${state.httpsOrigin}`);
}

main();
