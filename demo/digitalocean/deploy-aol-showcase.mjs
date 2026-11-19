#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Builds the standalone AOL-locked Parawing Deno host bundle (`@parawing/deno-host` + Blitz Wasm)
// and deploys it with Deno 2.9.8 + Caddy auto-TLS onto the `parawing-aol-showcase` DO droplet.

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "../..");
const STATE_PATH = resolve(REPO_ROOT, "demo/.aol-droplet-state.json");
const DENO_HOST_PKG = resolve(REPO_ROOT, "packages/deno-host/package.json");
const BAZEL_DIST_DIR = resolve(REPO_ROOT, "bazel-bin/packages/deno-host/dist");
const ENGINE_PUBLIC_DIR = resolve(REPO_ROOT, "packages/engine/public");

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

function waitForSsh(ip, keyPath, timeoutMs = 120_000) {
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

async function stageServerBundle(stageDir) {
  console.log("[aol:deploy] Building @parawing/deno-host dist with Bazel…");
  execFileSync("bazel", ["build", "//packages/deno-host:dist", "//packages/engine:assets"], {
    cwd: REPO_ROOT,
    stdio: "inherit",
  });

  mkdirSync(join(stageDir, "dist"), { recursive: true });
  mkdirSync(join(stageDir, "src"), { recursive: true });
  mkdirSync(join(stageDir, "public"), { recursive: true });

  cpSync(join(BAZEL_DIST_DIR, "engine-bundle.mjs"), join(stageDir, "dist/engine-bundle.mjs"));
  cpSync(join(BAZEL_DIST_DIR, "child-bootstrap.js"), join(stageDir, "dist/child-bootstrap.js"));
  cpSync(ENGINE_PUBLIC_DIR, join(stageDir, "public"), { recursive: true });

  const req = createRequire(DENO_HOST_PKG);
  const { build } = req("esbuild");
  const res = await build({
    entryPoints: [resolve(REPO_ROOT, "packages/deno-host/src/aol-showcase-server.ts")],
    outfile: join(stageDir, "src/aol-showcase-bundle.mjs"),
    bundle: true,
    format: "esm",
    platform: "node",
    target: "node22",
    external: ["node:*", "../dist/engine-bundle.mjs", "../dist/child-bootstrap.js"],
    sourcemap: false,
    logLevel: "warning",
  });
  if (res.errors.length > 0) {
    throw new Error(`esbuild failed with ${res.errors.length} error(s)`);
  }
}

async function main() {
  if (!existsSync(STATE_PATH)) {
    throw new Error(
      `Missing ${STATE_PATH}; run: node demo/digitalocean/provision-droplet.mjs ensure --name parawing-aol-showcase --state demo/.aol-droplet-state.json`,
    );
  }
  const state = JSON.parse(readFileSync(STATE_PATH, "utf8"));
  const keyPath = resolveSshKey();
  const stageDir = mkdtempSync(join(tmpdir(), "parawing-aol-stage-"));

  try {
    await stageServerBundle(stageDir);
    const tarball = join(tmpdir(), `parawing-aol-${Date.now()}.tar.gz`);
    execFileSync("tar", ["-czf", tarball, "-C", stageDir, "dist", "src", "public"], {
      env: { ...process.env, COPYFILE_DISABLE: "1" },
    });

    console.log(`[aol:deploy] Connecting to ${state.name} (${state.ip} / ${state.httpsOrigin})…`);
    waitForSsh(state.ip, keyPath);

    runSsh(
      state.ip,
      keyPath,
      `set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! command -v caddy >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq curl unzip ca-certificates caddy
fi
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi
if ! command -v /usr/local/bin/deno >/dev/null 2>&1; then
  curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh -s v2.9.8
fi
mkdir -p /opt/parawing-aol /var/lib/parawing-aol-home
`,
    );

    console.log("[aol:deploy] Uploading AOL-locked Parawing bundle…");
    execFileSync(
      "scp",
      [...sshArgs(keyPath), tarball, `root@${state.ip}:/tmp/parawing-aol.tar.gz`],
      { stdio: "inherit" },
    );
    rmSync(tarball, { force: true });

    const caddyfile = `${state.sslipHost} {
  encode zstd gzip

  handle /showcase/* {
    reverse_proxy 127.0.0.1:7080
  }

  handle /health {
    reverse_proxy 127.0.0.1:7080
  }

  handle / {
    redir https://maceip.github.io/parawing/ 302
  }
}
`;

    runSsh(
      state.ip,
      keyPath,
      `set -euo pipefail
rm -rf /opt/parawing-aol/dist /opt/parawing-aol/src /opt/parawing-aol/public
tar -xzf /tmp/parawing-aol.tar.gz -C /opt/parawing-aol
rm -f /tmp/parawing-aol.tar.gz

cat >/etc/systemd/system/parawing-aol-showcase.service <<'UNIT'
[Unit]
Description=Parawing AOL-Only Showcase Host (Blitz + Zero-Perm Deno V8)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/parawing-aol
Environment=HOME=/var/lib/parawing-aol-home
Environment=SHOWCASE_HOST=127.0.0.1
Environment=SHOWCASE_PORT=7080
Environment=SHOWCASE_REGION=${state.region}
Environment=PARAWING_DENO_BIN=/usr/local/bin/deno
Environment=PARAWING_PUBLIC_DIR=/opt/parawing-aol/public
ExecStart=/usr/bin/node /opt/parawing-aol/src/aol-showcase-bundle.mjs
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/caddy/Caddyfile <<'CADDY'
${caddyfile}
CADDY

systemctl daemon-reload
systemctl enable --now parawing-aol-showcase.service caddy.service
systemctl restart parawing-aol-showcase.service caddy.service

for i in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:7080/showcase/status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS http://127.0.0.1:7080/showcase/status
echo ""
`,
    );

    console.log(`[aol:deploy] Deployed and verified on ${state.httpsOrigin}/showcase/status`);
  } finally {
    rmSync(stageDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
