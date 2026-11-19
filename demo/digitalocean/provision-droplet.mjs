#!/usr/bin/env node
// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

// Provisions or inspects the DigitalOcean Ubuntu 24.04 x86_64 droplet running
// server-side Parawing (`parawing-rust-host` + Deno + CRIU + Caddy TLS + Vivari Wisp relay).

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const DEMO_ROOT = resolve(import.meta.dirname, "..");
const STATE_PATH = resolve(DEMO_ROOT, ".droplet-state.json");
const DEFAULT_NAME = "parawing-vivari-demo";
const DEFAULT_SIZE = "s-2vcpu-4gb";
const DEFAULT_IMAGE = "ubuntu-24-04-x64";

function resolveDoToken() {
  const fromEnv = process.env.DIGITALOCEAN_ACCESS_TOKEN || process.env.DIGITAL_OCEAN_API_KEY;
  if (fromEnv && fromEnv.trim()) return fromEnv.trim();
  const candidates = [
    resolve(DEMO_ROOT, ".env"),
    resolve(homedir(), "walkaway-hackathon/.env"),
    resolve(homedir(), ".env"),
  ];
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    const match = /(dop_v1_[0-9a-f]{64})/.exec(readFileSync(file, "utf8"));
    if (match) return match[1];
  }
  throw new Error("DigitalOcean token not found; set DIGITALOCEAN_ACCESS_TOKEN");
}

async function doApi(token, method, path, body) {
  const res = await fetch(`https://api.digitalocean.com/v2${path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (res.status === 204) return null;
  const json = await res.json();
  if (!res.ok) {
    throw new Error(`DigitalOcean API ${method} ${path} (${res.status}): ${JSON.stringify(json)}`);
  }
  return json;
}

function publicIpv4(droplet) {
  const nets = droplet?.networks?.v4 || [];
  return nets.find((n) => n.type === "public")?.ip_address || "";
}

async function waitForDropletActive(token, id, timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { droplet } = await doApi(token, "GET", `/droplets/${id}`);
    const ip = publicIpv4(droplet);
    if (droplet.status === "active" && ip) return { droplet, ip };
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error(`Timed out waiting for droplet ${id} to become active`);
}

async function ensureDroplet(token, targetName) {
  const { droplets } = await doApi(token, "GET", "/droplets?per_page=100");
  const existing = droplets.find((d) => d.name === targetName);
  if (existing) {
    const { droplet, ip } = await waitForDropletActive(token, existing.id);
    return { droplet, ip, created: false };
  }
  const { ssh_keys: keys } = await doApi(token, "GET", "/account/keys?per_page=50");
  if (!keys.length) throw new Error("No SSH keys registered in DigitalOcean account");
  const { regions } = await doApi(token, "GET", "/regions?per_page=50");
  const preferred = ["sfo3", "sfo2", "nyc3", "nyc1", "tor1", "fra1"];
  const picked =
    preferred.find((slug) =>
      regions.some((r) => r.slug === slug && r.available && r.sizes.includes(DEFAULT_SIZE)),
    ) || regions.find((r) => r.available && r.sizes.includes(DEFAULT_SIZE))?.slug;
  if (!picked) throw new Error(`No DigitalOcean region currently offers ${DEFAULT_SIZE}`);
  const created = await doApi(token, "POST", "/droplets", {
    name: targetName,
    region: picked,
    size: DEFAULT_SIZE,
    image: DEFAULT_IMAGE,
    ssh_keys: keys.map((k) => k.id),
    backups: false,
    ipv6: true,
    monitoring: true,
    tags: ["parawing-demo"],
  });
  const { droplet, ip } = await waitForDropletActive(token, created.droplet.id);
  return { droplet, ip, created: true };
}

function readArgValue(argv, flag, fallback) {
  const idx = argv.indexOf(flag);
  return idx >= 0 && argv[idx + 1] ? argv[idx + 1] : fallback;
}

async function main() {
  const argv = process.argv.slice(2);
  const action = argv.find((a) => !a.startsWith("-")) || "ensure";
  const targetName = readArgValue(argv, "--name", DEFAULT_NAME);
  const statePath = resolve(readArgValue(argv, "--state", STATE_PATH));
  const token = resolveDoToken();
  if (action === "destroy") {
    const { droplets } = await doApi(token, "GET", "/droplets?per_page=100");
    const existing = droplets.find((d) => d.name === targetName);
    if (existing) {
      await doApi(token, "DELETE", `/droplets/${existing.id}`);
      console.log(JSON.stringify({ deleted: existing.id, name: targetName }));
    } else {
      console.log(JSON.stringify({ deleted: null, name: targetName }));
    }
    return;
  }
  const { droplet, ip, created } = await ensureDroplet(token, targetName);
  const sslipHost = `${ip.replace(/\./g, "-")}.sslip.io`;
  const state = {
    dropletId: droplet.id,
    name: droplet.name,
    region: droplet.region.slug,
    size: droplet.size_slug,
    ip,
    sslipHost,
    httpsOrigin: `https://${sslipHost}`,
    created,
    updatedAt: new Date().toISOString(),
  };
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
  console.log(JSON.stringify(state, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
