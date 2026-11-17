#!/usr/bin/env bash
# Copyright (c) 2026 Cloudflare, Inc.
# Licensed under the Apache 2.0 license found in the LICENSE file or at:
# https://opensource.org/licenses/Apache-2.0

# Build or hydrate Parawing's Wasm/isolate bundles (`//packages/engine:dev_build`) and native
# binaries (`parawing_rust_host_bin`, `parawing`) using a 96-vCPU Limrun sandbox (over HTTPS :443
# when direct gRPC :4443 is proxy-restricted), Limrun's RBE remote cache, and Limrun Asset Storage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${PARAWING_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
FORCE_REBUILD=0
HYDRATE_ONLY=0
KEEP_SANDBOX=0
IF_AUTHENTICATED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_DIR="$2"
      shift 2
      ;;
    --force-rebuild)
      FORCE_REBUILD=1
      shift
      ;;
    --hydrate-only)
      HYDRATE_ONLY=1
      shift
      ;;
    --keep-sandbox)
      KEEP_SANDBOX=1
      shift
      ;;
    --if-authenticated)
      IF_AUTHENTICATED=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: bazel/limrun/sandbox-hydrate.sh [--repo <dir>] [--force-rebuild] [--hydrate-only] [--if-authenticated] [--keep-sandbox]

Hydrates gitignored Wasm/worker bundles and native binaries (`dev_build`,
`parawing-rust-host`, `parawing`) from Limrun Asset Storage, or builds them on a
96-vCPU Limrun sandbox backed by Limrun's remote Bazel cache.
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$HOME/.deno/bin:/usr/local/bin:$PATH"

read_dotenv_key() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  local val
  val="$(
    sed -n 's/^[[:space:]]*\(export[[:space:]]\{1,\}\)\{0,1\}LIM_API_KEY[[:space:]]*=[[:space:]]*//p' "$file" \
      | tail -n 1 \
      | sed -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
  )"
  [[ -n "$val" ]] || return 1
  printf '%s' "$val"
}

ensure_lim_auth() {
  if [[ -n "${LIM_API_KEY:-}" ]]; then
    return 0
  fi
  if [[ -s "${HOME:-}/.gemini/lim/config.yaml" && ! -s "${HOME:-}/.lim/config.yaml" ]]; then
    mkdir -p "${HOME}/.lim"
    ln -sfn "${HOME}/.gemini/lim/config.yaml" "${HOME}/.lim/config.yaml"
  fi
  if [[ -s "${HOME:-}/.lim/config.yaml" ]]; then
    return 0
  fi
  for candidate in \
    "${REPO_DIR}/.limrun.env" \
    "${HOME:-}/.config/limrun/env" \
    "${HOME:-}/trap/.env"; do
    if key="$(read_dotenv_key "$candidate")"; then
      export LIM_API_KEY="$key"
      return 0
    fi
  done
  if [[ "$IF_AUTHENTICATED" -eq 1 ]]; then
    echo "[limrun-parawing] Skipping Limrun hydration (no Limrun credentials configured)."
    exit 0
  fi
  echo "sandbox-hydrate.sh: No Limrun API key configured (run 'lim login' or set LIM_API_KEY)." >&2
  return 1
}

compute_lock_hash() {
  (
    env -C "$REPO_DIR" sha256sum \
      MODULE.bazel \
      MODULE.bazel.lock \
      Cargo.lock \
      packages/rust-host/Cargo.lock \
      packages/parawing-cli/Cargo.lock \
      packages/device-authority/Cargo.lock \
      pnpm-lock.yaml
    find "$REPO_DIR/scripts/patches" -type f -print0 | sort -z | xargs -0 sha256sum
  ) | sha256sum | cut -c1-16
}

LOCK_HASH="$(compute_lock_hash)"
ASSET_NAME="parawing-linux-x86_64-${LOCK_HASH}.tar.gz"
SHA_ASSET_NAME="${ASSET_NAME}.sha256"
STAMP_FILE="$REPO_DIR/dist/limrun-bin/.limrun-stamp"

if [[ "$FORCE_REBUILD" -eq 0 \
   && -f "$STAMP_FILE" \
   && -f "$REPO_DIR/packages/core/pkg/parawing_core_bg.wasm" \
   && -f "$REPO_DIR/packages/engine/public/rbi/scene_host.wasm" \
   && -x "$REPO_DIR/dist/limrun-bin/parawing-rust-host" \
   && -x "$REPO_DIR/dist/limrun-bin/parawing" ]]; then
  if [[ "$(cat "$STAMP_FILE")" == "$ASSET_NAME" ]]; then
    echo "[limrun-parawing] Already hydrated ($ASSET_NAME) in $REPO_DIR"
    exit 0
  fi
fi

ensure_lim_auth

TMP_WORK="$(mktemp -d /tmp/limrun-parawing.XXXXXX)"
cleanup() {
  rm -rf "$TMP_WORK"
  if [[ "$KEEP_SANDBOX" -eq 0 && -n "${SANDBOX_ID:-}" ]]; then
    lim gradle delete "$SANDBOX_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

verify_pulled_archive() {
  local archive="$1"
  local sha_id
  sha_id="$(lim asset list --name "$SHA_ASSET_NAME" --json 2>/dev/null | node -e '
    const items = JSON.parse(require("fs").readFileSync(0, "utf8") || "[]");
    process.stdout.write(items[0]?.id || "");
  ' || true)"
  if [[ -n "$sha_id" ]] && lim asset pull "$sha_id" -o "$TMP_WORK" >/dev/null 2>&1; then
    local expected actual
    expected="$(awk '{print tolower($1)}' "$TMP_WORK/$SHA_ASSET_NAME")"
    actual="$(sha256sum "$archive" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
      echo "[limrun-parawing] SHA-256 mismatch on $archive: got $actual, expected $expected" >&2
      return 1
    fi
  fi
  return 0
}

if [[ "$FORCE_REBUILD" -eq 0 ]]; then
  echo "[limrun-parawing] Checking Limrun Asset Storage for $ASSET_NAME..."
  ASSET_ID="$(lim asset list --name "$ASSET_NAME" --json 2>/dev/null | node -e '
    const items = JSON.parse(require("fs").readFileSync(0, "utf8") || "[]");
    process.stdout.write(items[0]?.id || "");
  ' || true)"
  if [[ -n "$ASSET_ID" ]] \
     && lim asset pull "$ASSET_ID" -o "$TMP_WORK" >/dev/null \
     && verify_pulled_archive "$TMP_WORK/$ASSET_NAME"; then
    tar -xzf "$TMP_WORK/$ASSET_NAME" -C "$REPO_DIR"
    mkdir -p "$(dirname "$STAMP_FILE")"
    printf '%s\n' "$ASSET_NAME" > "$STAMP_FILE"
    echo "[limrun-parawing] Hydrated $REPO_DIR from Limrun Asset Storage ($ASSET_NAME, $ASSET_ID)"
    exit 0
  fi
  if [[ "$HYDRATE_ONLY" -eq 1 ]]; then
    echo "[limrun-parawing] Asset $ASSET_NAME not found in Limrun Asset Storage (--hydrate-only set)." >&2
    exit 1
  fi
fi

echo "[limrun-parawing] Provisioning 96-vCPU Limrun sandbox for parawing ($LOCK_HASH)..."
SANDBOX_JSON="$(lim gradle create --display-name "parawing-${LOCK_HASH:0:8}" --inactivity-timeout 30m --hard-timeout 60m --label "project=parawing" --json)"
SANDBOX_ID="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).metadata.id)' <<<"$SANDBOX_JSON")"
echo "[limrun-parawing] Syncing workspace to sandbox $SANDBOX_ID..."

env -C "$REPO_DIR" lim gradle sync --id "$SANDBOX_ID" >/dev/null

CACHE_TOKEN="$(lim access-token create --permission 'remotecache:*:all' --permission 'remoteexecution:*:all' --ttl-seconds 3600 --quiet)"
SETUP_JSON="$(NODE_USE_ENV_PROXY=1 node -e '
  const path = require("path"), fs = require("fs"), cp = require("child_process");
  const limBin = fs.realpathSync(cp.execFileSync("which", ["lim"], { encoding: "utf8" }).trim());
  const limRoot = path.resolve(path.dirname(limBin), "..");
  const Limrun = require(path.join(limRoot, "node_modules/@limrun/api")).default;
  const { readConfig } = require(path.join(limRoot, "dist/lib/config"));
  const { getBazelSetup } = require(path.join(limRoot, "dist/lib/bazel-setup"));
  const cfg = readConfig();
  const client = new Limrun({ apiKey: process.env.LIM_API_KEY || cfg.apiKey, baseURL: cfg.apiEndpoint });
  getBazelSetup(client).then(j => process.stdout.write(JSON.stringify(j)));
')"
RBE_ENDPOINT="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).endpoint)' <<<"$SETUP_JSON")"
RBE_INSTANCE="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).instanceName)' <<<"$SETUP_JSON")"

env -C "$REPO_DIR" lim gradle run \
  --id "$SANDBOX_ID" \
  --no-sync \
  --timeout 3600 \
  --env "LIM_CACHE_TOKEN=$CACHE_TOKEN" \
  --env "RBE_ENDPOINT=$RBE_ENDPOINT" \
  --env "RBE_INSTANCE=$RBE_INSTANCE" \
  -- bash -ce '
    mkdir -p "$HOME/.local/bin"
    export PATH="$HOME/.local/bin:/opt/mise/installs/python/3/bin:$PATH"
    if ! command -v bazelisk >/dev/null 2>&1; then
      curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v1.25.0/bazelisk-linux-amd64 -o "$HOME/.local/bin/bazelisk"
      chmod +x "$HOME/.local/bin/bazelisk"
      ln -sfn "$HOME/.local/bin/bazelisk" "$HOME/.local/bin/bazel"
    fi
    OUT_BASE="$(bazel --output_user_root=/tmp/bazel-parawing info output_base)"
    COMMON_FLAGS=(
      --jobs=96
      --remote_cache="$RBE_ENDPOINT"
      --remote_instance_name="$RBE_INSTANCE"
      --remote_header="Authorization=Bearer $LIM_CACHE_TOKEN"
      --remote_upload_local_results=true
      --remote_cache_compression
    )
    cat > /tmp/glibc_compat.c <<'\''CEOF'\''
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
int vsscanf(const char *, const char *, __builtin_va_list);
__asm__(".symver strtol, strtol@GLIBC_2.2.5");
__asm__(".symver strtoul, strtoul@GLIBC_2.2.5");
__asm__(".symver vsscanf, vsscanf@GLIBC_2.2.5");
long __isoc23_strtol(const char *nptr, char **endptr, int base) {
  return strtol(nptr, endptr, base);
}
unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base) {
  return strtoul(nptr, endptr, base);
}
int __isoc23_sscanf(const char *s, const char *fmt, ...) {
  __builtin_va_list ap;
  __builtin_va_start(ap, fmt);
  int r = vsscanf(s, fmt, ap);
  __builtin_va_end(ap);
  return r;
}
CEOF
    cc -O2 -fPIC -fno-builtin -c /tmp/glibc_compat.c -o /tmp/glibc_compat.o
    bazel --output_user_root=/tmp/bazel-parawing run "${COMMON_FLAGS[@]}" //packages/engine:dev_build
    bazel --output_user_root=/tmp/bazel-parawing build "${COMMON_FLAGS[@]}" \
      --linkopt=-Wl,--defsym=pidfd_spawnp=0 \
      --linkopt=-Wl,--defsym=pidfd_getpid=0 \
      //packages/rust-host:parawing_rust_host_bin \
      //packages/parawing-cli:parawing_playback \
      @rust_tools//:cargo @rust_tools//:rustc
    RUST_TOOLS_BIN="$OUT_BASE/external/rules_rust++rust_host_tools+rust_tools/bin"
    PATH="$RUST_TOOLS_BIN:$PATH" RUSTC="$RUST_TOOLS_BIN/rustc" "$RUST_TOOLS_BIN/cargo" rustc \
      --release --locked --manifest-path packages/parawing-cli/Cargo.toml --bin parawing \
      --target-dir /tmp/parawing-cli-target -j 96 -- \
      -C link-arg=/tmp/glibc_compat.o \
      -C link-arg=-Wl,--defsym=pidfd_spawnp=0 \
      -C link-arg=-Wl,--defsym=pidfd_getpid=0
    mkdir -p dist/limrun-bin
    cp -L bazel-bin/packages/rust-host/parawing_rust_host_bin dist/limrun-bin/parawing-rust-host
    cp -L /tmp/parawing-cli-target/release/parawing dist/limrun-bin/parawing
    chmod 0755 dist/limrun-bin/parawing-rust-host dist/limrun-bin/parawing
    tar -czf /tmp/parawing-out.tar.gz \
      packages/core/pkg \
      packages/renderer-core/pkg \
      packages/engine/public/rbi \
      packages/dom-shim/dist \
      packages/page-script/dist \
      packages/page-renderer/dist \
      packages/worker-script/dist \
      dist/limrun-bin
    cp -f /tmp/parawing-out.tar.gz .limrun-parawing-artifacts.tar.gz
  '

env -C "$REPO_DIR" lim gradle pull-file .limrun-parawing-artifacts.tar.gz "$TMP_WORK/$ASSET_NAME" --id "$SANDBOX_ID"
(env -C "$TMP_WORK" sha256sum "$ASSET_NAME" > "$TMP_WORK/$SHA_ASSET_NAME")

for target_name in "$ASSET_NAME" "$SHA_ASSET_NAME"; do
  for old_id in $(lim asset list --name "$target_name" --json 2>/dev/null | node -e '
    for (const item of JSON.parse(require("fs").readFileSync(0, "utf8") || "[]")) console.log(item.id);
  ' || true); do
    lim asset delete "$old_id" >/dev/null 2>&1 || true
  done
done
lim asset push "$TMP_WORK/$ASSET_NAME" -n "$ASSET_NAME" >/dev/null
lim asset push "$TMP_WORK/$SHA_ASSET_NAME" -n "$SHA_ASSET_NAME" >/dev/null

tar -xzf "$TMP_WORK/$ASSET_NAME" -C "$REPO_DIR"
mkdir -p "$(dirname "$STAMP_FILE")"
printf '%s\n' "$ASSET_NAME" > "$STAMP_FILE"
echo "[limrun-parawing] Built on Limrun, pushed $ASSET_NAME (+ .sha256), and hydrated $REPO_DIR"
