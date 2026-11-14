// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! macOS local Linux hypervisor capsule driver running CRIU 4.1.1 against live Deno V8 workers.

use crate::capsule::{
    CpuBaseline, RuntimeEnvironmentSpec, CAPSULE_CACHE_LINE_BYTES, CAPSULE_PINNED_PAGE_SIZE,
};
use crate::freeze_thaw::FreezeError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const CAPSULE_IMAGE_TAG: &str = "parawing-capsule-criu:trixie-4.1.1";
pub const CAPSULE_GLIBC_TUNABLES: &str =
    "glibc.cpu.hwcaps=-AVX,-AVX2,-FMA,-AVX512F,-AVX512BW,-AVX512DQ,-AVX512VL";
const ARCHIVE_MAGIC: &[u8; 8] = b"PWCAP01\0";
const ENTRY_FILE: u8 = 1;
const ENTRY_SYMLINK: u8 = 2;
const ENTRY_DIR: u8 = 3;
static CONTAINER_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleCriuProbe {
    pub available: bool,
    pub docker_bin: Option<String>,
    pub hypervisor: String,
    pub image_tag: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct CapsuleDumpTarget {
    pub docker_bin: PathBuf,
    pub container_id: String,
    pub pid: u32,
}

impl CapsuleDumpTarget {
    pub fn set_heap_secret(&self, secret: &str) -> Result<(), FreezeError> {
        let payload = serde_json::json!({ "op": "setSecret", "secret": secret });
        send_worker_command(&self.docker_bin, &self.container_id, &payload)
    }

    pub fn inspect(&self, timeout: Duration) -> Result<CapsuleInspectReport, FreezeError> {
        inspect_container_worker(&self.docker_bin, &self.container_id, timeout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleInspectReport {
    pub pid: u32,
    pub counter: u64,
    pub has_secret: bool,
    pub dynamic_secret: Option<String>,
    pub reseed_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeartbeatReport {
    counter: u64,
    reseed_sha256: Option<String>,
}

/// Live Deno V8 worker running inside a local Linux capsule container with `/capsule/work`.
pub struct CapsuleDenoWorker {
    docker_bin: PathBuf,
    target: CapsuleDumpTarget,
}

impl CapsuleDenoWorker {
    pub fn dump_target(&self) -> &CapsuleDumpTarget {
        &self.target
    }

    pub fn pid(&self) -> u32 {
        self.target.pid
    }

    pub fn container_id(&self) -> &str {
        &self.target.container_id
    }

    pub fn set_heap_secret(&self, secret: &str) -> Result<(), FreezeError> {
        self.target.set_heap_secret(secret)
    }

    pub fn wait_counter_at_least(&self, min: u64, timeout: Duration) -> Result<u64, FreezeError> {
        wait_heartbeat(&self.docker_bin, &self.target.container_id, min, timeout)
    }

    pub fn is_alive(&self) -> Result<bool, FreezeError> {
        check_container_pid_alive(&self.docker_bin, &self.target.container_id, self.target.pid)
    }

    pub fn inspect(&self, timeout: Duration) -> Result<CapsuleInspectReport, FreezeError> {
        self.target.inspect(timeout)
    }

    pub fn destroy_now(mut self) -> Result<(), FreezeError> {
        let cid = std::mem::take(&mut self.target.container_id);
        force_remove_container(&self.docker_bin, &cid)
    }
}

impl Drop for CapsuleDenoWorker {
    fn drop(&mut self) {
        if !self.target.container_id.is_empty() {
            let _ = force_remove_container(&self.docker_bin, &self.target.container_id);
        }
    }
}

/// Deno V8 worker thawed via CRIU inside a brand-new Linux capsule container.
pub struct CapsuleRestoredWorker {
    docker_bin: PathBuf,
    container_id: String,
    pid: u32,
}

impl CapsuleRestoredWorker {
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> Result<bool, FreezeError> {
        check_container_pid_alive(&self.docker_bin, &self.container_id, self.pid)
    }

    pub fn inspect(&self, timeout: Duration) -> Result<CapsuleInspectReport, FreezeError> {
        inspect_container_worker(&self.docker_bin, &self.container_id, timeout)
    }

    pub fn into_deno_worker(mut self) -> CapsuleDenoWorker {
        let container_id = std::mem::take(&mut self.container_id);
        CapsuleDenoWorker {
            docker_bin: self.docker_bin.clone(),
            target: CapsuleDumpTarget {
                docker_bin: self.docker_bin.clone(),
                container_id,
                pid: self.pid,
            },
        }
    }
}

impl Drop for CapsuleRestoredWorker {
    fn drop(&mut self) {
        if !self.container_id.is_empty() {
            let _ = force_remove_container(&self.docker_bin, &self.container_id);
        }
    }
}

/// Manages local Linux VM capsule containers and CRIU 4.1.1 checkpoint/restore on macOS.
pub struct MacosLinuxCapsuleDriver;

impl MacosLinuxCapsuleDriver {
    pub fn probe() -> CapsuleCriuProbe {
        let Some(docker_bin) = resolve_docker_binary() else {
            return CapsuleCriuProbe {
                available: false,
                docker_bin: None,
                hypervisor: String::new(),
                image_tag: CAPSULE_IMAGE_TAG.to_string(),
                reason: "docker CLI not found for Linux capsule hypervisor".to_string(),
            };
        };
        let info = match run_docker(
            &docker_bin,
            &["info", "--format", "{{.OSType}}/{{.Architecture}}"],
        ) {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Ok(o) => {
                return CapsuleCriuProbe {
                    available: false,
                    docker_bin: Some(docker_bin.display().to_string()),
                    hypervisor: String::new(),
                    image_tag: CAPSULE_IMAGE_TAG.to_string(),
                    reason: format!("docker info failed: {}", stderr_trim(&o)),
                };
            }
            Err(e) => {
                return CapsuleCriuProbe {
                    available: false,
                    docker_bin: Some(docker_bin.display().to_string()),
                    hypervisor: String::new(),
                    image_tag: CAPSULE_IMAGE_TAG.to_string(),
                    reason: e.to_string(),
                };
            }
        };
        if !info.starts_with("linux/") {
            return CapsuleCriuProbe {
                available: false,
                docker_bin: Some(docker_bin.display().to_string()),
                hypervisor: info.clone(),
                image_tag: CAPSULE_IMAGE_TAG.to_string(),
                reason: format!("hypervisor OS is {info}, expected linux/*"),
            };
        }
        CapsuleCriuProbe {
            available: true,
            docker_bin: Some(docker_bin.display().to_string()),
            hypervisor: info,
            image_tag: CAPSULE_IMAGE_TAG.to_string(),
            reason: "Linux hypervisor capsule ready for CRIU 4.1.1".to_string(),
        }
    }

    pub fn ensure_image_ready(docker_bin: &Path) -> Result<(), FreezeError> {
        let inspect = run_docker(docker_bin, &["image", "inspect", CAPSULE_IMAGE_TAG])?;
        if !inspect.status.success() {
            build_local_capsule_image(docker_bin)?;
        }
        let check = run_docker(
            docker_bin,
            &[
                "run",
                "--rm",
                "--privileged",
                CAPSULE_IMAGE_TAG,
                "criu",
                "check",
            ],
        )?;
        ensure_ok(&check, "criu check inside capsule image")
    }

    pub fn probe_capsule_environment(
        docker_bin: &Path,
    ) -> Result<RuntimeEnvironmentSpec, FreezeError> {
        Self::ensure_image_ready(docker_bin)?;
        let tunables_env = format!("GLIBC_TUNABLES={CAPSULE_GLIBC_TUNABLES}");
        let out = run_docker(
            docker_bin,
            &[
                "run",
                "--rm",
                "-e",
                &tunables_env,
                CAPSULE_IMAGE_TAG,
                "sh",
                "-c",
                "uname -m && getconf PAGESIZE && printf '%s\\n' \"${GLIBC_TUNABLES:-none}\" && grep -m1 -E '^(Features|flags)' /proc/cpuinfo",
            ],
        )?;
        ensure_ok(&out, "probe Linux capsule environment")?;
        parse_capsule_env(&String::from_utf8_lossy(&out.stdout))
    }

    pub fn spawn_deno_worker(
        docker_bin: &Path,
        baseline: CpuBaseline,
    ) -> Result<CapsuleDenoWorker, FreezeError> {
        Self::ensure_image_ready(docker_bin)?;
        let cid = start_privileged_container(docker_bin, "parawing-cap-src")?;
        if let Err(err) = init_worker_in_container(docker_bin, &cid, baseline) {
            let _ = force_remove_container(docker_bin, &cid);
            return Err(err);
        }
        let pid = match read_deno_pid(docker_bin, &cid) {
            Ok(p) => p,
            Err(err) => {
                let _ = force_remove_container(docker_bin, &cid);
                return Err(err);
            }
        };
        Ok(CapsuleDenoWorker {
            docker_bin: docker_bin.to_path_buf(),
            target: CapsuleDumpTarget {
                docker_bin: docker_bin.to_path_buf(),
                container_id: cid,
                pid,
            },
        })
    }
}

pub fn resolve_docker_binary() -> Option<PathBuf> {
    for candidate in ["/usr/local/bin/docker", "/opt/homebrew/bin/docker"] {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let candidate = dir.join("docker");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn build_local_capsule_image(docker_bin: &Path) -> Result<(), FreezeError> {
    let dir = make_private_temp_dir("pwcap-img")?;
    let dockerfile = dir.path().join("Dockerfile");
    let body = local_capsule_dockerfile();
    if let Err(err) = std::fs::write(&dockerfile, body) {
        return Err(FreezeError::CriuExecution(format!(
            "write Dockerfile: {err}"
        )));
    }
    let out = run_docker(
        docker_bin,
        &[
            "build",
            "--platform",
            host_docker_platform(),
            "-t",
            CAPSULE_IMAGE_TAG,
            "-f",
            &dockerfile.display().to_string(),
            &dir.path().display().to_string(),
        ],
    )?;
    ensure_ok(&out, "docker build capsule image")
}

fn host_docker_platform() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "linux/amd64"
    } else {
        "linux/arm64"
    }
}

fn local_capsule_dockerfile() -> &'static str {
    concat!(
        "FROM debian:trixie-slim\n",
        "ARG TARGETARCH\n",
        "ARG DENO_VERSION=2.9.8\n",
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n",
        "    ca-certificates criu curl procps unzip && \\\n",
        "    case \"${TARGETARCH}\" in \\\n",
        "      amd64) DENO_TRIPLE=\"x86_64-unknown-linux-gnu\" ;; \\\n",
        "      arm64) DENO_TRIPLE=\"aarch64-unknown-linux-gnu\" ;; \\\n",
        "      *) exit 1 ;; \\\n",
        "    esac && \\\n",
        "    curl -fsSL \"https://github.com/denoland/deno/releases/download/v${DENO_VERSION}/deno-${DENO_TRIPLE}.zip\" -o /tmp/deno.zip && \\\n",
        "    unzip -q /tmp/deno.zip -d /usr/local/bin && \\\n",
        "    chmod 0755 /usr/local/bin/deno && \\\n",
        "    rm -f /tmp/deno.zip && \\\n",
        "    rm -rf /var/lib/apt/lists/* && \\\n",
        "    mkdir -p /capsule/work /capsule/deno_dir /capsule/ckpt\n",
        "ENV PATH=\"/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" \\\n",
        "    DENO_NO_UPDATE_CHECK=1 \\\n",
        "    GLIBC_TUNABLES=\"glibc.cpu.hwcaps=-AVX,-AVX2,-FMA,-AVX512F,-AVX512BW,-AVX512DQ,-AVX512VL\"\n",
        "RUN /usr/local/bin/deno --version && criu --version\n",
    )
}

fn parse_capsule_env(stdout: &str) -> Result<RuntimeEnvironmentSpec, FreezeError> {
    let mut lines = stdout.lines().map(str::trim).filter(|l| !l.is_empty());
    let arch = lines
        .next()
        .ok_or_else(|| FreezeError::CriuUnavailable("missing capsule uname -m".to_string()))?;
    let page_raw = lines
        .next()
        .ok_or_else(|| FreezeError::CriuUnavailable("missing capsule PAGESIZE".to_string()))?;
    let tunables_line = lines.next().unwrap_or_default();
    let cpu_line = lines.next().unwrap_or_default();

    let baseline = CpuBaseline::for_arch(arch)
        .ok_or_else(|| FreezeError::CriuUnavailable(format!("unsupported capsule arch: {arch}")))?;
    let page_size = page_raw.parse::<u32>().map_err(|e| {
        FreezeError::CriuUnavailable(format!("bad capsule page size '{page_raw}': {e}"))
    })?;
    if page_size != CAPSULE_PINNED_PAGE_SIZE {
        return Err(FreezeError::CriuUnavailable(format!(
            "capsule page size {page_size}B != {CAPSULE_PINNED_PAGE_SIZE}B"
        )));
    }
    let v8_flags = baseline.baseline_v8_flags();
    let exposed_cpu_features =
        map_capsule_cpu_features(baseline, cpu_line, tunables_line, &v8_flags);
    Ok(RuntimeEnvironmentSpec {
        os: "linux".to_string(),
        baseline,
        page_size,
        cache_line_bytes: CAPSULE_CACHE_LINE_BYTES,
        exposed_cpu_features,
        v8_flags,
        criu_available: true,
    })
}

fn map_capsule_cpu_features(
    baseline: CpuBaseline,
    cpu_line: &str,
    tunables_line: &str,
    v8_flags: &[String],
) -> Vec<String> {
    let tokens: BTreeSet<&str> = cpu_line
        .split_once(':')
        .map(|(_, rhs)| rhs)
        .unwrap_or(cpu_line)
        .split_whitespace()
        .collect();
    match baseline {
        CpuBaseline::Aarch64Armv8Baseline => map_aarch64_features(&tokens),
        CpuBaseline::X8664V2Baseline => map_x86_64_features(&tokens, tunables_line, v8_flags),
    }
}

fn map_aarch64_features(tokens: &BTreeSet<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if tokens.contains("asimd") {
        out.push("neon".to_string());
    }
    if tokens.contains("fp") {
        out.push("fp-armv8".to_string());
    }
    if tokens.contains("sve") {
        out.push("sve".to_string());
    }
    if tokens.contains("sve2") {
        out.push("sve2".to_string());
    }
    out
}

fn has_masked_hwcap(tunables_line: &str, token: &str) -> bool {
    tunables_line
        .split(['=', ',', ':'])
        .any(|part| part.trim() == token)
}

fn map_x86_64_features(
    tokens: &BTreeSet<&str>,
    tunables_line: &str,
    v8_flags: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for (raw, mapped) in [("sse4_2", "sse4.2"), ("popcnt", "popcnt"), ("cx16", "cx16")] {
        if tokens.contains(raw) {
            out.push(mapped.to_string());
        }
    }
    for (raw, hwcaps_mask, v8_disable) in [
        ("avx", "-AVX", "--no-enable-avx"),
        ("avx2", "-AVX2", "--no-enable-avx2"),
        ("fma", "-FMA", "--no-enable-fma3"),
    ] {
        let suppressed = has_masked_hwcap(tunables_line, hwcaps_mask)
            && v8_flags.iter().any(|f| f == v8_disable);
        if tokens.contains(raw) && !suppressed {
            out.push(raw.to_string());
        }
    }
    out
}

fn start_privileged_container(docker_bin: &Path, prefix: &str) -> Result<String, FreezeError> {
    let seq = CONTAINER_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!("{prefix}-{}-{seq}-{nanos}", std::process::id());
    let tunables_env = format!("GLIBC_TUNABLES={CAPSULE_GLIBC_TUNABLES}");
    let out = run_docker(
        docker_bin,
        &[
            "run",
            "-d",
            "--rm",
            "-e",
            &tunables_env,
            "--name",
            &name,
            "--network=none",
            "--privileged",
            CAPSULE_IMAGE_TAG,
            "sleep",
            "infinity",
        ],
    )?;
    ensure_ok(&out, "start capsule container")?;
    Ok(name)
}

fn check_container_pid_alive(
    docker_bin: &Path,
    container_id: &str,
    pid: u32,
) -> Result<bool, FreezeError> {
    let out = run_docker(
        docker_bin,
        &["exec", container_id, "kill", "-0", &pid.to_string()],
    )?;
    Ok(out.status.success())
}

fn inspect_container_worker(
    docker_bin: &Path,
    container_id: &str,
    timeout: Duration,
) -> Result<CapsuleInspectReport, FreezeError> {
    let rm = run_docker(
        docker_bin,
        &[
            "exec",
            container_id,
            "rm",
            "-f",
            "/capsule/work/inspect.json",
        ],
    )?;
    ensure_ok(&rm, "clear inspect.json")?;
    let payload = serde_json::json!({ "op": "inspect" });
    send_worker_command(docker_bin, container_id, &payload)?;
    poll_inspect_json(docker_bin, container_id, timeout)
}

fn init_worker_in_container(
    docker_bin: &Path,
    container_id: &str,
    baseline: CpuBaseline,
) -> Result<(), FreezeError> {
    let prep = run_docker(
        docker_bin,
        &[
            "exec",
            container_id,
            "mkdir",
            "-p",
            "/capsule/work",
            "/capsule/deno_dir",
            "/capsule/ckpt",
        ],
    )?;
    ensure_ok(&prep, "mkdir /capsule dirs")?;

    let stage = make_private_temp_dir("pwcap-worker")?;
    let worker_path = stage.path().join("worker.mjs");
    std::fs::write(&worker_path, worker_js_source())
        .map_err(|e| FreezeError::CriuExecution(format!("write worker.mjs: {e}")))?;
    let cp_target = format!("{container_id}:/capsule/work/worker.mjs");
    let cp = run_docker(
        docker_bin,
        &["cp", &worker_path.display().to_string(), &cp_target],
    )?;
    ensure_ok(&cp, "copy worker.mjs")?;

    let v8_flags = baseline.baseline_v8_flags().join(",");
    // Detach Deno via setsid and log files so CRIU sees zero pipes into containerd-shim.
    let launch_cmd = format!(
        "GLIBC_TUNABLES='{CAPSULE_GLIBC_TUNABLES}' DENO_NO_UPDATE_CHECK=1 DENO_DIR=/capsule/deno_dir \
         setsid /usr/local/bin/deno run --no-prompt --no-config --no-lock --no-code-cache \
         --allow-read=/capsule/work --allow-write=/capsule/work --v8-flags={v8_flags} \
         /capsule/work/worker.mjs </dev/null >>/capsule/work/deno.log 2>>/capsule/work/deno.err & \
         echo $! > /capsule/work/deno.pid"
    );
    let run = run_docker(docker_bin, &["exec", container_id, "sh", "-c", &launch_cmd])?;
    ensure_ok(&run, "launch capsule deno worker")
}

fn worker_js_source() -> &'static str {
    r#"const WORK = "/capsule/work";
let dynamicSecret = null;
let counter = 0;
let prngSeed = 0x9e3779b9;
let reseedSha256 = null;

function handleCmd() {
  try {
    const raw = Deno.readTextFileSync(`${WORK}/cmd.json`);
    Deno.removeSync(`${WORK}/cmd.json`);
    const cmd = JSON.parse(raw);
    if (cmd.op === "setSecret") {
      dynamicSecret = String(cmd.secret);
    } else if (cmd.op === "reseed") {
      let acc = prngSeed;
      const hex = String(cmd.entropyHex || "");
      for (let i = 0; i < hex.length; i++) {
        acc = ((acc * 33) ^ hex.charCodeAt(i)) >>> 0;
      }
      prngSeed = acc;
      reseedSha256 = cmd.reseedSha256 ? String(cmd.reseedSha256) : null;
    } else if (cmd.op === "inspect") {
      const report = {
        pid: Deno.pid,
        counter,
        hasSecret: dynamicSecret !== null,
        dynamicSecret,
        reseedSha256,
      };
      const tmp = `${WORK}/inspect.tmp`;
      Deno.writeTextFileSync(tmp, JSON.stringify(report));
      Deno.renameSync(tmp, `${WORK}/inspect.json`);
    }
  } catch (err) {
    if (!(err instanceof Deno.errors.NotFound)) {
      console.error("worker cmd err:", String(err));
    }
  }
}

setInterval(() => {
  counter += 1;
  handleCmd();
  const tmp = `${WORK}/heartbeat.tmp`;
  Deno.writeTextFileSync(tmp, JSON.stringify({ counter, reseedSha256 }));
  Deno.renameSync(tmp, `${WORK}/heartbeat.json`);
}, 40);
"#
}

fn read_deno_pid(docker_bin: &Path, container_id: &str) -> Result<u32, FreezeError> {
    for _ in 0..40 {
        let out = run_docker(
            docker_bin,
            &["exec", container_id, "cat", "/capsule/work/deno.pid"],
        )?;
        if out.status.success() {
            if let Ok(pid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() {
                return Ok(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(FreezeError::CriuExecution(
        "timed out waiting for /capsule/work/deno.pid".to_string(),
    ))
}

fn send_worker_command(
    docker_bin: &Path,
    container_id: &str,
    payload: &serde_json::Value,
) -> Result<(), FreezeError> {
    let encoded = serde_json::to_vec(payload)
        .map_err(|e| FreezeError::CriuExecution(format!("encode cmd: {e}")))?;
    let stage = make_private_temp_dir("pwcap-cmd")?;
    let local_tmp = stage.path().join("cmd.tmp");
    std::fs::write(&local_tmp, &encoded)
        .map_err(|e| FreezeError::CriuExecution(format!("write cmd.tmp: {e}")))?;
    let dst = format!("{container_id}:/capsule/work/cmd.tmp");
    let cp = run_docker(docker_bin, &["cp", &local_tmp.display().to_string(), &dst])?;
    ensure_ok(&cp, "copy cmd.tmp")?;
    let mv = run_docker(
        docker_bin,
        &[
            "exec",
            container_id,
            "mv",
            "/capsule/work/cmd.tmp",
            "/capsule/work/cmd.json",
        ],
    )?;
    ensure_ok(&mv, "activate cmd.json")?;
    wait_cmd_consumed(docker_bin, container_id, Duration::from_secs(5))
}

fn wait_cmd_consumed(
    docker_bin: &Path,
    container_id: &str,
    timeout: Duration,
) -> Result<(), FreezeError> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let chk = run_docker(
            docker_bin,
            &[
                "exec",
                container_id,
                "test",
                "!",
                "-f",
                "/capsule/work/cmd.json",
            ],
        )?;
        if chk.status.success() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(FreezeError::CriuExecution(
        "timed out waiting for Deno worker to consume cmd.json".to_string(),
    ))
}

fn wait_heartbeat(
    docker_bin: &Path,
    container_id: &str,
    min_counter: u64,
    timeout: Duration,
) -> Result<u64, FreezeError> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Some(hb) = try_read_heartbeat(docker_bin, container_id)? {
            if hb.counter >= min_counter {
                return Ok(hb.counter);
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(FreezeError::CriuExecution(format!(
        "timed out waiting for Deno counter >= {min_counter}"
    )))
}

fn try_read_heartbeat(
    docker_bin: &Path,
    container_id: &str,
) -> Result<Option<HeartbeatReport>, FreezeError> {
    let out = run_docker(
        docker_bin,
        &["exec", container_id, "cat", "/capsule/work/heartbeat.json"],
    )?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(serde_json::from_slice(&out.stdout).ok())
}

fn poll_inspect_json(
    docker_bin: &Path,
    container_id: &str,
    timeout: Duration,
) -> Result<CapsuleInspectReport, FreezeError> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let out = run_docker(
            docker_bin,
            &["exec", container_id, "cat", "/capsule/work/inspect.json"],
        )?;
        if out.status.success() {
            if let Ok(parsed) = serde_json::from_slice::<CapsuleInspectReport>(&out.stdout) {
                return Ok(parsed);
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(FreezeError::CriuExecution(
        "timed out waiting for restored Deno inspect.json".to_string(),
    ))
}

/// Runs real `criu dump` inside the source capsule and packs `/capsule` tree.
pub fn dump_capsule_target(
    target: &CapsuleDumpTarget,
) -> Result<(Vec<String>, Vec<u8>), FreezeError> {
    let docker_bin = &target.docker_bin;
    let cid = &target.container_id;
    let prep = run_docker(
        docker_bin,
        &[
            "exec",
            cid,
            "sh",
            "-c",
            "rm -rf /capsule/ckpt && mkdir -p /capsule/ckpt/dump",
        ],
    )?;
    ensure_ok(&prep, "prepare /capsule/ckpt/dump dir")?;

    let pid_str = target.pid.to_string();
    let dump_args = vec![
        "dump".to_string(),
        "--tree".to_string(),
        pid_str.clone(),
        "--images-dir".to_string(),
        "/capsule/ckpt/dump".to_string(),
        "--shell-job".to_string(),
        "--ext-unix-sk".to_string(),
        "--file-locks".to_string(),
    ];
    let dump = run_docker(
        docker_bin,
        &[
            "exec",
            cid,
            "criu",
            "dump",
            "--tree",
            &pid_str,
            "--images-dir",
            "/capsule/ckpt/dump",
            "--shell-job",
            "--ext-unix-sk",
            "--file-locks",
        ],
    )?;
    ensure_ok(&dump, "criu dump")?;

    let stage = make_private_temp_dir("pwcap-dump")?;
    let cp = run_docker(
        docker_bin,
        &[
            "cp",
            &format!("{cid}:/capsule"),
            &stage.path().display().to_string(),
        ],
    )?;
    ensure_ok(&cp, "docker cp /capsule out")?;
    let _ = run_docker(docker_bin, &["exec", cid, "rm", "-rf", "/capsule/ckpt"]);

    let packed = pack_capsule_tree(&stage.path().join("capsule"), target.pid)?;
    Ok((dump_args, packed))
}

/// Restores a packed CRIU 4.1.1 archive into a fresh Linux capsule container and reseeds PRNG.
pub fn restore_capsule_archive(
    archive_bytes: &[u8],
    reseed_entropy_hex: &str,
    reseed_digest_sha256: &str,
) -> Result<(Vec<String>, CapsuleRestoredWorker), FreezeError> {
    let docker_bin = resolve_docker_binary().ok_or_else(|| {
        FreezeError::CriuUnavailable("docker CLI not found for capsule restore".to_string())
    })?;
    MacosLinuxCapsuleDriver::ensure_image_ready(&docker_bin)?;

    let stage = make_private_temp_dir("pwcap-restore")?;
    let root = stage.path().join("capsule");
    let pid = unpack_capsule_tree(archive_bytes, &root)?;

    let dst_cid = start_privileged_container(&docker_bin, "parawing-cap-dst")?;
    match restore_into_container(
        &docker_bin,
        &dst_cid,
        &root,
        pid,
        reseed_entropy_hex,
        reseed_digest_sha256,
    ) {
        Ok(args) => Ok((
            args,
            CapsuleRestoredWorker {
                docker_bin,
                container_id: dst_cid,
                pid,
            },
        )),
        Err(err) => {
            let _ = force_remove_container(&docker_bin, &dst_cid);
            Err(err)
        }
    }
}

fn restore_into_container(
    docker_bin: &Path,
    dst_cid: &str,
    local_root: &Path,
    pid: u32,
    entropy_hex: &str,
    reseed_digest: &str,
) -> Result<Vec<String>, FreezeError> {
    let prep = run_docker(docker_bin, &["exec", dst_cid, "rm", "-rf", "/capsule"])?;
    ensure_ok(&prep, "clear dst /capsule")?;
    let cp = run_docker(
        docker_bin,
        &[
            "cp",
            &local_root.display().to_string(),
            &format!("{dst_cid}:/"),
        ],
    )?;
    ensure_ok(&cp, "copy capsule tree into dst container")?;

    let restore_args = vec![
        "restore".to_string(),
        "--images-dir".to_string(),
        "/capsule/ckpt/dump".to_string(),
        "--shell-job".to_string(),
        "--ext-unix-sk".to_string(),
        "--file-locks".to_string(),
        "-d".to_string(),
    ];
    let restore = run_docker(
        docker_bin,
        &[
            "exec",
            dst_cid,
            "criu",
            "restore",
            "--images-dir",
            "/capsule/ckpt/dump",
            "--shell-job",
            "--ext-unix-sk",
            "--file-locks",
            "-d",
        ],
    )?;
    ensure_ok(&restore, "criu restore")?;
    let _ = run_docker(docker_bin, &["exec", dst_cid, "rm", "-rf", "/capsule/ckpt"]);

    let alive = run_docker(
        docker_bin,
        &["exec", dst_cid, "kill", "-0", &pid.to_string()],
    )?;
    ensure_ok(&alive, "verify restored deno PID")?;

    let cmd = serde_json::json!({
        "op": "reseed",
        "entropyHex": entropy_hex,
        "reseedSha256": reseed_digest,
    });
    send_worker_command(docker_bin, dst_cid, &cmd)?;
    Ok(restore_args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{enforce_baseline_compatibility, CapsuleManifest};
    use crate::freeze_thaw::{
        default_prwp_inherit_fd_labels, freeze_session, generate_test_ed25519_keypair,
        thaw_session, BrokerRequestTracker, CriuBackendKind, FreezeParams, FreezeStateSnapshot,
        KeyLease, ThawOutcome, ThawParams,
    };
    use ring::signature::KeyPair;
    use std::sync::Mutex;

    fn capsule_sample_lease() -> KeyLease {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("random lease key");
        KeyLease {
            lease_id: "cap-lease-1".to_string(),
            session_id: "cap-sess-1".to_string(),
            epoch: 5,
            issued_at_ms: 1_000,
            expires_at_ms: 900_000,
            revoked: false,
            aes256_key: key,
        }
    }

    fn capsule_sample_snapshot() -> FreezeStateSnapshot {
        FreezeStateSnapshot {
            session_id: "cap-sess-1".to_string(),
            target_id: "cap-tab-1".to_string(),
            url: "https://capsule.example.test/app".to_string(),
            html: "<!DOCTYPE html><html><body><div>Capsule</div></body></html>".to_string(),
            history: vec!["https://capsule.example.test/app".to_string()],
            viewport_width: 640,
            viewport_height: 480,
            scroll_x: 0.0,
            scroll_y: 0.0,
            session_storage: BTreeMap::new(),
            non_credential_form_values: BTreeMap::new(),
            js_state_json: r#"{"source":"tier2-criu"}"#.to_string(),
            last_input_seq: 1,
            acked_scroll_seq: 1,
            freeze_wall_ms: 5_000,
            monotonic_offset_ns: 500_000_000,
        }
    }

    fn assert_no_plaintext_secret(dir: &Path, needle: &[u8]) {
        for entry in std::fs::read_dir(dir).expect("read ckpt dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                assert_no_plaintext_secret(&path, needle);
                continue;
            }
            let bytes = std::fs::read(&path).expect("read ckpt file");
            let leaked = bytes.windows(needle.len()).any(|w| w == needle);
            assert!(
                !leaked,
                "plaintext V8 heap secret found in {}",
                path.display()
            );
        }
    }

    #[tokio::test]
    async fn macos_linux_capsule_tier2_criu_freezes_and_thaws_live_deno_v8_heap() {
        let probe = MacosLinuxCapsuleDriver::probe();
        if std::env::var("PARAWING_REQUIRE_CAPSULE_CRIU").as_deref() == Ok("1") {
            assert!(probe.available, "capsule CRIU required: {}", probe.reason);
        }
        if !probe.available {
            eprintln!("skipping capsule CRIU live test: {}", probe.reason);
            return;
        }

        let docker_bin = PathBuf::from(probe.docker_bin.expect("docker_bin"));
        let env = MacosLinuxCapsuleDriver::probe_capsule_environment(&docker_bin)
            .expect("probe capsule environment");
        let manifest = CapsuleManifest::new(
            env.baseline,
            "sha256:capsule-bin",
            "sha256:capsule-v8",
            true,
        );
        enforce_baseline_compatibility(&manifest, &env).expect("capsule baseline compatible");

        let worker = MacosLinuxCapsuleDriver::spawn_deno_worker(&docker_bin, env.baseline)
            .expect("spawn Deno worker in Linux capsule");
        let src_cid = worker.container_id().to_string();
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).expect("secret nonce");
        let expected_secret = format!("v8-heap-only-secret-{}", crate::capsule::hex_encode(&nonce));
        worker
            .set_heap_secret(&expected_secret)
            .expect("inject V8 heap secret");
        let pre_freeze_counter = worker
            .wait_counter_at_least(3, Duration::from_secs(10))
            .expect("wait counter >= 3");

        let signer = generate_test_ed25519_keypair();
        let lease = capsule_sample_lease();
        let snap = capsule_sample_snapshot();
        let broker = BrokerRequestTracker::default();
        let ckpt_stage = make_private_temp_dir("pwcap-sealed").expect("ckpt dir");

        let bundle = freeze_session(FreezeParams {
            rpc: None,
            broker: &broker,
            drain_budget: Duration::from_millis(10),
            manifest: &manifest,
            env: &env,
            key_lease: &lease,
            signer: &signer,
            snapshot: &snap,
            epoch: 5,
            generation: 1,
            pid: Some(worker.pid()),
            criu_images_dir: Some(ckpt_stage.path()),
            inherit_fd_labels: default_prwp_inherit_fd_labels(),
            capsule_target: Some(worker.dump_target()),
        })
        .await
        .expect("freeze with macOS Linux capsule CRIU");

        assert!(bundle.criu_dump_error.is_none());
        let img = bundle.criu_images.as_ref().expect("CRIU image ref");
        assert_eq!(img.backend, CriuBackendKind::MacosLinuxCapsule);
        assert!(img.sealed_archive_sha256.is_some());
        assert_no_plaintext_secret(ckpt_stage.path(), b"v8-heap-only-secret-");

        worker.destroy_now().expect("destroy source container");
        let dead_check = run_docker(&docker_bin, &["inspect", &src_cid]).expect("inspect src");
        assert!(
            !dead_check.status.success(),
            "source container must be gone"
        );

        let restored_slot = Mutex::new(None);
        let outcome = thaw_session(ThawParams {
            bundle: &bundle,
            target_manifest: &manifest,
            target_env: &env,
            trusted_signer_pubkey: signer.public_key().as_ref(),
            key_lease: &lease,
            now_wall_ms: 9_000,
            monotonic_elapsed_ms: 400,
            replug_rpc: None,
            replug_parked_rpc: None,
            reseed_target_rpc: None,
            inherit_fd_labels: Vec::new(),
            capsule_restore_out: Some(&restored_slot),
        })
        .await
        .expect("thaw capsule CRIU bundle");

        let reseed_sha = match outcome {
            ThawOutcome::Tier2Criu {
                csprng_reseed_sha256,
                criu_restore_args,
                ..
            } => {
                assert!(criu_restore_args.contains(&"restore".to_string()));
                csprng_reseed_sha256
            }
            ThawOutcome::Tier1Fallback { reason, .. } => {
                panic!("expected Tier2Criu restore, got Tier1Fallback: {reason}");
            }
        };

        let restored = restored_slot
            .lock()
            .expect("lock restored slot")
            .take()
            .expect("restored worker present");
        assert!(
            restored.is_alive().expect("check alive"),
            "restored Deno dead"
        );
        std::thread::sleep(Duration::from_millis(200));
        let inspect = restored
            .inspect(Duration::from_secs(10))
            .expect("inspect restored V8 heap");
        assert_eq!(
            inspect.dynamic_secret.as_deref(),
            Some(expected_secret.as_str())
        );
        assert!(
            inspect.counter > pre_freeze_counter,
            "expected post-thaw counter {} > pre-freeze counter {}",
            inspect.counter,
            pre_freeze_counter
        );
        assert_eq!(inspect.reseed_sha256.as_deref(), Some(reseed_sha.as_str()));
    }

    #[test]
    fn parse_capsule_env_honors_x86_64_glibc_tunables_hwcaps_masking() {
        let manifest = CapsuleManifest::new(
            CpuBaseline::X8664V2Baseline,
            "sha256:x86-bin",
            "sha256:x86-v8",
            true,
        );
        let masked_out = format!(
            "x86_64\n4096\n{CAPSULE_GLIBC_TUNABLES}\nflags : fpu sse4_2 popcnt cx16 avx avx2 fma\n"
        );
        let masked_env = parse_capsule_env(&masked_out).expect("parse masked x86_64 env");
        assert_eq!(
            masked_env.exposed_cpu_features,
            vec!["sse4.2", "popcnt", "cx16"]
        );
        assert!(enforce_baseline_compatibility(&manifest, &masked_env).is_ok());

        let unmasked_out = "x86_64\n4096\nnone\nflags : fpu sse4_2 popcnt cx16 avx avx2 fma\n";
        let unmasked_env = parse_capsule_env(unmasked_out).expect("parse unmasked x86_64 env");
        assert!(unmasked_env.exposed_cpu_features.iter().any(|f| f == "avx"));
        assert_eq!(
            enforce_baseline_compatibility(&manifest, &unmasked_env),
            Err(crate::capsule::CapsuleError::ForbiddenExtensionDetected(
                "avx".to_string()
            ))
        );
    }
}

#[derive(Debug, Clone)]
struct TreeEntry {
    kind: u8,
    mode: u32,
    target_or_data: Vec<u8>,
}

fn collect_tree_entries(
    base: &Path,
    rel: &Path,
    out: &mut BTreeMap<String, TreeEntry>,
) -> Result<(), FreezeError> {
    let full = base.join(rel);
    let mut dir_entries = std::fs::read_dir(&full)
        .map_err(|e| FreezeError::CriuExecution(format!("read {}: {e}", full.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| FreezeError::CriuExecution(format!("readdir entry: {e}")))?;
    dir_entries.sort_by_key(|e| e.file_name());

    for entry in dir_entries {
        let name = entry.file_name();
        let next_rel = rel.join(&name);
        let rel_str = next_rel.to_string_lossy().replace('\\', "/");
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| {
            FreezeError::CriuExecution(format!("lstat {}: {e}", entry.path().display()))
        })?;
        insert_tree_entry(base, &next_rel, &rel_str, &entry.path(), &meta, out)?;
    }
    Ok(())
}

fn insert_tree_entry(
    base: &Path,
    next_rel: &Path,
    rel_str: &str,
    path: &Path,
    meta: &std::fs::Metadata,
    out: &mut BTreeMap<String, TreeEntry>,
) -> Result<(), FreezeError> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        let link = std::fs::read_link(path)
            .map_err(|e| FreezeError::CriuExecution(format!("readlink {}: {e}", path.display())))?;
        out.insert(
            rel_str.to_string(),
            TreeEntry {
                kind: ENTRY_SYMLINK,
                mode: 0o777,
                target_or_data: link.to_string_lossy().as_bytes().to_vec(),
            },
        );
        return Ok(());
    }
    if ft.is_dir() {
        out.insert(
            rel_str.to_string(),
            TreeEntry {
                kind: ENTRY_DIR,
                mode: file_mode_or(meta, 0o755),
                target_or_data: Vec::new(),
            },
        );
        return collect_tree_entries(base, next_rel, out);
    }
    let data = std::fs::read(path)
        .map_err(|e| FreezeError::CriuExecution(format!("read {}: {e}", path.display())))?;
    out.insert(
        rel_str.to_string(),
        TreeEntry {
            kind: ENTRY_FILE,
            mode: file_mode_or(meta, 0o644),
            target_or_data: data,
        },
    );
    Ok(())
}

fn file_mode_or(meta: &std::fs::Metadata, _default_mode: u32) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        _default_mode
    }
}

fn pack_capsule_tree(root: &Path, pid: u32) -> Result<Vec<u8>, FreezeError> {
    let mut entries = BTreeMap::new();
    collect_tree_entries(root, Path::new(""), &mut entries)?;

    let mut raw = Vec::new();
    raw.extend_from_slice(ARCHIVE_MAGIC);
    raw.extend_from_slice(&pid.to_le_bytes());
    raw.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (rel_path, entry) in &entries {
        raw.push(entry.kind);
        raw.extend_from_slice(&entry.mode.to_le_bytes());
        let path_bytes = rel_path.as_bytes();
        raw.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
        raw.extend_from_slice(path_bytes);
        raw.extend_from_slice(&(entry.target_or_data.len() as u64).to_le_bytes());
        raw.extend_from_slice(&entry.target_or_data);
    }

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&raw)
        .map_err(|e| FreezeError::Compression(format!("zlib capsule archive: {e}")))?;
    let out = enc
        .finish()
        .map_err(|e| FreezeError::Compression(format!("zlib capsule finish: {e}")))?;
    raw.zeroize();
    Ok(out)
}

fn unpack_capsule_tree(compressed: &[u8], dest_root: &Path) -> Result<u32, FreezeError> {
    let mut dec = ZlibDecoder::new(compressed);
    let mut raw = Vec::new();
    dec.read_to_end(&mut raw)
        .map_err(|e| FreezeError::Compression(format!("decompress capsule archive: {e}")))?;
    let mut cur = ArchiveCursor::new(&raw);
    let magic = cur.take(8)?;
    if magic != ARCHIVE_MAGIC {
        raw.zeroize();
        return Err(FreezeError::InvalidBundle(
            "bad capsule archive magic".to_string(),
        ));
    }
    let pid = cur.u32_le()?;
    let count = cur.u32_le()?;
    std::fs::create_dir_all(dest_root)
        .map_err(|e| FreezeError::CriuExecution(format!("create dest root: {e}")))?;
    for _ in 0..count {
        unpack_one_entry(&mut cur, dest_root)?;
    }
    raw.zeroize();
    Ok(pid)
}

fn unpack_one_entry(cur: &mut ArchiveCursor<'_>, dest_root: &Path) -> Result<(), FreezeError> {
    let kind = cur.u8()?;
    let mode = cur.u32_le()?;
    let path_len = cur.u32_le()? as usize;
    let rel_str = std::str::from_utf8(cur.take(path_len)?)
        .map_err(|_| FreezeError::InvalidBundle("non-UTF8 capsule path".to_string()))?;
    let rel_path = safe_relative_path(rel_str)?;
    let full = dest_root.join(rel_path);
    let data_len = cur.u64_le()? as usize;
    let payload = cur.take(data_len)?;

    if kind == ENTRY_DIR {
        return std::fs::create_dir_all(&full)
            .map_err(|e| FreezeError::CriuExecution(format!("mkdir {}: {e}", full.display())));
    }
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| FreezeError::CriuExecution(format!("mkdir parent: {e}")))?;
    }
    if kind == ENTRY_SYMLINK {
        let target = std::str::from_utf8(payload)
            .map_err(|_| FreezeError::InvalidBundle("non-UTF8 symlink target".to_string()))?;
        return create_symlink(target, &full);
    }
    std::fs::write(&full, payload)
        .map_err(|e| FreezeError::CriuExecution(format!("write {}: {e}", full.display())))?;
    apply_mode(&full, mode);
    Ok(())
}

fn safe_relative_path(rel: &str) -> Result<PathBuf, FreezeError> {
    let mut clean = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            std::path::Component::Normal(part) => clean.push(part),
            _ => {
                return Err(FreezeError::InvalidBundle(format!(
                    "unsafe path in capsule archive: {rel}"
                )));
            }
        }
    }
    Ok(clean)
}

fn create_symlink(target: &str, link_path: &Path) -> Result<(), FreezeError> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path).map_err(|e| {
            FreezeError::CriuExecution(format!("symlink {}: {e}", link_path.display()))
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link_path);
        Err(FreezeError::CriuUnavailable(
            "symlinks require Unix".to_string(),
        ))
    }
}

fn apply_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

struct ArchiveCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ArchiveCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FreezeError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| FreezeError::InvalidBundle("capsule archive overflow".to_string()))?;
        if end > self.bytes.len() {
            return Err(FreezeError::InvalidBundle(
                "truncated capsule archive".to_string(),
            ));
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, FreezeError> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<u32, FreezeError> {
        let arr: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| FreezeError::InvalidBundle("bad u32 in capsule archive".to_string()))?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64_le(&mut self) -> Result<u64, FreezeError> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| FreezeError::InvalidBundle("bad u64 in capsule archive".to_string()))?;
        Ok(u64::from_le_bytes(arr))
    }
}

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_private_temp_dir(prefix: &str) -> Result<TempDirGuard, FreezeError> {
    let seq = CONTAINER_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| FreezeError::CriuExecution(format!("create temp dir: {e}")))?;
    apply_mode(&dir, 0o700);
    Ok(TempDirGuard(dir))
}

fn run_docker(docker_bin: &Path, args: &[&str]) -> Result<std::process::Output, FreezeError> {
    Command::new(docker_bin)
        .args(args)
        .output()
        .map_err(|e| FreezeError::CriuExecution(format!("spawn docker {:?}: {e}", args.first())))
}

fn force_remove_container(docker_bin: &Path, container_id: &str) -> Result<(), FreezeError> {
    let out = run_docker(docker_bin, &["rm", "-f", container_id])?;
    ensure_ok(&out, "remove capsule container")
}

fn stderr_trim(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim().to_string()
}

fn ensure_ok(out: &std::process::Output, label: &str) -> Result<(), FreezeError> {
    if out.status.success() {
        return Ok(());
    }
    let err = stderr_trim(out);
    let msg = if err.is_empty() {
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    } else {
        err
    };
    Err(FreezeError::CriuExecution(format!(
        "{label} exited {}: {msg}",
        out.status
    )))
}
