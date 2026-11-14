// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! R0 reproducible capsule manifest, SHA-256 identity, and per-arch CPU baseline checks.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

/// Fixed cache-line alignment shared across capsule builds and IPC ring buffers.
pub const CAPSULE_CACHE_LINE_BYTES: usize = 64;

/// Pinned virtual memory page size enforced across capsule hosts for CRIU portability.
pub const CAPSULE_PINNED_PAGE_SIZE: u32 = 4096;

/// Cache-line padded wrapper enforcing 64-byte alignment across baseline architectures.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheAligned<T>(pub T);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CpuBaseline {
    Aarch64Armv8Baseline,
    X8664V2Baseline,
}

impl CpuBaseline {
    pub fn for_arch(arch: &str) -> Option<Self> {
        match arch {
            "aarch64" | "arm64" => Some(Self::Aarch64Armv8Baseline),
            "x86_64" | "amd64" => Some(Self::X8664V2Baseline),
            _ => None,
        }
    }

    pub fn host_default() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X8664V2Baseline
        } else {
            Self::Aarch64Armv8Baseline
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64Armv8Baseline => "armv8.0-a-baseline",
            Self::X8664V2Baseline => "x86-64-v2",
        }
    }

    pub fn rust_target_triple(self) -> &'static str {
        match self {
            Self::Aarch64Armv8Baseline => "aarch64-unknown-linux-musl",
            Self::X8664V2Baseline => "x86_64-unknown-linux-musl",
        }
    }

    pub fn required_features(self) -> &'static [&'static str] {
        match self {
            Self::Aarch64Armv8Baseline => &["neon", "fp-armv8"],
            Self::X8664V2Baseline => &["sse4.2", "popcnt", "cx16"],
        }
    }

    pub fn forbidden_features(self) -> &'static [&'static str] {
        match self {
            Self::Aarch64Armv8Baseline => &["sve", "sve2", "i8mm", "bf16"],
            Self::X8664V2Baseline => &["avx", "avx2", "fma", "avx512f", "avx512bw"],
        }
    }

    pub fn baseline_v8_flags(self) -> Vec<String> {
        match self {
            Self::Aarch64Armv8Baseline => vec![
                "--disallow-code-generation-from-strings".to_string(),
                "--arm-arch=armv8".to_string(),
            ],
            Self::X8664V2Baseline => vec![
                "--disallow-code-generation-from-strings".to_string(),
                "--no-enable-avx".to_string(),
                "--no-enable-avx2".to_string(),
                "--no-enable-fma3".to_string(),
            ],
        }
    }
}

pub fn parse_v8_flags_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn is_forbidden_v8_flag(baseline: CpuBaseline, flag: &str) -> bool {
    const COMMON_FORBIDDEN: &[&str] = &[
        "--enable-avx",
        "--enable-avx2",
        "--enable-fma",
        "--enable-fma3",
        "--enable-sve",
        "--allow-natives-syntax",
        "--no-disallow-code-generation-from-strings",
        "--no-enable-fma",
        "--no-enable-sve",
    ];
    if COMMON_FORBIDDEN.contains(&flag) {
        return true;
    }
    matches!(baseline, CpuBaseline::Aarch64Armv8Baseline)
        && flag.starts_with("--arm-arch=")
        && flag != "--arm-arch=armv8"
}

pub fn resolve_v8_flags_with_override(
    baseline: CpuBaseline,
    env_override: Option<&str>,
) -> Result<Vec<String>, CapsuleError> {
    let raw = match env_override {
        Some(v) if !v.trim().is_empty() => v,
        _ => return Ok(baseline.baseline_v8_flags()),
    };
    let parsed = parse_v8_flags_csv(raw);
    for flag in &parsed {
        if is_forbidden_v8_flag(baseline, flag) {
            return Err(CapsuleError::ForbiddenV8Flag(flag.clone()));
        }
    }
    let parsed_set: BTreeSet<&str> = parsed.iter().map(String::as_str).collect();
    for req in baseline.baseline_v8_flags() {
        if !parsed_set.contains(req.as_str()) {
            return Err(CapsuleError::MissingRequiredV8Flag(req));
        }
    }
    let mut deduped = Vec::with_capacity(parsed.len());
    for flag in parsed {
        if !deduped.contains(&flag) {
            deduped.push(flag);
        }
    }
    Ok(deduped)
}

pub fn resolved_v8_flags(baseline: CpuBaseline) -> Result<Vec<String>, CapsuleError> {
    let env_val = std::env::var("PARAWING_V8_BASELINE_FLAGS").ok();
    resolve_v8_flags_with_override(baseline, env_val.as_deref())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleManifest {
    pub version: u32,
    pub baseline: CpuBaseline,
    pub rust_target: String,
    pub page_size: u32,
    pub cache_line_bytes: usize,
    pub binary_sha256: String,
    pub v8_snapshot_sha256: String,
    pub v8_flags: Vec<String>,
    pub criu_enabled: bool,
    pub reproducible_epoch: u64,
}

impl CapsuleManifest {
    pub fn new(
        baseline: CpuBaseline,
        binary_sha256: impl Into<String>,
        v8_snapshot_sha256: impl Into<String>,
        criu_enabled: bool,
    ) -> Self {
        Self {
            version: 1,
            baseline,
            rust_target: baseline.rust_target_triple().to_string(),
            page_size: CAPSULE_PINNED_PAGE_SIZE,
            cache_line_bytes: CAPSULE_CACHE_LINE_BYTES,
            binary_sha256: binary_sha256.into(),
            v8_snapshot_sha256: v8_snapshot_sha256.into(),
            v8_flags: baseline.baseline_v8_flags(),
            criu_enabled,
            reproducible_epoch: 0,
        }
    }

    /// Build a manifest honoring validated `PARAWING_V8_BASELINE_FLAGS`.
    pub fn from_env(
        baseline: CpuBaseline,
        binary_sha256: impl Into<String>,
        v8_snapshot_sha256: impl Into<String>,
        criu_enabled: bool,
    ) -> Result<Self, CapsuleError> {
        let mut manifest = Self::new(baseline, binary_sha256, v8_snapshot_sha256, criu_enabled);
        manifest.v8_flags = resolved_v8_flags(baseline)?;
        Ok(manifest)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted_flags = self.v8_flags.clone();
        sorted_flags.sort();
        let canonical = serde_json::json!({
            "version": self.version,
            "baseline": self.baseline.as_str(),
            "rustTarget": self.rust_target,
            "pageSize": self.page_size,
            "cacheLineBytes": self.cache_line_bytes,
            "binarySha256": self.binary_sha256,
            "v8SnapshotSha256": self.v8_snapshot_sha256,
            "v8Flags": sorted_flags,
            "criuEnabled": self.criu_enabled,
            "reproducibleEpoch": self.reproducible_epoch,
        });
        canonical.to_string().into_bytes()
    }

    pub fn compute_capsule_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"parawing-capsule-manifest-v1\0");
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }

    pub fn capsule_hash_hex(&self) -> String {
        hex_encode(&self.compute_capsule_hash())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEnvironmentSpec {
    pub os: String,
    pub baseline: CpuBaseline,
    pub page_size: u32,
    pub cache_line_bytes: usize,
    pub exposed_cpu_features: Vec<String>,
    pub v8_flags: Vec<String>,
    pub criu_available: bool,
}

impl RuntimeEnvironmentSpec {
    /// Construct an emulated baseline environment matching Linux capsule constraints.
    pub fn emulated_baseline(baseline: CpuBaseline, criu_available: bool) -> Self {
        Self {
            os: "linux".to_string(),
            baseline,
            page_size: CAPSULE_PINNED_PAGE_SIZE,
            cache_line_bytes: CAPSULE_CACHE_LINE_BYTES,
            exposed_cpu_features: baseline
                .required_features()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            v8_flags: baseline.baseline_v8_flags(),
            criu_available,
        }
    }

    /// Probe real host OS, architecture, page size, and CPU extensions.
    pub fn probe_host(criu_available: bool) -> Self {
        let baseline = CpuBaseline::host_default();
        let env_flags = std::env::var("PARAWING_V8_BASELINE_FLAGS").ok();
        let v8_flags = match env_flags.as_deref() {
            Some(raw) if !raw.trim().is_empty() => parse_v8_flags_csv(raw),
            _ => baseline.baseline_v8_flags(),
        };
        Self {
            os: std::env::consts::OS.to_string(),
            baseline,
            page_size: probe_host_page_size(),
            cache_line_bytes: std::mem::align_of::<CacheAligned<u64>>(),
            exposed_cpu_features: probe_host_cpu_features(),
            v8_flags,
            criu_available,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleError {
    ArchBaselineMismatch {
        expected: CpuBaseline,
        actual: CpuBaseline,
    },
    PageSizeMismatch {
        expected: u32,
        actual: u32,
    },
    CacheLineMismatch {
        expected: usize,
        actual: usize,
    },
    MissingRequiredFeature(String),
    ForbiddenExtensionDetected(String),
    MissingRequiredV8Flag(String),
    ForbiddenV8Flag(String),
    CapsuleHashMismatch {
        expected_hex: String,
        actual_hex: String,
    },
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchBaselineMismatch { expected, actual } => {
                write!(
                    f,
                    "baseline mismatch: expected {}, got {}",
                    expected.as_str(),
                    actual.as_str()
                )
            }
            Self::PageSizeMismatch { expected, actual } => {
                write!(f, "page size mismatch: expected {expected}B, got {actual}B")
            }
            Self::CacheLineMismatch { expected, actual } => {
                write!(
                    f,
                    "cache-line mismatch: expected {expected}B, got {actual}B"
                )
            }
            Self::MissingRequiredFeature(feat) => {
                write!(f, "missing required baseline CPU feature: {feat}")
            }
            Self::ForbiddenExtensionDetected(feat) => {
                write!(f, "non-baseline CPU feature exposed in capsule: {feat}")
            }
            Self::MissingRequiredV8Flag(flag) => {
                write!(f, "missing required baseline V8 flag: {flag}")
            }
            Self::ForbiddenV8Flag(flag) => {
                write!(f, "forbidden or invalid baseline V8 flag: {flag}")
            }
            Self::CapsuleHashMismatch {
                expected_hex,
                actual_hex,
            } => {
                write!(
                    f,
                    "capsule_hash mismatch: expected {expected_hex}, got {actual_hex}"
                )
            }
        }
    }
}

impl std::error::Error for CapsuleError {}

pub fn enforce_baseline_compatibility(
    manifest: &CapsuleManifest,
    env: &RuntimeEnvironmentSpec,
) -> Result<(), CapsuleError> {
    if manifest.page_size != CAPSULE_PINNED_PAGE_SIZE || env.page_size != manifest.page_size {
        return Err(CapsuleError::PageSizeMismatch {
            expected: CAPSULE_PINNED_PAGE_SIZE,
            actual: env.page_size,
        });
    }
    if manifest.cache_line_bytes != CAPSULE_CACHE_LINE_BYTES
        || env.cache_line_bytes != manifest.cache_line_bytes
    {
        return Err(CapsuleError::CacheLineMismatch {
            expected: CAPSULE_CACHE_LINE_BYTES,
            actual: env.cache_line_bytes,
        });
    }
    if manifest.baseline != env.baseline {
        return Err(CapsuleError::ArchBaselineMismatch {
            expected: manifest.baseline,
            actual: env.baseline,
        });
    }
    check_cpu_features(manifest.baseline, &env.exposed_cpu_features)?;
    check_v8_flags(manifest.baseline, &manifest.v8_flags, &env.v8_flags)?;
    Ok(())
}

fn check_cpu_features(baseline: CpuBaseline, exposed: &[String]) -> Result<(), CapsuleError> {
    let feature_set: BTreeSet<&str> = exposed.iter().map(String::as_str).collect();
    for req in baseline.required_features() {
        if !feature_set.contains(req) {
            return Err(CapsuleError::MissingRequiredFeature((*req).to_string()));
        }
    }
    for forbidden in baseline.forbidden_features() {
        if feature_set.contains(forbidden) {
            return Err(CapsuleError::ForbiddenExtensionDetected(
                (*forbidden).to_string(),
            ));
        }
    }
    Ok(())
}

fn check_v8_flags(
    baseline: CpuBaseline,
    manifest_flags: &[String],
    env_flags: &[String],
) -> Result<(), CapsuleError> {
    for flag in manifest_flags.iter().chain(env_flags.iter()) {
        if is_forbidden_v8_flag(baseline, flag) {
            return Err(CapsuleError::ForbiddenV8Flag(flag.clone()));
        }
    }
    let manifest_set: BTreeSet<&str> = manifest_flags.iter().map(String::as_str).collect();
    let env_set: BTreeSet<&str> = env_flags.iter().map(String::as_str).collect();
    for flag in baseline.baseline_v8_flags() {
        if !manifest_set.contains(flag.as_str()) || !env_set.contains(flag.as_str()) {
            return Err(CapsuleError::MissingRequiredV8Flag(flag));
        }
    }
    Ok(())
}

pub fn verify_capsule_hash(
    expected: &[u8; 32],
    manifest: &CapsuleManifest,
) -> Result<(), CapsuleError> {
    let actual = manifest.compute_capsule_hash();
    if actual != *expected {
        return Err(CapsuleError::CapsuleHashMismatch {
            expected_hex: hex_encode(expected),
            actual_hex: hex_encode(&actual),
        });
    }
    Ok(())
}

pub fn probe_host_page_size() -> u32 {
    if let Ok(output) = std::process::Command::new("getconf")
        .arg("PAGESIZE")
        .output()
    {
        if output.status.success() {
            if let Ok(parsed) = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
            {
                return parsed;
            }
        }
    }
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        16384
    } else {
        CAPSULE_PINNED_PAGE_SIZE
    }
}

pub fn probe_host_cpu_features() -> Vec<String> {
    let mut features = Vec::new();
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            features.push("neon".to_string());
        }
        if std::arch::is_aarch64_feature_detected!("fp") {
            features.push("fp-armv8".to_string());
        }
        if std::arch::is_aarch64_feature_detected!("sve") {
            features.push("sve".to_string());
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            features.push("sse4.2".to_string());
        }
        if std::arch::is_x86_feature_detected!("popcnt") {
            features.push("popcnt".to_string());
        }
        if std::arch::is_x86_feature_detected!("cmpxchg16b") {
            features.push("cx16".to_string());
        }
        if std::arch::is_x86_feature_detected!("avx") {
            features.push("avx".to_string());
        }
        if std::arch::is_x86_feature_detected!("avx2") {
            features.push("avx2".to_string());
        }
        if std::arch::is_x86_feature_detected!("fma") {
            features.push("fma".to_string());
        }
    }
    features
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex_encode(&digest)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_aligned_enforces_64_byte_alignment() {
        assert_eq!(std::mem::align_of::<CacheAligned<u64>>(), 64);
        assert!(std::mem::size_of::<CacheAligned<u64>>() >= 64);
    }

    #[test]
    fn capsule_manifest_hash_is_reproducible_and_sensitive() {
        let m1 = CapsuleManifest::new(
            CpuBaseline::X8664V2Baseline,
            "sha256:bin-1",
            "sha256:v8-1",
            true,
        );
        let m2 = CapsuleManifest::new(
            CpuBaseline::X8664V2Baseline,
            "sha256:bin-1",
            "sha256:v8-1",
            true,
        );
        assert_eq!(m1.compute_capsule_hash(), m2.compute_capsule_hash());

        let m3 = CapsuleManifest::new(
            CpuBaseline::X8664V2Baseline,
            "sha256:bin-2",
            "sha256:v8-1",
            true,
        );
        assert_ne!(m1.compute_capsule_hash(), m3.compute_capsule_hash());
        let expected = m1.compute_capsule_hash();
        assert!(verify_capsule_hash(&expected, &m2).is_ok());
        assert!(matches!(
            verify_capsule_hash(&expected, &m3),
            Err(CapsuleError::CapsuleHashMismatch { .. })
        ));
    }

    #[test]
    fn baseline_enforcement_rejects_extra_cpu_extensions_and_page_size_drift() {
        let x86_manifest = CapsuleManifest::new(
            CpuBaseline::X8664V2Baseline,
            "sha256:bin",
            "sha256:snap",
            true,
        );
        let ok_env = RuntimeEnvironmentSpec::emulated_baseline(CpuBaseline::X8664V2Baseline, true);
        assert!(enforce_baseline_compatibility(&x86_manifest, &ok_env).is_ok());

        let mut leaky_env = ok_env.clone();
        leaky_env.exposed_cpu_features.push("avx2".to_string());
        assert_eq!(
            enforce_baseline_compatibility(&x86_manifest, &leaky_env),
            Err(CapsuleError::ForbiddenExtensionDetected("avx2".to_string()))
        );

        let mut wrong_v8 = ok_env.clone();
        wrong_v8.v8_flags.retain(|f| f != "--no-enable-fma3");
        assert_eq!(
            enforce_baseline_compatibility(&x86_manifest, &wrong_v8),
            Err(CapsuleError::MissingRequiredV8Flag(
                "--no-enable-fma3".to_string()
            ))
        );

        let mut wrong_page = ok_env;
        wrong_page.page_size = 16384;
        assert_eq!(
            enforce_baseline_compatibility(&x86_manifest, &wrong_page),
            Err(CapsuleError::PageSizeMismatch {
                expected: 4096,
                actual: 16384,
            })
        );
    }

    #[test]
    fn armv8_baseline_enforces_neon_and_forbids_sve() {
        let arm_manifest = CapsuleManifest::new(
            CpuBaseline::Aarch64Armv8Baseline,
            "sha256:arm-bin",
            "sha256:arm-snap",
            true,
        );
        let ok_env =
            RuntimeEnvironmentSpec::emulated_baseline(CpuBaseline::Aarch64Armv8Baseline, true);
        assert!(enforce_baseline_compatibility(&arm_manifest, &ok_env).is_ok());

        let mut sve_env = ok_env;
        sve_env.exposed_cpu_features.push("sve".to_string());
        assert_eq!(
            enforce_baseline_compatibility(&arm_manifest, &sve_env),
            Err(CapsuleError::ForbiddenExtensionDetected("sve".to_string()))
        );

        let host_probe = RuntimeEnvironmentSpec::probe_host(false);
        assert!(!host_probe.exposed_cpu_features.is_empty());
        assert_eq!(host_probe.cache_line_bytes, 64);
    }

    #[test]
    fn v8_baseline_override_rejects_relaxing_flags_and_matches_deno() {
        let valid_x86 = resolve_v8_flags_with_override(
            CpuBaseline::X8664V2Baseline,
            Some("--disallow-code-generation-from-strings,--no-enable-avx,--no-enable-avx2,--no-enable-fma3,--predictable"),
        )
        .expect("valid x86 baseline override");
        assert!(valid_x86.iter().any(|f| f == "--predictable"));

        let err_bad = resolve_v8_flags_with_override(
            CpuBaseline::X8664V2Baseline,
            Some("--disallow-code-generation-from-strings,--no-enable-avx,--no-enable-avx2,--no-enable-fma"),
        );
        assert_eq!(
            err_bad,
            Err(CapsuleError::ForbiddenV8Flag("--no-enable-fma".to_string()))
        );

        let err_sve = resolve_v8_flags_with_override(
            CpuBaseline::Aarch64Armv8Baseline,
            Some("--disallow-code-generation-from-strings,--no-enable-sve"),
        );
        assert_eq!(
            err_sve,
            Err(CapsuleError::ForbiddenV8Flag("--no-enable-sve".to_string()))
        );

        let err_missing = resolve_v8_flags_with_override(
            CpuBaseline::Aarch64Armv8Baseline,
            Some("--disallow-code-generation-from-strings"),
        );
        assert_eq!(
            err_missing,
            Err(CapsuleError::MissingRequiredV8Flag(
                "--arm-arch=armv8".to_string()
            ))
        );

        let deno_bin = crate::rpc_pipe::resolve_deno_binary(None);
        if std::path::Path::new(&deno_bin).exists() {
            for baseline in [
                CpuBaseline::Aarch64Armv8Baseline,
                CpuBaseline::X8664V2Baseline,
            ] {
                let flags = baseline.baseline_v8_flags().join(",");
                let out = std::process::Command::new(&deno_bin)
                    .args(["eval", &format!("--v8-flags={flags}"), "console.log(1)"])
                    .output()
                    .expect("run deno baseline flags");
                assert!(
                    out.status.success(),
                    "deno rejected flags {flags}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}
