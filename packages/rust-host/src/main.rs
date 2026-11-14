// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Binary entrypoint for the native Rust Parawing browser host.

use parawing_rust_host::capsule::{CapsuleManifest, CpuBaseline};
use parawing_rust_host::engine_host::{start_engine_host, EngineHostConfig};

fn parse_cli_args() -> (String, u16, String) {
    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 8788;
    let mut capsule_id = "parawing-rust-host:0.1.0".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => {
                if let Some(v) = args.next() {
                    host = v;
                }
            }
            "--port" => {
                if let Some(v) = args.next().and_then(|s| s.parse::<u16>().ok()) {
                    port = v;
                }
            }
            "--capsule-id" => {
                if let Some(v) = args.next() {
                    capsule_id = v;
                }
            }
            _ => {}
        }
    }
    (host, port, capsule_id)
}

#[tokio::main]
async fn main() {
    let (host, port, capsule_id) = parse_cli_args();
    let manifest = CapsuleManifest::from_env(
        CpuBaseline::host_default(),
        capsule_id,
        "deno-v8:1",
        cfg!(target_os = "linux"),
    )
    .expect("valid PARAWING_V8_BASELINE_FLAGS");
    let capsule_hash = manifest.capsule_hash_hex();
    let handle = start_engine_host(EngineHostConfig {
        bind_addr: format!("{host}:{port}"),
        capsule_manifest: manifest,
        ..EngineHostConfig::default()
    })
    .await
    .expect("start parawing-rust-host");
    println!(
        "parawing-rust-host listening on {} (capsule_hash={capsule_hash})",
        handle.origin_http()
    );
    let _ = tokio::signal::ctrl_c().await;
    handle.shutdown().await;
}
