// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! W3C WebAuthn Level 3 section 5.11.1 Related Origin Requests (`/.well-known/webauthn`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use url::Url;

use crate::webauthn::types::WebAuthnError;

/// Maximum distinct registrable origin labels honoured per well-known document.
pub const MAX_RELATED_ORIGIN_LABELS: usize = 5;

const WELL_KNOWN_PATH: &str = "/.well-known/webauthn";
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

fn security_error(detail: String) -> WebAuthnError {
    WebAuthnError::Security(detail)
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(build_client)
}

fn build_client() -> reqwest::Client {
    ensure_crypto_provider();
    reqwest::Client::builder()
        .referer(false)
        .timeout(FETCH_TIMEOUT)
        .build()
        .expect("related-origins HTTPS client")
}

static CLIENT_OVERRIDE: OnceLock<Mutex<Option<Arc<reqwest::Client>>>> = OnceLock::new();

fn client_slot() -> &'static Mutex<Option<Arc<reqwest::Client>>> {
    CLIENT_OVERRIDE.get_or_init(|| Mutex::new(None))
}

fn http_client() -> reqwest::Client {
    if let Ok(guard) = client_slot().lock() {
        if let Some(override_client) = guard.as_ref() {
            return override_client.as_ref().clone();
        }
    }
    client().clone()
}

/// Overrides the HTTPS client for local `TestServer` verification tests.
#[cfg(test)]
pub fn set_client_for_test(client: reqwest::Client) {
    let mut guard = client_slot().lock().expect("client override lock");
    *guard = Some(Arc::new(client));
}

/// Restores the default production HTTPS client after a test completes.
#[cfg(test)]
pub fn reset_client_for_test() {
    let mut guard = client_slot().lock().expect("client override lock");
    *guard = None;
}

fn registrable_origin_label(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let label = labels[labels.len() - 2..].join(".");
    if label.is_empty() {
        None
    } else {
        Some(label)
    }
}

fn effective_domain(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    Some(host)
}

fn normalized_port(url: &Url) -> Option<u16> {
    if let Some(port) = url.port() {
        return Some(port);
    }
    match url.scheme().to_ascii_lowercase().as_str() {
        "https" | "wss" => Some(443),
        "http" | "ws" => Some(80),
        _ => None,
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    if !a.scheme().eq_ignore_ascii_case(b.scheme()) {
        return false;
    }
    let host_a = a.host_str().map(|h| h.to_ascii_lowercase());
    let host_b = b.host_str().map(|h| h.to_ascii_lowercase());
    host_a == host_b && normalized_port(a) == normalized_port(b)
}

fn well_known_url(rp_id: &str) -> Result<Url, WebAuthnError> {
    Url::parse(&format!("https://{rp_id}{WELL_KNOWN_PATH}")).map_err(|_| {
        security_error(format!(
            "The relying party identifier '{rp_id}' does not name a valid well-known URL"
        ))
    })
}

async fn fetch_origins(rp_id: &str) -> Result<Vec<String>, WebAuthnError> {
    let url = well_known_url(rp_id)?;
    let response = http_client()
        .get(url)
        .header(reqwest::header::AUTHORIZATION, "")
        .send()
        .await
        .map_err(|e| {
            security_error(format!(
                "The related origins document for '{rp_id}' could not be fetched: {e}"
            ))
        })?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        return Err(security_error(format!(
            "The related origins document for '{rp_id}' returned HTTP status {status}"
        )));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if media_type != "application/json" {
        return Err(security_error(format!(
            "The related origins document for '{rp_id}' is not application/json (got '{content_type}')"
        )));
    }

    let body = response.text().await.map_err(|e| {
        security_error(format!(
            "The related origins document for '{rp_id}' could not be read: {e}"
        ))
    })?;
    parse_origins_json(rp_id, &body)
}

fn parse_origins_json(rp_id: &str, body: &str) -> Result<Vec<String>, WebAuthnError> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|e| {
        security_error(format!(
            "The related origins document for '{rp_id}' is not valid JSON: {e}"
        ))
    })?;
    let object = value.as_object().ok_or_else(|| {
        security_error(format!(
            "The related origins document for '{rp_id}' is not a JSON object"
        ))
    })?;
    let origins = object.get("origins").ok_or_else(|| {
        security_error(format!(
            "The related origins document for '{rp_id}' has no 'origins' property"
        ))
    })?;
    let list = origins.as_array().ok_or_else(|| {
        security_error(format!(
            "The 'origins' property in the related origins document for '{rp_id}' is not an array"
        ))
    })?;

    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let text = item.as_str().ok_or_else(|| {
            security_error(format!(
                "The 'origins' property for '{rp_id}' is not an array of strings"
            ))
        })?;
        out.push(text.to_string());
    }
    Ok(out)
}

/// Validates whether `https://<rp_id_requested>/.well-known/webauthn` lists `caller_origin`.
pub async fn validate(caller_origin: &str, rp_id_requested: &str) -> Result<bool, WebAuthnError> {
    let origins = fetch_origins(rp_id_requested).await?;
    let caller = Url::parse(caller_origin)
        .map_err(|_| security_error(format!("Invalid origin URL: {caller_origin}")))?;

    let mut labels_seen: HashSet<String> = HashSet::new();
    for origin_item in origins {
        let Ok(url) = Url::parse(&origin_item) else {
            continue;
        };
        let Some(domain) = effective_domain(&url) else {
            continue;
        };
        let Some(label) = registrable_origin_label(&domain) else {
            continue;
        };
        if labels_seen.len() >= MAX_RELATED_ORIGIN_LABELS && !labels_seen.contains(&label) {
            continue;
        }
        if same_origin(&caller, &url) {
            return Ok(true);
        }
        if labels_seen.len() < MAX_RELATED_ORIGIN_LABELS {
            labels_seen.insert(label);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_origins_on_scheme_host_and_port() {
        let parse = |s: &str| Url::parse(s).unwrap();
        assert!(same_origin(
            &parse("https://example.com"),
            &parse("https://example.com")
        ));
        assert!(same_origin(
            &parse("https://example.com"),
            &parse("https://example.com:443")
        ));
        assert!(!same_origin(
            &parse("https://example.com"),
            &parse("https://example.com:8443")
        ));
        assert!(!same_origin(
            &parse("https://example.com"),
            &parse("http://example.com")
        ));
        assert!(!same_origin(
            &parse("https://example.com"),
            &parse("https://www.example.com")
        ));
        assert!(!same_origin(
            &parse("https://example.com"),
            &parse("https://other.com")
        ));
    }

    #[test]
    fn takes_the_last_two_labels_as_the_registrable_label() {
        assert_eq!(
            registrable_origin_label("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_origin_label("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_origin_label("www.example.co.jp").as_deref(),
            Some("co.jp")
        );
        assert_eq!(registrable_origin_label("localhost"), None);
    }
}
