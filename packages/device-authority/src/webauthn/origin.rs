// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! WebAuthn Level 3 section 5.1 / section 13.4 origin and effective RP-ID validation.

use url::{Host, Url};

use crate::webauthn::types::WebAuthnError;

/// Normalized caller origin and effective relying party identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedOrigin {
    /// Lowercased effective relying party identifier.
    pub effective_rp_id: String,
    /// Normalized caller origin with default port elided.
    pub normalized_origin: String,
}

/// Outcome of the synchronous origin and RP-ID suffix check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginValidation {
    /// Caller host matches or is a subdomain of `effective_rp_id`; no fetch required.
    Suffix(ValidatedOrigin),
    /// Caller host is not under `rp_id`; `related_origins::validate` must decide.
    NeedsRelatedOrigins {
        /// Pre-normalized origin and requested RP ID.
        validated: ValidatedOrigin,
        /// Exact caller origin passed by the trusted host.
        caller_origin: String,
        /// Requested relying party identifier.
        rp_id: String,
    },
}

/// Validates secure-context origin rules and determines whether ROR is required.
pub fn validate_origin_and_effective_rp_id(
    origin: &str,
    requested_rp_id: Option<&str>,
    cross_origin: bool,
    is_create: bool,
) -> Result<OriginValidation, WebAuthnError> {
    let url = Url::parse(origin)
        .map_err(|_| WebAuthnError::Security(format!("Invalid origin URL: {origin}")))?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = extract_host(&url, origin)?;

    let is_localhost =
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host.ends_with(".localhost");
    if scheme != "https" && !(scheme == "http" && is_localhost) {
        return Err(WebAuthnError::Security(format!(
            "WebAuthn requires a secure context (HTTPS or localhost), got {origin}"
        )));
    }
    if cross_origin && is_create {
        return Err(WebAuthnError::NotAllowed(
            "PublicKeyCredential creation is not permitted in cross-origin iframes".to_string(),
        ));
    }

    let rp_id = match requested_rp_id {
        Some(requested) if !requested.is_empty() => requested.to_ascii_lowercase(),
        _ => host.clone(),
    };
    if rp_id.contains("://") || rp_id.contains('/') || rp_id.contains(':') {
        return Err(WebAuthnError::Security(format!(
            "Invalid RP ID format: {rp_id}"
        )));
    }

    let validated = ValidatedOrigin {
        effective_rp_id: rp_id.clone(),
        normalized_origin: normalize_origin(&scheme, &host, url.port()),
    };

    if !(rp_id.contains('.') || rp_id == "localhost") {
        return Err(WebAuthnError::Security(format!(
            "RP ID '{rp_id}' is not a valid registrable domain suffix for origin host '{host}'"
        )));
    }
    if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
        return Ok(OriginValidation::NeedsRelatedOrigins {
            validated,
            caller_origin: origin.to_string(),
            rp_id,
        });
    }
    Ok(OriginValidation::Suffix(validated))
}

fn extract_host(url: &Url, origin: &str) -> Result<String, WebAuthnError> {
    let host = match url.host() {
        Some(Host::Domain(domain)) => domain.to_ascii_lowercase(),
        Some(Host::Ipv4(addr)) => addr.to_string(),
        Some(Host::Ipv6(addr)) => addr.to_string(),
        None => {
            return Err(WebAuthnError::Security(format!(
                "Invalid origin URL: {origin}"
            )));
        }
    };
    if host.is_empty() {
        return Err(WebAuthnError::Security(format!(
            "Invalid origin URL: {origin}"
        )));
    }
    Ok(host)
}

fn normalize_origin(scheme: &str, host: &str, port: Option<u16>) -> String {
    let mut normalized = format!("{scheme}://{host}");
    if let Some(p) = port {
        let is_default = (scheme == "https" && p == 443) || (scheme == "http" && p == 80);
        if !is_default {
            normalized.push_str(&format!(":{p}"));
        }
    }
    normalized
}

/// Returns a conservative registrable domain suffix for human approval display scoping.
pub fn registrable_suffix(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::related_origins;
    use crate::webauthn::test_server::{TestResponse, TestServer};

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn suffix(
        origin: &str,
        requested_rp_id: Option<&str>,
        cross_origin: bool,
        is_create: bool,
    ) -> ValidatedOrigin {
        match validate_origin_and_effective_rp_id(origin, requested_rp_id, cross_origin, is_create)
            .unwrap()
        {
            OriginValidation::Suffix(validated) => validated,
            OriginValidation::NeedsRelatedOrigins { .. } => {
                panic!("{origin} should have been decided by the suffix rule")
            }
        }
    }

    fn block_on_ror(caller_origin: &str, rp_id: &str) -> Result<bool, WebAuthnError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio current_thread runtime");
        rt.block_on(related_origins::validate(caller_origin, rp_id))
    }

    fn related_origins_against(response: TestResponse) -> Result<bool, WebAuthnError> {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = TestServer::start(response);
        related_origins::set_client_for_test(server.client());
        let outcome = block_on_ror("https://caller.example", &server.rp_id());
        related_origins::reset_client_for_test();
        outcome
    }

    #[test]
    fn accepts_https_origins_and_defaults_the_rp_id_to_the_host() {
        let validated = suffix("https://example.com", None, false, false);
        assert_eq!(validated.effective_rp_id, "example.com");
        assert_eq!(validated.normalized_origin, "https://example.com");
    }

    #[test]
    fn accepts_a_subdomain_origin_with_an_explicit_rp_id() {
        let validated = suffix(
            "https://login.example.com",
            Some("example.com"),
            false,
            false,
        );
        assert_eq!(validated.effective_rp_id, "example.com");
        assert_eq!(validated.normalized_origin, "https://login.example.com");
    }

    #[test]
    fn a_non_suffix_rp_id_is_deferred_to_the_related_origins_procedure() {
        let outcome = validate_origin_and_effective_rp_id(
            "https://evil.com",
            Some("example.com"),
            false,
            false,
        )
        .unwrap();
        match outcome {
            OriginValidation::NeedsRelatedOrigins {
                validated,
                caller_origin,
                rp_id,
            } => {
                assert_eq!(validated.effective_rp_id, "example.com");
                assert_eq!(caller_origin, "https://evil.com");
                assert_eq!(rp_id, "example.com");
            }
            OriginValidation::Suffix(validated) => {
                panic!("expected deferred decision, got {validated:?}")
            }
        }
    }

    #[test]
    fn rejects_a_single_label_rp_id_for_a_public_host() {
        let err =
            validate_origin_and_effective_rp_id("https://example.com", Some("com"), false, false)
                .unwrap_err();
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn rejects_plain_http_except_for_localhost() {
        let err = validate_origin_and_effective_rp_id("http://example.com", None, false, false)
            .unwrap_err();
        assert!(err.detail().contains("secure context"));

        let ok = suffix("http://localhost:8080", None, false, false);
        assert_eq!(ok.effective_rp_id, "localhost");
        assert_eq!(ok.normalized_origin, "http://localhost:8080");
    }

    #[test]
    fn keeps_a_non_default_port_and_drops_a_default_port() {
        let kept = suffix("https://example.com:8443", None, false, false);
        assert_eq!(kept.normalized_origin, "https://example.com:8443");

        let dropped = suffix("https://example.com:443", None, false, false);
        assert_eq!(dropped.normalized_origin, "https://example.com");
    }

    #[test]
    fn rejects_an_rp_id_carrying_a_scheme_port_or_path() {
        for bad in ["https://example.com", "example.com:443", "example.com/path"] {
            let err =
                validate_origin_and_effective_rp_id("https://example.com", Some(bad), false, false)
                    .unwrap_err();
            assert_eq!(err.dom_exception_name(), "SecurityError", "accepted {bad}");
        }
    }

    #[test]
    fn rejects_cross_origin_creation() {
        let err = validate_origin_and_effective_rp_id("https://example.com", None, true, true)
            .unwrap_err();
        assert_eq!(err.dom_exception_name(), "NotAllowedError");
    }

    #[test]
    fn rejects_an_ipv6_host_as_a_relying_party_identifier() {
        let err = validate_origin_and_effective_rp_id("http://[::1]:9000", None, false, false)
            .unwrap_err();
        assert_eq!(err.dom_exception_name(), "SecurityError");
        assert!(err.detail().contains("Invalid RP ID format"));
    }

    #[test]
    fn defers_an_ipv6_host_with_an_explicit_domain_rp_id() {
        let outcome = validate_origin_and_effective_rp_id(
            "http://[::1]:9000",
            Some("example.com"),
            false,
            false,
        )
        .unwrap();
        match outcome {
            OriginValidation::NeedsRelatedOrigins { rp_id, .. } => {
                assert_eq!(rp_id, "example.com");
            }
            OriginValidation::Suffix(validated) => {
                panic!("suffix rule should not have decided this: {validated:?}")
            }
        }
    }

    #[test]
    fn localhost_and_loopback_are_decided_by_the_suffix_rule() {
        let ok = suffix("http://localhost:8080", Some("localhost"), false, false);
        assert_eq!(ok.effective_rp_id, "localhost");

        let loopback = suffix("http://127.0.0.1:8080", Some("127.0.0.1"), false, false);
        assert_eq!(loopback.effective_rp_id, "127.0.0.1");

        let sub = suffix("http://app.localhost:3000", Some("localhost"), false, false);
        assert_eq!(sub.effective_rp_id, "localhost");
    }

    #[test]
    fn a_suffix_rp_id_is_decided_without_any_fetch() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = TestServer::start(TestResponse::json("{\"origins\":[]}"));
        related_origins::set_client_for_test(server.client());
        let outcome = validate_origin_and_effective_rp_id(
            "https://login.example.com",
            Some("example.com"),
            false,
            false,
        )
        .unwrap();
        related_origins::reset_client_for_test();

        match outcome {
            OriginValidation::Suffix(validated) => {
                assert_eq!(validated.effective_rp_id, "example.com");
            }
            OriginValidation::NeedsRelatedOrigins { .. } => {
                panic!("suffix rule should have decided this")
            }
        }
        let requests = server.requests.lock().expect("request log");
        assert!(
            requests.is_empty(),
            "unexpected network fetch: {requests:?}"
        );
    }

    #[test]
    fn accepts_an_origin_the_relying_party_lists() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["https://caller.example"]}"#,
        ));
        assert!(outcome.expect("valid well-known document"));
    }

    #[test]
    fn refuses_an_origin_the_relying_party_does_not_list() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["https://someone-else.example"]}"#,
        ));
        assert!(!outcome.expect("valid well-known document"));
    }

    #[test]
    fn refuses_an_origin_when_the_document_has_no_origins_property() {
        let outcome = related_origins_against(TestResponse::json(r#"{"other": []}"#));
        let err = outcome.expect_err("missing origins property must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
        assert!(err.detail().contains("origins"), "{}", err.detail());
    }

    #[test]
    fn refuses_an_origin_when_the_document_is_not_valid_json() {
        let outcome = related_origins_against(TestResponse::json("this is not json"));
        let err = outcome.expect_err("invalid JSON must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn refuses_an_origin_when_the_document_is_not_an_object() {
        let outcome = related_origins_against(TestResponse::json(r#"["https://caller.example"]"#));
        let err = outcome.expect_err("non-object JSON must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn refuses_an_origin_when_the_origins_property_is_not_an_array() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": "https://caller.example"}"#,
        ));
        let err = outcome.expect_err("non-array origins must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn refuses_an_origin_when_the_origins_array_holds_a_non_string() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["https://caller.example", 7]}"#,
        ));
        let err = outcome.expect_err("non-string array item must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn refuses_an_origin_when_the_document_is_not_json_media() {
        let outcome = related_origins_against(TestResponse::with(
            200,
            "text/html",
            r#"{"origins": ["https://caller.example"]}"#,
        ));
        let err = outcome.expect_err("non-JSON media type must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
        assert!(err.detail().contains("application/json"));
    }

    #[test]
    fn refuses_an_origin_when_the_status_is_not_200() {
        let outcome = related_origins_against(TestResponse::with(
            404,
            "application/json",
            r#"{"origins": ["https://caller.example"]}"#,
        ));
        let err = outcome.expect_err("HTTP 404 must fail");
        assert_eq!(err.dom_exception_name(), "SecurityError");
    }

    #[test]
    fn follows_a_redirect_and_reads_the_status_after_it() {
        let outcome = related_origins_against(
            TestResponse::json(r#"{"origins": ["https://caller.example"]}"#).redirecting(),
        );
        assert!(outcome.expect("redirected well-known document"));
    }

    #[test]
    fn honours_the_max_labels_cap() {
        let mut origins: Vec<String> = Vec::new();
        for i in 0..related_origins::MAX_RELATED_ORIGIN_LABELS {
            origins.push(format!("https://other-{i}.example"));
        }
        origins.push("https://caller.example".to_string());
        let body = serde_json::json!({ "origins": origins }).to_string();

        let outcome = related_origins_against(TestResponse::json(body));
        assert!(!outcome.expect("valid well-known document"));
    }

    #[test]
    fn accepts_an_origin_listed_within_the_max_labels_cap() {
        let mut origins: Vec<String> = Vec::new();
        for i in 0..(related_origins::MAX_RELATED_ORIGIN_LABELS - 1) {
            origins.push(format!("https://other-{i}.example"));
        }
        origins.push("https://caller.example".to_string());
        let body = serde_json::json!({ "origins": origins }).to_string();

        let outcome = related_origins_against(TestResponse::json(body));
        assert!(outcome.expect("valid well-known document"));
    }

    #[test]
    fn skips_unparsable_origins_and_keeps_looking() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["not a url", "https://caller.example"]}"#,
        ));
        assert!(outcome.expect("valid well-known document"));
    }

    #[test]
    fn compares_origins_on_scheme_host_and_port() {
        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["https://caller.example:8443"]}"#,
        ));
        assert!(!outcome.expect("port mismatch must return false"));

        let outcome = related_origins_against(TestResponse::json(
            r#"{"origins": ["http://caller.example"]}"#,
        ));
        assert!(!outcome.expect("scheme mismatch must return false"));
    }

    #[test]
    fn the_whole_chain_lets_a_related_origin_through() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let origin = "https://caller.example";
        let rp_id = "rp.example";

        let server = TestServer::start_for_host(
            rp_id,
            TestResponse::json(r#"{"origins": ["https://caller.example"]}"#),
        );
        related_origins::set_client_for_test(server.client());

        let outcome = validate_origin_and_effective_rp_id(origin, Some(rp_id), false, false)
            .expect("valid caller origin");
        assert!(matches!(
            outcome,
            OriginValidation::NeedsRelatedOrigins { .. }
        ));

        let related = block_on_ror(origin, rp_id);
        assert!(related.expect("related origin listed"));
        related_origins::reset_client_for_test();

        use crate::credentials::{LocalPasskeyBroker, PasskeyBroker, RegistrationRequest};
        use crate::webauthn::authenticator::MemoryPasskeyStore;
        use crate::webauthn::types::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};

        let mut broker = LocalPasskeyBroker::with_store(Box::new(MemoryPasskeyStore::new()));
        let request = RegistrationRequest {
            task_id: "related-origins-test".to_string(),
            origin: origin.to_string(),
            rp: PublicKeyCredentialRpEntity {
                id: rp_id.to_string(),
                name: Some(rp_id.to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"user".to_vec(),
                name: "user@example.com".to_string(),
                display_name: "user@example.com".to_string(),
            },
            challenge: b"challenge".to_vec(),
            pub_key_cred_params: Vec::new(),
            exclude_credentials: Vec::new(),
            authenticator_selection: None,
            attestation: None,
            extensions: None,
            cross_origin: false,
            related_origin_validated: true,
        };
        assert!(broker.begin_registration(request).is_ok());
    }

    #[test]
    fn the_broker_refuses_an_origin_without_the_related_origins_check() {
        use crate::credentials::{LocalPasskeyBroker, PasskeyBroker, RegistrationRequest};
        use crate::webauthn::authenticator::MemoryPasskeyStore;
        use crate::webauthn::types::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};

        let mut broker = LocalPasskeyBroker::with_store(Box::new(MemoryPasskeyStore::new()));
        let request = RegistrationRequest {
            task_id: "related-origins-test".to_string(),
            origin: "https://caller.example".to_string(),
            rp: PublicKeyCredentialRpEntity {
                id: "rp.example".to_string(),
                name: Some("rp.example".to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: b"user".to_vec(),
                name: "user@example.com".to_string(),
                display_name: "user@example.com".to_string(),
            },
            challenge: b"challenge".to_vec(),
            pub_key_cred_params: Vec::new(),
            exclude_credentials: Vec::new(),
            authenticator_selection: None,
            attestation: None,
            extensions: None,
            cross_origin: false,
            related_origin_validated: false,
        };
        let error = broker
            .begin_registration(request)
            .expect_err("broker must refuse unchecked non-suffix origin");
        assert!(
            error.to_string().contains("not related"),
            "unexpected error: {error}"
        );
    }
}
