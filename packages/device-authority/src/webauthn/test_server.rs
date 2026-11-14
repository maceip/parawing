// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Real local TLS HTTPS server for `/.well-known/webauthn` Related Origins tests.

#![cfg(test)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Default relying party host served by `TestServer::start`.
pub const TEST_HOST: &str = "localhost";

/// HTTP response served by the local TLS test server.
#[derive(Clone, Debug)]
pub struct TestResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Content-Type` header value.
    pub content_type: String,
    /// Response body payload.
    pub body: String,
    /// When true, emits an initial `302 Found` redirect before returning `status`.
    pub redirect_first: bool,
}

impl TestResponse {
    /// Builds a `200 OK` `application/json` response.
    pub fn json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            content_type: "application/json".to_string(),
            body: body.into(),
            redirect_first: false,
        }
    }

    /// Builds a response with explicit status code and `Content-Type`.
    pub fn with(status: u16, content_type: &str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.into(),
            redirect_first: false,
        }
    }

    /// Configures a single `302 Found` redirect hop prior to the final response.
    pub fn redirecting(mut self) -> Self {
        self.redirect_first = true;
        self
    }
}

/// Ephemeral local HTTPS server speaking real TLS 1.3 / 1.2 via `rustls`.
pub struct TestServer {
    /// Ephemeral local socket address bound on `127.0.0.1:0`.
    pub addr: SocketAddr,
    /// DNS name encoded in the server certificate's Subject Alternative Name.
    pub host: String,
    /// DER-encoded root CA certificate signing the server leaf certificate.
    pub ca_cert_der: Vec<u8>,
    /// Recorded HTTP request paths in arrival order.
    pub requests: Arc<Mutex<Vec<String>>>,
    /// Shutdown signal flag for the listener loop.
    pub stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    /// Starts a local TLS server on `localhost` returning `response` for every request.
    pub fn start(response: TestResponse) -> Self {
        Self::start_with(move |_path| response.clone())
    }

    /// Starts a local TLS server with SAN `host` returning `response`.
    pub fn start_for_host(host: &str, response: TestResponse) -> Self {
        Self::start_with_host(host, move |_path| response.clone())
    }

    /// Starts a local TLS server on `localhost` using `responder`.
    pub fn start_with<F>(responder: F) -> Self
    where
        F: Fn(&str) -> TestResponse + Send + Sync + 'static,
    {
        Self::start_with_host(TEST_HOST, responder)
    }

    /// Starts a local TLS server with SAN `host` and dynamic `responder`.
    pub fn start_with_host<F>(host: &str, responder: F) -> Self
    where
        F: Fn(&str) -> TestResponse + Send + Sync + 'static,
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let host = host.to_string();
        let (ca_cert_der, leaf_cert_der, leaf_key_der) = generate_ca_and_leaf(&host);

        let cert_chain = vec![CertificateDer::from(leaf_cert_der)];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));
        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)
                .expect("TLS test server config"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local test address");
        listener
            .set_nonblocking(true)
            .expect("non-blocking test listener");

        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_accept_loop(
            listener,
            server_config,
            Arc::new(responder),
            requests.clone(),
            stop.clone(),
        );

        Self {
            addr,
            host,
            ca_cert_der,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    /// Returns the RP ID corresponding to this server's certificate DNS name.
    pub fn rp_id(&self) -> String {
        self.host.clone()
    }

    /// Builds a `reqwest::Client` trusting this server's CA and resolving `host` to `addr`.
    pub fn client(&self) -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca_cert = reqwest::Certificate::from_der(&self.ca_cert_der).expect("parse CA DER cert");
        reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .resolve(&self.host, self.addr)
            .referer(false)
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build test HTTPS client")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_accept_loop<F>(
    listener: TcpListener,
    server_config: Arc<ServerConfig>,
    responder: Arc<F>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()>
where
    F: Fn(&str) -> TestResponse + Send + Sync + 'static,
{
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let cfg = server_config.clone();
                    let reqs = requests.clone();
                    let resp = responder.clone();
                    std::thread::spawn(move || {
                        let _ = serve_one(stream, cfg, resp, reqs);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    })
}

fn serve_one<F>(
    stream: TcpStream,
    server_config: Arc<ServerConfig>,
    responder: Arc<F>,
    requests: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()>
where
    F: Fn(&str) -> TestResponse,
{
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let conn = ServerConnection::new(server_config).map_err(std::io::Error::other)?;
    let tls = StreamOwned::new(conn, stream);
    let mut reader = BufReader::new(tls);

    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    if let Ok(mut guard) = requests.lock() {
        guard.push(path.clone());
    }

    drain_headers(&mut reader)?;
    write_http_response(reader.get_mut(), &path, &responder(&path))
}

fn drain_headers<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    let mut header = String::new();
    loop {
        header.clear();
        let read = reader.read_line(&mut header)?;
        if read == 0 || header.trim().is_empty() {
            return Ok(());
        }
    }
}

fn write_http_response<W: Write>(
    writer: &mut W,
    path: &str,
    response: &TestResponse,
) -> std::io::Result<()> {
    if response.redirect_first && !path.contains("redirected=1") {
        let body = "redirecting";
        let header = format!(
            "HTTP/1.1 302 Found\r\nLocation: /.well-known/webauthn?redirected=1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        writer.write_all(header.as_bytes())?;
        writer.write_all(body.as_bytes())?;
        return writer.flush();
    }

    let body = &response.body;
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        body.len()
    );
    writer.write_all(header.as_bytes())?;
    writer.write_all(body.as_bytes())?;
    writer.flush()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn generate_ca_and_leaf(host: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate().expect("CA keypair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA cert");

    let mut leaf_params =
        rcgen::CertificateParams::new(vec![host.to_string()]).expect("leaf params");
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = rcgen::KeyPair::generate().expect("leaf keypair");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("signed leaf cert");

    (
        ca_cert.der().to_vec(),
        leaf_cert.der().to_vec(),
        leaf_key.serialize_der(),
    )
}
