// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Command-line entry point that connects to the engine and starts playback.

mod access;
mod cli;
mod oauth;
mod tls;

use parawing_playback::{play, FontSource, PlaybackOptions};
use std::{error::Error, io};
use tokio_tungstenite::tungstenite;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn user_error(error: &(dyn Error + 'static)) -> String {
    let mut cause = Some(error);
    while let Some(err) = cause {
        if let Some(ws) = err.downcast_ref::<tungstenite::Error>() {
            return match ws {
                tungstenite::Error::Protocol(
                    tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
                )
                | tungstenite::Error::ConnectionClosed => {
                    "Connection to the Parawing server was lost. Check that it is still running, then try again.".into()
                }
                tungstenite::Error::Io(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
                    ) =>
                {
                    "Could not reach the Parawing server. Check that it is running, then try again."
                        .into()
                }
                tungstenite::Error::Io(_) => {
                    "Connection to the Parawing server was lost. Check that it is still running, then try again.".into()
                }
                tungstenite::Error::Http(response) if response.status().as_u16() == 401 => {
                    "CDP authentication failed (HTTP 401). Run 'parawing login' again or check your API token.".into()
                }
                tungstenite::Error::Http(response) if response.status().as_u16() == 403 => {
                    "CDP access denied (HTTP 403). Check the selected account and Browser Rendering - Edit permission.".into()
                }
                tungstenite::Error::Http(response) if response.status().as_u16() == 429 => {
                    "Browser session limit or rate limit reached (HTTP 429). Try again later.".into()
                }
                tungstenite::Error::Http(response) => format!(
                    "Parawing server rejected the connection (HTTP {}).",
                    response.status()
                ),
                _ => format!("Could not connect to the Parawing server: {ws}"),
            };
        }
        if let Some(request) = err.downcast_ref::<reqwest::Error>() {
            if request.is_connect() || request.is_timeout() {
                let mut detail: &(dyn Error + 'static) = request;
                while let Some(source) = detail.source() {
                    detail = source;
                }
                return format!("Could not connect to the Parawing server: {detail}");
            }
            if let Some(status) = request.status() {
                return format!("Parawing server returned HTTP {status}.");
            }
        }
        cause = err.source();
    }
    error.to_string()
}

const RELEASE_VERSION: &str = include_str!("../../../VERSION").trim_ascii();

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("parawing: {}", user_error(error.as_ref()));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--version") {
        println!("parawing {RELEASE_VERSION}");
        return Ok(());
    }
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{}", cli::HELP);
        return Ok(());
    }
    if let Some(command @ ("login" | "logout")) = args.first().map(String::as_str) {
        if args.len() != 1 {
            return Err(format!("Usage: parawing {command}").into());
        }
        return if command == "login" {
            oauth::login().await
        } else {
            oauth::logout().await
        };
    }
    let server_env = std::env::var("PARAWING_SERVER").ok();
    let options = match cli::parse(args, server_env.as_deref()) {
        Ok(Some(options)) => options,
        Ok(None) => {
            print!("{}", cli::HELP);
            return Ok(());
        }
        Err(message) => {
            eprintln!("{message}\nTry 'parawing --help' for more information.");
            std::process::exit(2);
        }
    };
    run_playback(options).await
}

async fn run_playback(options: cli::Options) -> Result<()> {
    let cli::Options {
        url,
        backend,
        seconds,
        display,
        debug,
        mode,
        fps,
        compositor_v2,
    } = options;
    let mut connection = access::Connection::resolve(backend).await?;
    if connection.has_unencrypted_access_token() {
        eprintln!("warning: CF_ACCESS_TOKEN will be sent over an unencrypted HTTP/WS connection");
    }
    if debug {
        eprintln!(
            "parawing: debug: connecting CDP WebSocket to {}",
            connection.websocket
        );
    }
    let ws = connection.connect().await?;
    // After connect: a rejected saved login is replaced, and fonts use the replacement's origin.
    let font_source = FontSource::new(connection.font_server.clone(), connection.font_client()?)?;
    let mut options = PlaybackOptions::new(url, mode, seconds, display, debug, fps)?;
    if compositor_v2 {
        options = options.with_v2_endpoint(connection.v2_endpoint()?);
    }
    play(ws, options, font_source).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_websocket_has_a_readable_error() {
        let reset = tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        );
        let message = user_error(&reset);
        assert!(message.contains("Connection to the Parawing server was lost"));
        assert!(!message.contains("Protocol"));

        let refused =
            tungstenite::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert!(user_error(&refused).contains("Could not reach the Parawing server"));
    }

    #[test]
    fn release_version_is_valid_semver() {
        let parts: Vec<&str> = RELEASE_VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "unexpected RELEASE_VERSION: {RELEASE_VERSION}"
        );
        assert!(parts.iter().all(|part| part.parse::<u64>().is_ok()));
    }
}
