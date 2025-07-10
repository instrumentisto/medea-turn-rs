use std::{io, net::SocketAddr, sync::Arc};

use clap::Parser;
use medea_turn::{NoneAuthHandler, Server, ServerConfig, transport::UdpSocket};
use serde::Deserialize;
use tokio::signal;
use tracing as log;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

#[derive(Debug, Deserialize, Default, Parser)]
#[command(author, version, about)]
struct Config {
    /// Maximum allowed level of application log entries.
    ///
    /// Defaults to `INFO`.
    #[arg(long)]
    log_level: Option<String>,

    /// IP that STUN UDP socket will bind to.
    ///
    /// Defaults to `0.0.0.0`.
    #[arg(long)]
    bind_ip: Option<String>,

    /// Port that STUN UDP will use.
    ///
    /// Defaults to `3478`.
    #[arg(long)]
    bind_port: Option<u16>,
}

#[tokio::main(flavor = "current_thread")] // single thread is enough
async fn main() -> io::Result<()> {
    let from_cli = Config::parse();
    let from_file: Config = match std::fs::read_to_string("config.toml") {
        Ok(file) => toml::from_str(&file).expect("Failed to parse TOML config"),
        Err(_) => Config::default(),
    };

    let config = Config {
        log_level: from_cli.log_level.or(from_file.log_level),
        bind_ip: from_cli
            .bind_ip
            .or(from_file.bind_ip)
            .or(Some("0.0.0.0".to_owned())),
        bind_port: from_cli.bind_port.or(from_file.bind_port).or(Some(3478)),
    };

    // CLI > file > RUST_LOG > default
    let log_level_filter = match &config.log_level {
        Some(lvl) => EnvFilter::new(lvl),
        None => EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info")),
    };
    tracing_subscriber::fmt()
        .with_env_filter(log_level_filter)
        .json()
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    log::warn!("Config: {config:?}");

    let bind_addr = SocketAddr::new(
        config.bind_ip.unwrap().parse().unwrap(),
        config.bind_port.unwrap(),
    );

    let turn_server_config: ServerConfig<NoneAuthHandler> = ServerConfig {
        connections: vec![Arc::new(UdpSocket::bind(bind_addr).await?)],
        turn: None,
    };

    let serv = Server::new(turn_server_config);

    wait_for_shutdown().await?;

    drop(serv);

    Ok(())
}

/// Waits for SIGINT or SIGTERM on unix and for Ctrl-C on non-unix platforms.
async fn wait_for_shutdown() -> io::Result<()> {
    if cfg!(unix) {
        let mut sigterm =
            signal::unix::signal(signal::unix::SignalKind::terminate())?;
        let sigint = signal::ctrl_c();

        tokio::select! {
            _ = sigint => {}
            _ = sigterm.recv() => {}
        }

        Ok(())
    } else {
        signal::ctrl_c().await
    }
}
