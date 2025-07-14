mod conf;
mod log;

use std::{io, net::SocketAddr, sync::Arc};

use medea_turn::{NoneAuthHandler, Server, ServerConfig, transport::UdpSocket};
use tokio::signal;

use crate::conf::Conf;

#[tokio::main(flavor = "current_thread")] // single thread is enough
async fn main() -> anyhow::Result<()> {
    drop(dotenv::dotenv().ok());
    let conf = Conf::parse()?;

    log::init(conf.log.clone());

    tracing::info!("Config: {conf:?}");

    let bind_addr = SocketAddr::new(conf.stun.bind_ip, conf.stun.bind_port);

    let server_config: ServerConfig<NoneAuthHandler> = ServerConfig {
        connections: vec![Arc::new(UdpSocket::bind(bind_addr).await?)],
        turn: None,
    };

    let serv = Server::new(server_config);

    wait_for_shutdown().await?;

    drop(serv);

    Ok(())
}

#[cfg(unix)]
/// Waits for [SIGINT] or [SIGTERM].
///
/// [SIGINT]: https://en.wikipedia.org/wiki/Signal_(IPC)#SIGINT
/// [SIGTERM]: https://en.wikipedia.org/wiki/Signal_(IPC)#SIGTERM
async fn wait_for_shutdown() -> io::Result<()> {
    use tokio::signal::unix;

    let mut sigterm = unix::signal(unix::SignalKind::terminate())?;
    let sigint = signal::ctrl_c();

    tokio::select! {
        _ = sigint => {}
        _ = sigterm.recv() => {}
    }

    Ok(())
}

#[cfg(not(unix))]
/// Waits for a [`signal::ctrl_c`].
async fn wait_for_shutdown() -> io::Result<()> {
    signal::ctrl_c().await
}
