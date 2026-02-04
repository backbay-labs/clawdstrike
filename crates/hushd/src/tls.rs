//! TLS listener for hushd (rustls + tokio-rustls).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::serve::Listener;
use axum::{extract::connect_info::Connected, serve};
use rustls::ServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::config::TlsConfig;

pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

#[derive(Clone, Debug)]
pub struct TlsConnectInfo(pub std::net::SocketAddr);

impl<'a> Connected<serve::IncomingStream<'a, TlsListener>> for TlsConnectInfo {
    fn connect_info(stream: serve::IncomingStream<'a, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl TlsListener {
    pub fn new(listener: TcpListener, tls: &TlsConfig) -> anyhow::Result<Self> {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&tls.cert_path)?
            .collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            anyhow::bail!(
                "TLS cert file contained no certificates: {}",
                tls.cert_path.display()
            );
        }

        let key = PrivateKeyDer::from_pem_file(&tls.key_path)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}

impl Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (tcp, addr) = match self.listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    handle_accept_error(e).await;
                    continue;
                }
            };

            match self.acceptor.accept(tcp).await {
                Ok(tls) => return (tls, addr),
                Err(err) => {
                    tracing::warn!(remote_addr = %addr, error = %err, "TLS handshake failed");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

async fn handle_accept_error(e: io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }

    tracing::error!(error = %e, "accept error");
    tokio::time::sleep(Duration::from_secs(1)).await;
}
