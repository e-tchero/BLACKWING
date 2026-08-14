use crate::cert;
use quinn::{Connection, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuicServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS certificate error: {0}")]
    Cert(#[from] cert::CertError),
    #[error("QUIC endpoint error")]
    EndpointError,
}

pub struct QuicServer {
    pub endpoint: Endpoint,
}

impl QuicServer {
    /// Binds a QUIC endpoint to the given address, generating a self-signed certificate.
    /// Optionally wraps the socket with a `RelayUdpSocket` if relay parameters are provided.
    pub fn bind(
        addr: SocketAddr,
        relay: Option<(SocketAddr, [u8; 32])>,
    ) -> Result<Self, QuicServerError> {
        let subject_alt_names = vec!["localhost".into(), "127.0.0.1".into()];
        let tls_config = cert::generate_server_config(subject_alt_names)?;
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|_| QuicServerError::EndpointError)?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = if let Some((relay_addr, token)) = relay {
            let std_socket = std::net::UdpSocket::bind(addr)?;
            std_socket.set_nonblocking(true)?;
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

            let relay_socket =
                crate::relay_socket::RelayUdpSocket::new(Arc::new(tokio_socket), relay_addr, token);

            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                relay_socket,
                Arc::new(quinn::TokioRuntime),
            )?
        } else {
            Endpoint::server(server_config, addr)?
        };

        Ok(Self { endpoint })
    }

    /// Accepts an incoming connection.
    pub async fn accept(&self) -> Option<Connection> {
        if let Some(incoming) = self.endpoint.accept().await {
            match incoming.await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    eprintln!("Incoming connection failed: {}", e);
                    None
                }
            }
        } else {
            None
        }
    }
}
