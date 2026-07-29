use crate::cert;
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuicClientError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("Connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

pub struct QuicClient {
    pub endpoint: Endpoint,
}

impl QuicClient {
    /// Binds a QUIC endpoint to an ephemeral local port.
    pub fn bind() -> Result<Self, QuicClientError> {
        let mut endpoint =
            Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;

        let tls_config = cert::generate_client_config();
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connects to a QUIC server at the given address.
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection, QuicClientError> {
        let conn = self.endpoint.connect(server_addr, "localhost")?.await?;
        Ok(conn)
    }
}
