use crate::cert;
use quinn::{ClientConfig, Connection, Endpoint};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use thiserror::Error;

/// Errors produced by the QUIC client endpoint.
#[derive(Debug, Error)]
pub enum QuicClientError {
    /// Binding or I/O failure.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// The connection attempt failed.
    #[error("Connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// The established connection failed.
    #[error("Connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

/// A QUIC client endpoint.
///
/// Binds an ephemeral local UDP port, optionally wrapping the socket with a
/// `RelayUdpSocket` so all traffic is routed through a relay.
pub struct QuicClient {
    /// The underlying Quinn endpoint.
    pub endpoint: Endpoint,
}

impl QuicClient {
    /// Binds a QUIC endpoint to an ephemeral local port.
    /// Optionally wraps the socket with a `RelayUdpSocket` if relay parameters are provided.
    pub fn bind(relay: Option<(SocketAddr, [u8; 32])>) -> Result<Self, QuicClientError> {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

        let tls_config = cert::generate_client_config();
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));

        let endpoint = if let Some((relay_addr, token)) = relay {
            let std_socket = std::net::UdpSocket::bind(addr)?;
            std_socket.set_nonblocking(true)?;
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)?;

            let relay_socket =
                crate::relay_socket::RelayUdpSocket::new(Arc::new(tokio_socket), relay_addr, token);

            let mut endpoint = Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                relay_socket,
                Arc::new(quinn::TokioRuntime),
            )?;
            endpoint.set_default_client_config(client_config);
            endpoint
        } else {
            let mut endpoint = Endpoint::client(addr)?;
            endpoint.set_default_client_config(client_config);
            endpoint
        };

        Ok(Self { endpoint })
    }

    /// Connects to a QUIC server at the given address.
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection, QuicClientError> {
        let conn = self.endpoint.connect(server_addr, "localhost")?.await?;
        Ok(conn)
    }
}
