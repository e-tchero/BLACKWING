use crate::cert;
use crate::ice_socket::IceUdpSocket;
use bw_ice::IceConnection;
use quinn::{ClientConfig, Connection, Endpoint, TransportConfig};
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
pub struct QuicClient {
    /// The underlying Quinn endpoint.
    pub endpoint: Endpoint,
}

impl QuicClient {
    /// Binds a production QUIC endpoint with certificate pinning.
    pub fn bind(
        relay: Option<(SocketAddr, [u8; 32])>,
        server_id: bw_crypto::DeviceId,
    ) -> Result<Self, QuicClientError> {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let tls_config = cert::generate_pinned_client_config(server_id);
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let transport_config = TransportConfig::default();
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = if let Some((relay_addr, token)) = relay {
            let mut relay_transport_config = TransportConfig::default();
            relay_transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
            client_config.transport_config(Arc::new(relay_transport_config));
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

    /// Development-only QUIC endpoint that skips certificate verification.
    pub fn bind_dev(relay: Option<(SocketAddr, [u8; 32])>) -> Result<Self, QuicClientError> {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let tls_config = cert::generate_dev_client_config();
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let transport_config = TransportConfig::default();
        let mut client_config = ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = if let Some((relay_addr, token)) = relay {
            let mut relay_transport_config = TransportConfig::default();
            relay_transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
            client_config.transport_config(Arc::new(relay_transport_config));
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

    /// Binds a QUIC endpoint over an ICE connection with certificate pinning.
    pub fn bind_with_ice(
        ice: IceConnection,
        server_id: bw_crypto::DeviceId,
    ) -> Result<Self, QuicClientError> {
        let tls_config = cert::generate_pinned_client_config(server_id);
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));
        let socket = IceUdpSocket::new(ice)?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// Development-only ICE endpoint.
    pub fn bind_with_ice_dev(ice: IceConnection) -> Result<Self, QuicClientError> {
        let tls_config = cert::generate_dev_client_config();
        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|_| quinn::ConnectError::EndpointStopping)?;
        let client_config = ClientConfig::new(Arc::new(quic_client_config));
        let socket = IceUdpSocket::new(ice)?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    /// Connects to a QUIC server at the given address.
    /// H6 fix: SNI derived from actual destination, not hardcoded "localhost".
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection, QuicClientError> {
        let sni = server_addr.ip().to_string();
        let conn = self.endpoint.connect(server_addr, &sni)?.await?;
        Ok(conn)
    }
}
