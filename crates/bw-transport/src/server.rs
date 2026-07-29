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
    pub fn bind(addr: SocketAddr) -> Result<Self, QuicServerError> {
        let subject_alt_names = vec!["localhost".into(), "127.0.0.1".into()];
        let tls_config = cert::generate_server_config(subject_alt_names)?;
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|_| QuicServerError::EndpointError)?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = Endpoint::server(server_config, addr)?;

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
