use bw_protocol::codec::{decode_frame, encode_frame};
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::PacketHeader;
use quinn::{RecvStream, SendStream};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("Failed to write to stream: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("Failed to read from stream: {0}")]
    Read(#[from] quinn::ReadError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] bw_protocol::error::ProtocolError),
    #[error("Connection closed unexpectedly")]
    Closed,
}

pub struct QuicProtocolAdapter {
    send: SendStream,
    recv: RecvStream,
}

impl QuicProtocolAdapter {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }

    /// Serializes and sends a ProtocolFrame over the QUIC stream.
    pub async fn send_frame(&mut self, frame: &ProtocolFrame<'_>) -> Result<(), AdapterError> {
        let buffer = encode_frame(frame);
        self.send.write_all(&buffer).await?;
        Ok(())
    }

    /// Reads bytes from the QUIC stream and deserializes them into a ProtocolFrame.
    pub async fn recv_frame<'a>(
        &mut self,
        buffer: &'a mut Vec<u8>,
    ) -> Result<ProtocolFrame<'a>, AdapterError> {
        let header_size = std::mem::size_of::<PacketHeader>();

        // Read header first
        let mut header_buf = vec![0u8; header_size];
        self.recv
            .read_exact(&mut header_buf)
            .await
            .map_err(|e| match e {
                quinn::ReadExactError::FinishedEarly(_) => AdapterError::Closed,
                quinn::ReadExactError::ReadError(err) => AdapterError::Read(err),
            })?;

        // Deserialize header to find out payload length
        let header = PacketHeader::try_from_bytes(&header_buf)?;

        // Prepare buffer for header + payload
        let total_size = header_size + header.payload_length as usize;
        buffer.resize(total_size, 0);
        buffer[..header_size].copy_from_slice(&header_buf);

        // Read payload
        if header.payload_length > 0 {
            self.recv
                .read_exact(&mut buffer[header_size..total_size])
                .await
                .map_err(|e| match e {
                    quinn::ReadExactError::FinishedEarly(_) => AdapterError::Closed,
                    quinn::ReadExactError::ReadError(err) => AdapterError::Read(err),
                })?;
        }

        // Decode the entire frame
        let frame = decode_frame(buffer)?;
        Ok(frame)
    }

    pub async fn close(&mut self) {
        let _ = self.send.finish();
    }
}
