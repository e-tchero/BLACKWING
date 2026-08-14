use bw_protocol::codec::{decode_frame, encode_frame};
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::PacketHeader;
use quinn::{RecvStream, SendStream};
use thiserror::Error;

/// Errors produced by the QUIC protocol adapter.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Failed to write the frame to the QUIC stream.
    #[error("Failed to write to stream: {0}")]
    Write(#[from] quinn::WriteError),
    /// Failed to read a frame from the QUIC stream.
    #[error("Failed to read from stream: {0}")]
    Read(#[from] quinn::ReadError),
    /// The frame failed protocol-level decoding.
    #[error("Protocol error: {0}")]
    Protocol(#[from] bw_protocol::error::ProtocolError),
    /// The peer closed the stream unexpectedly.
    #[error("Connection closed unexpectedly")]
    Closed,
}

/// Adapts Quinn QUIC streams to the `bw-protocol` frame codec.
///
/// Serializes `ProtocolFrame`s onto the send stream and decodes frames from
/// the receive stream.
pub struct QuicProtocolAdapter {
    send: SendStream,
    recv: RecvStream,
}

impl QuicProtocolAdapter {
    /// Creates an adapter wrapping the given QUIC send/receive streams.
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

    /// Gracefully finishes the underlying send stream.
    pub async fn close(&mut self) {
        let _ = self.send.finish();
    }
}
