#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(missing_docs)]
#![allow(clippy::field_reassign_with_default)]
use bw_protocol::frame::ProtocolFrame;
use bw_protocol::header::{PacketHeader, PROTOCOL_MAGIC};
use bw_protocol::version::CURRENT_VERSION;
use bw_transport::{QuicClient, QuicProtocolAdapter, QuicServer};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[tokio::test]
async fn test_wp6_1_protocol_adapter_exchange() {
    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let server = QuicServer::bind_dev(server_addr, None).expect("Server should bind");

    // Get actual bound port
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind_dev(None).expect("Client should bind");

    // Spawn server accept task
    let server_task = tokio::spawn(async move {
        // 2. Server accepts.
        let conn = server
            .accept()
            .await
            .expect("Server should accept connection");
        let (send_stream, recv_stream) = conn.accept_bi().await.expect("Should accept bi stream");

        let mut adapter = QuicProtocolAdapter::new(send_stream, recv_stream);
        let mut buffer = Vec::new();

        // 4. Server deserializes it.
        let frame = adapter
            .recv_frame(&mut buffer)
            .await
            .expect("Server should receive frame");
        assert_eq!(frame.header.packet_type, 1);
        assert_eq!(frame.payload, b"hello from client");

        // 5. Server responds with another ProtocolFrame.
        let mut header = PacketHeader::default();
        header.magic = PROTOCOL_MAGIC;
        header.schema_version = CURRENT_VERSION.into();
        header.packet_type = 2;
        header.payload_length = 17;
        let resp_frame = ProtocolFrame {
            header,
            payload: b"hello from server",
        };

        adapter
            .send_frame(&resp_frame)
            .await
            .expect("Server should send response frame");

        // Keep connection alive until client disconnects
        conn.closed().await;
    });

    // 1. Client connects.
    let conn = client
        .connect(connect_addr)
        .await
        .expect("Client should connect");
    let (send_stream, recv_stream) = conn.open_bi().await.expect("Should open bi stream");

    let mut adapter = QuicProtocolAdapter::new(send_stream, recv_stream);

    // 3. Client sends a serialized ProtocolFrame.
    let mut header = PacketHeader::default();
    header.magic = PROTOCOL_MAGIC;
    header.schema_version = CURRENT_VERSION.into();
    header.packet_type = 1;
    header.payload_length = 17;
    let req_frame = ProtocolFrame {
        header,
        payload: b"hello from client",
    };

    adapter
        .send_frame(&req_frame)
        .await
        .expect("Client should send frame");

    // 6. Client validates the response.
    let mut buffer = Vec::new();
    let resp_frame = adapter
        .recv_frame(&mut buffer)
        .await
        .expect("Client should receive frame");
    assert_eq!(resp_frame.header.packet_type, 2);
    assert_eq!(resp_frame.payload, b"hello from server");

    adapter.close().await;

    server_task.await.expect("Server task should complete");
}
