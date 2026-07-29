use bw_transport::{QuicClient, QuicServer};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[tokio::test]
async fn test_quic_raw_byte_exchange() {
    let server_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let server = QuicServer::bind(server_addr).expect("Server should bind");

    // Get actual bound port
    let bound_addr = server.endpoint.local_addr().unwrap();
    let connect_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bound_addr.port());

    let client = QuicClient::bind().expect("Client should bind");

    // Spawn server accept task
    let server_task = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .expect("Server should accept connection");
        let (mut send_stream, mut recv_stream) =
            conn.accept_bi().await.expect("Should accept bi stream");

        // Read "hello"
        let mut buf = vec![0u8; 5];
        recv_stream
            .read_exact(&mut buf)
            .await
            .expect("Should read exact");
        assert_eq!(&buf, b"hello");

        // Write "world"
        send_stream
            .write_all(b"world")
            .await
            .expect("Should write all");
        send_stream.finish().expect("Should finish stream");

        // Keep connection alive until client disconnects
        conn.closed().await;
    });

    // Client connects
    let conn = client
        .connect(connect_addr)
        .await
        .expect("Client should connect");

    // Client opens bi stream
    let (mut send_stream, mut recv_stream) = conn.open_bi().await.expect("Should open bi stream");

    // Write "hello"
    send_stream
        .write_all(b"hello")
        .await
        .expect("Should write hello");

    // Read "world"
    let mut buf = vec![0u8; 5];
    recv_stream
        .read_exact(&mut buf)
        .await
        .expect("Should read world");
    assert_eq!(&buf, b"world");

    server_task.await.expect("Server task should complete");
}
