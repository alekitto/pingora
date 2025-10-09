#![cfg(feature = "quic")]

mod utils;

use std::time::{Duration, Instant};

use rand::{rngs::OsRng, RngCore};
use reqwest::StatusCode;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use pingora_core::protocols::quic::{ClientConfig, Connection, Endpoint, TransportConfigBuilder};

fn build_client_config() -> ClientConfig {
    let mut builder = TransportConfigBuilder::new().expect("create client builder");
    builder = builder.verify_peer(false);
    let builder = builder
        .application_protos(&[b"h3"])
        .expect("set client ALPN");
    let client_config = builder.build_client();
    client_config
        .transport()
        .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32));
    client_config
}

async fn flush_connection(endpoint: &Endpoint, connection: &mut Connection) {
    loop {
        match connection.send() {
            Ok(packet) => {
                endpoint.send(&packet).await.expect("send datagram");
            }
            Err(quiche::Error::Done) => break,
            Err(err) => panic!("unexpected quiche send error: {err}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http3_frontend_completes_handshake_and_tcp_fallback() {
    utils::server_utils::init();

    let server_addr = "127.0.0.1:6154".parse().expect("parse server address");
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let client_endpoint = Endpoint::new(client_socket).expect("wrap client endpoint");
    let client_addr = client_endpoint.socket().local_addr().expect("client addr");

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    OsRng.fill_bytes(&mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut client_conn = build_client_config()
        .connect(Some("localhost"), &scid, client_addr, server_addr)
        .expect("connect to HTTP/3 listener");

    flush_connection(&client_endpoint, &mut client_conn).await;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = false;
    while Instant::now() < deadline {
        if let Ok(Ok(mut datagram)) =
            timeout(Duration::from_millis(100), client_endpoint.recv()).await
        {
            let _ = client_conn.recv(&mut datagram);
            received = true;
            break;
        }
        flush_connection(&client_endpoint, &mut client_conn).await;
    }

    assert!(
        received,
        "expected QUIC handshake response from proxy HTTP/3 listener"
    );

    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:6147/echo")
        .send()
        .await
        .expect("fallback HTTP request succeeds");
    assert_eq!(response.status(), StatusCode::OK);
}
