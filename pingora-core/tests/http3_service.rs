#![cfg(feature = "quic")]

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use http::{Response, StatusCode};
use once_cell::sync::Lazy;
use pingora_core::protocols::quic::{ClientConfig, Endpoint, ServerConfig, TransportConfigBuilder};
use pingora_core::services::http3::Http3Service;
use pingora_core::services::Service;
use rand::{rngs::OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time::timeout;

use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;

static LOGGER: Lazy<()> = Lazy::new(|| {
    let _ = env_logger::builder().is_test(true).try_init();
});

#[derive(Clone)]
struct RecordingApp {
    signal: Arc<Notify>,
}

#[async_trait]
impl ServeHttp for RecordingApp {
    async fn response(&self, _session: &mut ServerSession) -> Response<Vec<u8>> {
        self.signal.notify_waiters();
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(b"ok".to_vec())
            .expect("build HTTP/3 response")
    }
}

fn build_server_config(cert: &str, key: &str) -> ServerConfig {
    let mut builder = TransportConfigBuilder::new().expect("create server builder");
    builder = builder
        .load_cert_chain_from_pem_file(cert)
        .expect("load certificate chain")
        .load_priv_key_from_pem_file(key)
        .expect("load private key")
        .verify_peer(false);
    let builder = builder
        .application_protos(&[b"h3"])
        .expect("set server ALPN");
    let server_config = builder.build_server().expect("build server config");
    let _ = server_config
        .transport()
        .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32));
    server_config
}

fn build_client_config() -> ClientConfig {
    let mut builder = TransportConfigBuilder::new().expect("create client builder");
    builder = builder.verify_peer(false);
    let builder = builder
        .application_protos(&[b"h3"])
        .expect("set client ALPN");
    let client_config = builder.build_client();
    let _ = client_config
        .transport()
        .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32));
    client_config
}

async fn flush_connection(
    endpoint: &Endpoint,
    connection: &mut pingora_core::protocols::quic::Connection,
) {
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
async fn http3_service_accepts_handshake_and_notifies_app() {
    Lazy::force(&LOGGER);

    let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

    let server_config = build_server_config(&cert_path, &key_path);
    let listen_addr = "127.0.0.1:8643";

    let signal = Arc::new(Notify::new());
    let app = Arc::new(RecordingApp {
        signal: Arc::clone(&signal),
    });

    let mut service = Http3Service::new("test-http3", listen_addr, server_config, Arc::clone(&app));
    service.set_alpn_h3().expect("enable ALPN token");

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let service_task = tokio::spawn(async move {
        service
            .start_service(
                #[cfg(unix)]
                None,
                shutdown_rx,
                1,
            )
            .await;
    });

    // Give the service a moment to bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let client_endpoint = Endpoint::new(client_socket).expect("wrap client endpoint");
    let client_addr = client_endpoint
        .socket()
        .local_addr()
        .expect("client addr");

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    OsRng.fill_bytes(&mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut client_conn = build_client_config()
        .connect(
            Some("localhost"),
            &scid,
            client_addr,
            listen_addr.parse().unwrap(),
        )
        .expect("build client connection");

    flush_connection(&client_endpoint, &mut client_conn).await;

    let mut received = false;
    let deadline = Instant::now() + Duration::from_secs(2);
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

    assert!(received, "expected handshake response from HTTP/3 service");

    shutdown_tx.send(true).expect("trigger shutdown");
    service_task
        .await
        .expect("HTTP/3 service task should exit cleanly");
}
