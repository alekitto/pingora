use std::collections::VecDeque;
use std::time::{Duration, Instant};

use pingora_core::protocols::quic::{
    ClientConfig, Connection, Endpoint, ServerConfig, TransportConfigBuilder, MAX_DATAGRAM_SIZE,
};
use rand::{rngs::OsRng, RngCore};
use tokio::net::UdpSocket;

const STREAM_PAYLOAD: &[u8] = b"ping-stream";
const DATAGRAM_PAYLOAD: &[u8] = b"ping-dgram";

fn build_server_config(cert: &str, key: &str) -> ServerConfig {
    let mut builder = TransportConfigBuilder::new().expect("create server builder");
    builder = builder
        .load_cert_chain_from_pem_file(cert)
        .expect("load cert")
        .load_priv_key_from_pem_file(key)
        .expect("load key")
        .verify_peer(false);

    let builder = builder
        .application_protos(&[b"h3"])
        .expect("set server ALPN");
    let server_config = builder.build_server().expect("build server config");
    server_config
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

fn recv_stream_messages(connection: &mut Connection, buffer: &mut Vec<u8>) {
    let stream_ids: Vec<u64> = connection.inner().readable().collect();
    for stream_id in stream_ids {
        loop {
            let mut chunk = [0u8; 2048];
            match connection.inner_mut().stream_recv(stream_id, &mut chunk) {
                Ok((len, fin)) => {
                    buffer.extend_from_slice(&chunk[..len]);
                    if fin {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => panic!("unexpected stream recv error: {err}"),
            }
        }
    }
}

fn recv_datagram_messages(connection: &mut Connection, received: &mut VecDeque<Vec<u8>>) {
    loop {
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        match connection.inner_mut().dgram_recv(&mut buf) {
            Ok(len) => {
                buf.truncate(len);
                received.push_back(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(err) => panic!("unexpected datagram recv error: {err}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_streams_and_datagrams_round_trip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let cert_path = format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR"));

    let server_config = build_server_config(&cert_path, &key_path);
    let client_config = build_client_config();

    let server_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind server socket");
    let server_addr = server_socket.local_addr().expect("server addr");
    let server_endpoint = Endpoint::new(server_socket).expect("wrap server endpoint");

    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let client_addr = client_socket.local_addr().expect("client addr");
    let client_endpoint = Endpoint::new(client_socket).expect("wrap client endpoint");

    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    OsRng.fill_bytes(&mut scid);
    let scid = quiche::ConnectionId::from_ref(&scid);

    let mut client_conn = client_config
        .connect(Some("localhost"), &scid, client_addr, server_addr)
        .expect("client connection");

    let mut server_conn: Option<Connection> = None;

    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    let mut stream_received = Vec::new();
    let mut datagrams_received = VecDeque::new();
    let mut server_echoed_stream = false;
    let mut server_echoed_datagram = false;
    let mut client_sent_stream = false;
    let mut client_sent_datagram = false;

    loop {
        if start.elapsed() > timeout {
            panic!("timed out waiting for QUIC round trip");
        }

        flush_connection(&client_endpoint, &mut client_conn).await;
        if let Some(conn) = server_conn.as_mut() {
            flush_connection(&server_endpoint, conn).await;
        }

        let mut progress = false;

        if client_conn.inner().is_established()
            && server_conn
                .as_ref()
                .map(|conn| conn.inner().is_established())
                .unwrap_or(false)
        {
            if !client_sent_stream {
                client_conn
                    .inner_mut()
                    .stream_send(0, STREAM_PAYLOAD, true)
                    .expect("send stream payload");
                client_sent_stream = true;
            }
            if !client_sent_datagram {
                client_conn
                    .inner_mut()
                    .dgram_send(DATAGRAM_PAYLOAD)
                    .expect("send datagram payload");
                client_sent_datagram = true;
            }
        }

        tokio::select! {
            server_datagram = server_endpoint.recv() => {
                let mut datagram = server_datagram.expect("server receive");
                let info = *datagram.recv_info();
                if server_conn.is_none() {
                    let header = quiche::Header::from_slice(
                        datagram.payload_mut(),
                        quiche::MAX_CONN_ID_LEN,
                    )
                    .expect("parse header");
                    let scid = quiche::ConnectionId::from_ref(header.dcid.as_ref());
                    let mut conn = server_config
                        .accept(&scid, None, info.to, info.from)
                        .expect("accept connection");
                    match conn.recv(&mut datagram) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(err) => panic!("server recv failed: {err}"),
                    }
                    server_conn = Some(conn);
                } else if let Some(conn) = server_conn.as_mut() {
                    match conn.recv(&mut datagram) {
                        Ok(_) | Err(quiche::Error::Done) => {}
                        Err(err) => panic!("server recv failed: {err}"),
                    }
                }

                if let Some(conn) = server_conn.as_mut() {
                    loop {
                        let mut payload = vec![0u8; MAX_DATAGRAM_SIZE];
                        match conn.inner_mut().dgram_recv(&mut payload) {
                            Ok(len) => {
                                payload.truncate(len);
                                conn
                                    .inner_mut()
                                    .dgram_send(&payload)
                                    .expect("echo datagram");
                                server_echoed_datagram = true;
                            }
                            Err(quiche::Error::Done) => break,
                            Err(err) => panic!("server datagram recv failed: {err}"),
                        }
                    }

                    let readable: Vec<u64> = conn.inner().readable().collect();
                    for stream_id in readable {
                        loop {
                            let mut chunk = [0u8; 2048];
                            match conn.inner_mut().stream_recv(stream_id, &mut chunk) {
                                Ok((len, fin)) => {
                                    conn
                                        .inner_mut()
                                        .stream_send(stream_id, &chunk[..len], fin)
                                        .expect("echo stream chunk");
                                    server_echoed_stream = true;
                                    if fin {
                                        break;
                                    }
                                }
                                Err(quiche::Error::Done) => break,
                                Err(err) => panic!("server stream recv failed: {err}"),
                            }
                        }
                    }
                }
                progress = true;
            }
            client_datagram = client_endpoint.recv() => {
                let mut datagram = client_datagram.expect("client receive");
                match client_conn.recv(&mut datagram) {
                    Ok(_) | Err(quiche::Error::Done) => {}
                    Err(err) => panic!("client recv failed: {err}"),
                }
                recv_datagram_messages(&mut client_conn, &mut datagrams_received);
                recv_stream_messages(&mut client_conn, &mut stream_received);
                progress = true;
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }

        if progress {
            flush_connection(&client_endpoint, &mut client_conn).await;
            if let Some(conn) = server_conn.as_mut() {
                flush_connection(&server_endpoint, conn).await;
            }
        }

        if server_echoed_stream
            && server_echoed_datagram
            && stream_received.ends_with(STREAM_PAYLOAD)
            && datagrams_received
                .back()
                .map(|payload| payload.as_slice() == DATAGRAM_PAYLOAD)
                .unwrap_or(false)
        {
            break;
        }
    }
}
