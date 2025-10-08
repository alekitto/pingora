use pingora_core::listeners;

#[cfg(unix)]
use pingora_core::listeners::UdpSocketOptions;

#[tokio::test]
async fn udp_endpoint_receives_datagram() {
    let builder = listeners::udp("127.0.0.1:0");

    #[cfg(unix)]
    let endpoint = builder.listen(None).await.expect("binds UDP endpoint");

    #[cfg(windows)]
    let endpoint = builder.listen().await.expect("binds UDP endpoint");

    let local_addr = endpoint
        .udp_socket()
        .expect("listener exposes UDP socket")
        .local_addr()
        .expect("has local addr");

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender");
    let payload = b"integration".to_vec();
    sender
        .send_to(&payload, local_addr)
        .await
        .expect("send datagram");

    let datagram = endpoint.recv_datagram().await.expect("receive datagram");
    assert_eq!(datagram.data(), payload.as_slice());
    assert_eq!(datagram.source(), sender.local_addr().unwrap());
    assert_eq!(datagram.destination(), local_addr);
}

#[cfg(unix)]
#[tokio::test]
async fn udp_endpoint_supports_reuseport() {
    let mut reuse_options = UdpSocketOptions::default();
    reuse_options.so_reuseaddr = Some(true);
    reuse_options.so_reuseport = Some(true);

    let builder1 = listeners::udp_with_options("127.0.0.1:0", Some(reuse_options.clone()));

    let endpoint1 = builder1
        .listen(None)
        .await
        .expect("binds first UDP endpoint");

    let bound_addr = endpoint1
        .udp_socket()
        .expect("udp socket available")
        .local_addr()
        .expect("has local addr");

    let addr_str = bound_addr.to_string();
    let builder2 = listeners::udp_with_options(&addr_str, Some(reuse_options));

    let endpoint2 = builder2
        .listen(None)
        .await
        .expect("binds second UDP endpoint");

    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender");
    sender
        .send_to(b"payload", bound_addr)
        .await
        .expect("send datagram");

    let recv1 = endpoint1.recv_datagram();
    let recv2 = endpoint2.recv_datagram();

    tokio::select! {
        res = recv1 => {
            res.expect("endpoint 1 receives datagram");
        }
        res = recv2 => {
            res.expect("endpoint 2 receives datagram");
        }
    }
}
