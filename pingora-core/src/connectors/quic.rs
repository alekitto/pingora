use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use log::trace;
use pingora_error::{Error, ErrorType::InternalError, OkOrErr, OrErr, Result};
use rand::{rngs::OsRng, RngCore};
use tokio::net::UdpSocket;

use crate::protocols::quic::{ClientConfig, Connection, Datagram, Endpoint, SendDatagram};
use crate::upstreams::peer::{Peer, QuicTransportOptions};

/// Wrapper around a QUIC client connection and its underlying UDP endpoint.
pub struct QuicUpstream {
    endpoint: Endpoint,
    connection: Connection,
    remote_addr: SocketAddr,
    handshake_timeout: Option<Duration>,
}

impl QuicUpstream {
    /// Access the QUIC connection.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Mutable access to the QUIC connection.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Access the UDP endpoint used to exchange datagrams.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Mutable access to the UDP endpoint.
    pub fn endpoint_mut(&mut self) -> &mut Endpoint {
        &mut self.endpoint
    }

    /// Remote backend address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Configured handshake timeout for the upstream if any.
    pub fn handshake_timeout(&self) -> Option<Duration> {
        self.handshake_timeout
    }

    /// Receive the next datagram from the backend.
    pub async fn recv(&self) -> std::io::Result<Datagram> {
        self.endpoint.recv().await
    }

    /// Send an outgoing datagram to the backend.
    pub async fn send(&self, datagram: &SendDatagram) -> std::io::Result<usize> {
        self.endpoint.send(datagram).await
    }
}

/// QUIC client connector responsible for establishing upstream connections using `quiche`.
#[derive(Clone)]
pub struct QuicConnector {
    config: Arc<ClientConfig>,
}

impl QuicConnector {
    /// Create a new connector from a shared [`ClientConfig`].
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    fn quic_options<'a, P: Peer>(&self, peer: &'a P) -> Option<&'a QuicTransportOptions> {
        peer.quic_transport_options()
    }

    /// Establish a new QUIC connection to the backend specified by `peer`.
    pub async fn connect<P>(&self, peer: &P) -> Result<QuicUpstream>
    where
        P: Peer + Send + Sync,
    {
        let remote_addr = peer
            .address()
            .as_inet()
            .cloned()
            .or_err(InternalError, "QUIC upstream requires an IP address")?;

        let bind_addr = SocketAddr::new(
            match remote_addr {
                SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            0,
        );

        let socket = UdpSocket::bind(bind_addr)
            .await
            .or_err(InternalError, "failed to bind QUIC UDP socket")?;

        let local_addr = socket
            .local_addr()
            .or_err(InternalError, "failed to obtain local QUIC address")?;

        let endpoint =
            Endpoint::new(socket).or_err(InternalError, "failed to wrap QUIC UDP socket")?;

        let options = self.quic_options(peer);

        if let Some(opt) = options {
            if !opt.alpn_protocols.is_empty() {
                let protos: Vec<&[u8]> = opt.alpn_protocols.iter().map(Vec::as_slice).collect();
                let result = self
                    .config
                    .transport()
                    .with_config_mut(|cfg| cfg.set_application_protos(&protos));
                if let Err(err) = result {
                    return Err(Error::explain(
                        InternalError,
                        format!("failed to configure QUIC ALPN: {err}"),
                    ));
                }
            }
        }

        let scid_bytes = match options.and_then(|opt| opt.source_connection_id.clone()) {
            Some(scid) if scid.len() <= quiche::MAX_CONN_ID_LEN => scid,
            Some(scid) => {
                return Err(Error::explain(
                    InternalError,
                    format!(
                        "QUIC source connection id length {} exceeds maximum {}",
                        scid.len(),
                        quiche::MAX_CONN_ID_LEN
                    ),
                ));
            }
            None => {
                let mut random = [0u8; quiche::MAX_CONN_ID_LEN];
                OsRng.fill_bytes(&mut random);
                random.to_vec()
            }
        };

        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let server_name = options
            .and_then(|opt| opt.server_name.as_deref())
            .filter(|name| !name.is_empty())
            .or_else(|| {
                let sni = peer.sni();
                if sni.is_empty() {
                    None
                } else {
                    Some(sni)
                }
            });

        let connection = self
            .config
            .connect(server_name, &scid, local_addr, remote_addr)
            .or_err(InternalError, "failed to establish QUIC connection")?;

        let mut upstream = QuicUpstream {
            endpoint,
            connection,
            remote_addr,
            handshake_timeout: options.and_then(|opt| opt.handshake_timeout),
        };

        Self::flush_initial(&mut upstream).await?;

        Ok(upstream)
    }

    async fn flush_initial(upstream: &mut QuicUpstream) -> Result<()> {
        loop {
            match upstream.connection.send() {
                Ok(packet) => {
                    let size = upstream
                        .endpoint
                        .send(&packet)
                        .await
                        .or_err(InternalError, "failed to send QUIC datagram")?;
                    trace!("sent initial QUIC datagram of {size} bytes");
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    return Err(Error::explain(
                        InternalError,
                        format!("quiche send error during connect: {err}"),
                    ));
                }
            }
        }

        Ok(())
    }
}

impl QuicUpstream {
    /// Drive the connection timeout using `quiche`'s timer semantics.
    pub fn timeout(&self) -> Option<Duration> {
        self.connection.timeout()
    }
}
