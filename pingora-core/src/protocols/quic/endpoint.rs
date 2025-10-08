use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::protocols::digest::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, TimingDigest,
};
use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{Shutdown, UniqueID, UniqueIDType};

use super::datagram::{Datagram, SendDatagram, SendDatagramParts, MAX_DATAGRAM_SIZE};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// QUIC endpoint backed by a UDP socket.
#[derive(Clone, Debug)]
pub struct Endpoint {
    socket: Arc<UdpSocket>,
    socket_digest: Arc<SocketDigest>,
    proxy_digest: Option<Arc<ProxyDigest>>,
    created: SystemTime,
}

impl Endpoint {
    /// Wrap an existing UDP socket.
    pub fn new(socket: UdpSocket) -> std::io::Result<Self> {
        let local_addr = socket.local_addr()?;

        #[cfg(unix)]
        let digest = SocketDigest::from_raw_fd(socket.as_raw_fd());
        #[cfg(windows)]
        let digest = SocketDigest::from_raw_socket(socket.as_raw_socket());

        let _ = digest.local_addr.set(Some(SocketAddr::Inet(local_addr)));

        Ok(Self {
            socket: Arc::new(socket),
            socket_digest: Arc::new(digest),
            proxy_digest: None,
            created: SystemTime::now(),
        })
    }

    /// Wrap an existing UDP socket stored in an [`Arc`].
    pub fn from_arc(socket: Arc<UdpSocket>) -> std::io::Result<Self> {
        let local_addr = socket.local_addr()?;

        #[cfg(unix)]
        let digest = SocketDigest::from_raw_fd(socket.as_raw_fd());
        #[cfg(windows)]
        let digest = SocketDigest::from_raw_socket(socket.as_raw_socket());

        let _ = digest.local_addr.set(Some(SocketAddr::Inet(local_addr)));

        Ok(Self {
            socket,
            socket_digest: Arc::new(digest),
            proxy_digest: None,
            created: SystemTime::now(),
        })
    }

    /// Returns a clone of the inner socket for advanced usage.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Receive a single datagram allocating the default maximum size.
    pub async fn recv(&self) -> std::io::Result<Datagram> {
        self.recv_with_capacity(MAX_DATAGRAM_SIZE).await
    }

    /// Receive a single datagram allocating a custom buffer size.
    pub async fn recv_with_capacity(&self, capacity: usize) -> std::io::Result<Datagram> {
        let mut buf = vec![0u8; capacity];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        let to = self.socket.local_addr()?;

        let info = quiche::RecvInfo { from, to };
        let mut datagram = Datagram::new(buf, info);
        datagram.set_socket_digest(Arc::clone(&self.socket_digest));
        if let Some(proxy) = &self.proxy_digest {
            datagram.set_proxy_digest(Arc::clone(proxy));
        }

        Ok(datagram)
    }

    /// Send an outgoing datagram returned by [`Connection::send`](crate::protocols::quic::Connection::send).
    pub async fn send(&self, datagram: &SendDatagram) -> std::io::Result<usize> {
        self.socket
            .send_to(datagram.payload(), datagram.info().to)
            .await
    }

    /// Send an outgoing datagram represented by borrowed parts.
    pub async fn send_parts(&self, parts: SendDatagramParts<'_>) -> std::io::Result<usize> {
        let (payload, info) = parts.into_parts();
        self.socket.send_to(payload, info.to).await
    }
}

#[async_trait]
impl Shutdown for Endpoint {
    async fn shutdown(&mut self) {}
}

impl UniqueID for Endpoint {
    #[cfg(unix)]
    fn id(&self) -> UniqueIDType {
        self.socket.as_raw_fd()
    }

    #[cfg(windows)]
    fn id(&self) -> UniqueIDType {
        self.socket.as_raw_socket() as UniqueIDType
    }
}

impl GetTimingDigest for Endpoint {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        vec![Some(TimingDigest {
            established_ts: self.created,
        })]
    }
}

impl GetProxyDigest for Endpoint {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.proxy_digest.clone()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.proxy_digest = Some(Arc::new(digest));
    }
}

impl GetSocketDigest for Endpoint {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(Arc::clone(&self.socket_digest))
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.socket_digest = Arc::new(socket_digest);
    }
}
