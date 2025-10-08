// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Datagram wrapper for UDP packets.

use std::sync::Arc;
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::protocols::digest::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, TimingDigest,
};
use crate::protocols::l4::socket::SocketAddr;
use crate::protocols::{raw_connect::ProxyDigest, Shutdown, UniqueID, UniqueIDType};

/// Maximum UDP datagram payload size we allocate for when reading.
const MAX_DATAGRAM_CAPACITY: usize = 65_535;

/// Representation of a single UDP datagram received from a listener.
#[derive(Debug)]
pub struct Datagram {
    socket: Arc<UdpSocket>,
    payload: Vec<u8>,
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    socket_digest: Arc<SocketDigest>,
    received: SystemTime,
    proxy_digest: Option<Arc<ProxyDigest>>,
}

impl Datagram {
    pub(crate) async fn receive(socket: &Arc<UdpSocket>) -> std::io::Result<Self> {
        let mut buf = vec![0u8; MAX_DATAGRAM_CAPACITY];
        let (len, source) = socket.recv_from(&mut buf).await?;
        buf.truncate(len);

        let destination = socket.local_addr()?;
        let owned_socket = Arc::clone(socket);

        #[cfg(unix)]
        let digest = SocketDigest::from_raw_fd(owned_socket.as_raw_fd());
        #[cfg(windows)]
        let digest = SocketDigest::from_raw_socket(owned_socket.as_raw_socket());

        let _ = digest.peer_addr.set(Some(SocketAddr::Inet(source)));
        let _ = digest.local_addr.set(Some(SocketAddr::Inet(destination)));

        Ok(Datagram {
            socket: owned_socket,
            payload: buf,
            source,
            destination,
            socket_digest: Arc::new(digest),
            received: SystemTime::now(),
            proxy_digest: None,
        })
    }

    /// Access the underlying UDP socket.
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Immutable reference to the payload bytes for this datagram.
    pub fn data(&self) -> &[u8] {
        &self.payload
    }

    /// Consume the datagram, returning the underlying socket and payload.
    pub fn into_parts(
        self,
    ) -> (
        Arc<UdpSocket>,
        Vec<u8>,
        std::net::SocketAddr,
        std::net::SocketAddr,
    ) {
        (self.socket, self.payload, self.source, self.destination)
    }

    /// Source address of the datagram.
    pub fn source(&self) -> std::net::SocketAddr {
        self.source
    }

    /// Destination address the datagram was received on.
    pub fn destination(&self) -> std::net::SocketAddr {
        self.destination
    }
}

#[async_trait]
impl Shutdown for Datagram {
    async fn shutdown(&mut self) {}
}

impl UniqueID for Datagram {
    #[cfg(unix)]
    fn id(&self) -> UniqueIDType {
        self.socket.as_raw_fd()
    }

    #[cfg(windows)]
    fn id(&self) -> UniqueIDType {
        self.socket.as_raw_socket() as UniqueIDType
    }
}

impl GetSocketDigest for Datagram {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        Some(self.socket_digest.clone())
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.socket_digest = Arc::new(socket_digest);
    }
}

impl GetTimingDigest for Datagram {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        vec![Some(TimingDigest {
            established_ts: self.received,
        })]
    }
}

impl GetProxyDigest for Datagram {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.proxy_digest.clone()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.proxy_digest = Some(Arc::new(digest));
    }
}
