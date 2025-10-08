use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;

use crate::protocols::digest::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, TimingDigest,
};
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{Shutdown, UniqueID, UniqueIDType};

/// Maximum QUIC datagram size we support when allocating buffers.
pub const MAX_DATAGRAM_SIZE: usize = 65_535;

/// Owned representation of a QUIC UDP datagram.
pub struct Datagram {
    payload: Vec<u8>,
    info: quiche::RecvInfo,
    received: SystemTime,
    socket_digest: Option<Arc<SocketDigest>>,
    proxy_digest: Option<Arc<ProxyDigest>>,
}

impl Datagram {
    /// Create a new datagram from raw parts.
    pub fn new(payload: Vec<u8>, info: quiche::RecvInfo) -> Self {
        Self {
            payload,
            info,
            received: SystemTime::now(),
            socket_digest: None,
            proxy_digest: None,
        }
    }

    /// Build a datagram from discrete parts.
    pub fn from_parts(parts: DatagramParts) -> Self {
        Self {
            payload: parts.payload,
            info: parts.info,
            received: parts.received.unwrap_or_else(SystemTime::now),
            socket_digest: parts.socket_digest,
            proxy_digest: parts.proxy_digest,
        }
    }

    /// Decompose the datagram into raw components.
    pub fn into_parts(self) -> DatagramParts {
        DatagramParts {
            payload: self.payload,
            info: self.info,
            received: Some(self.received),
            socket_digest: self.socket_digest,
            proxy_digest: self.proxy_digest,
        }
    }

    /// Immutable view into the payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Mutable view into the payload bytes.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.payload
    }

    /// Length of the datagram payload.
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Access the `quiche` metadata associated with the datagram.
    pub fn recv_info(&self) -> &quiche::RecvInfo {
        &self.info
    }

    /// Return a copy of the [`quiche::RecvInfo`] for interfacing with `quiche` APIs.
    pub fn quiche_recv_info(&self) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: self.info.from,
            to: self.info.to,
        }
    }

    /// Timestamp indicating when the datagram was received.
    pub fn received_at(&self) -> SystemTime {
        self.received
    }

    /// Attach socket metadata to the datagram.
    pub fn set_socket_digest(&mut self, digest: Arc<SocketDigest>) {
        self.socket_digest = Some(digest);
    }

    /// Attach proxy metadata to the datagram.
    pub fn set_proxy_digest(&mut self, digest: Arc<ProxyDigest>) {
        self.proxy_digest = Some(digest);
    }
}

/// Owned parts for constructing [`Datagram`] values.
pub struct DatagramParts {
    pub payload: Vec<u8>,
    pub info: quiche::RecvInfo,
    pub received: Option<SystemTime>,
    pub socket_digest: Option<Arc<SocketDigest>>,
    pub proxy_digest: Option<Arc<ProxyDigest>>,
}

/// Borrowed view of datagram data suitable for the `quiche` APIs.
pub struct DatagramPayload<'a> {
    payload: &'a mut [u8],
    info: quiche::RecvInfo,
}

impl<'a> DatagramPayload<'a> {
    /// Deconstruct into a tuple compatible with `quiche::Connection::recv`.
    pub fn into_parts(self) -> (&'a mut [u8], quiche::RecvInfo) {
        (self.payload, self.info)
    }
}

impl<'a> From<&'a mut Datagram> for DatagramPayload<'a> {
    fn from(value: &'a mut Datagram) -> Self {
        let info = value.quiche_recv_info();
        let payload = value.payload.as_mut_slice();
        Self { payload, info }
    }
}

/// Owned outgoing datagram returned by `Connection::send`.
#[derive(Debug, Clone)]
pub struct SendDatagram {
    payload: Vec<u8>,
    info: quiche::SendInfo,
}

impl SendDatagram {
    pub fn new(payload: Vec<u8>, info: quiche::SendInfo) -> Self {
        Self { payload, info }
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn info(&self) -> quiche::SendInfo {
        self.info
    }

    pub fn into_parts(self) -> SendDatagramPartsOwned {
        SendDatagramPartsOwned {
            payload: self.payload,
            info: self.info,
        }
    }

    pub fn as_parts(&self) -> SendDatagramParts<'_> {
        SendDatagramParts {
            payload: &self.payload,
            info: self.info,
        }
    }
}

/// Borrowed view of outgoing datagram data.
pub struct SendDatagramParts<'a> {
    pub payload: &'a [u8],
    pub info: quiche::SendInfo,
}

impl<'a> SendDatagramParts<'a> {
    pub fn into_parts(self) -> (&'a [u8], quiche::SendInfo) {
        (self.payload, self.info)
    }
}

/// Owned parts for outgoing datagrams.
pub struct SendDatagramPartsOwned {
    pub payload: Vec<u8>,
    pub info: quiche::SendInfo,
}

#[async_trait]
impl Shutdown for Datagram {
    async fn shutdown(&mut self) {}
}

impl UniqueID for Datagram {
    fn id(&self) -> UniqueIDType {
        let mut hasher = DefaultHasher::new();
        self.info.from.hash(&mut hasher);
        self.info.to.hash(&mut hasher);
        let value = hasher.finish();
        #[cfg(unix)]
        {
            (value & 0x7fff_ffff) as i32
        }
        #[cfg(windows)]
        {
            value as UniqueIDType
        }
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

impl GetSocketDigest for Datagram {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.socket_digest.clone()
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.socket_digest = Some(Arc::new(socket_digest));
    }
}
