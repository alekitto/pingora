use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

use crate::protocols::digest::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketDigest, TimingDigest,
};
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{Shutdown, UniqueID, UniqueIDType};

use super::datagram::{Datagram, SendDatagram};

/// Wrapper around a `quiche::Connection` providing Pingora digest integration.
pub struct Connection {
    inner: quiche::Connection,
    established: SystemTime,
    proxy_digest: Option<Arc<ProxyDigest>>,
    socket_digest: Option<Arc<SocketDigest>>,
}

impl Connection {
    /// Create a new wrapper around an established `quiche` connection.
    pub fn new(connection: quiche::Connection) -> Self {
        Self {
            inner: connection,
            established: SystemTime::now(),
            proxy_digest: None,
            socket_digest: None,
        }
    }

    /// Access the inner `quiche::Connection`.
    pub fn inner(&self) -> &quiche::Connection {
        &self.inner
    }

    /// Mutable access to the inner `quiche::Connection`.
    pub fn inner_mut(&mut self) -> &mut quiche::Connection {
        &mut self.inner
    }

    /// Feed an incoming datagram into the QUIC connection state machine.
    pub fn recv(&mut self, datagram: &mut Datagram) -> Result<usize, quiche::Error> {
        let info = datagram.quiche_recv_info();
        self.inner.recv(datagram.payload_mut(), info)
    }

    /// Produce an outgoing datagram for the peer if there is pending data.
    pub fn send(&mut self) -> Result<SendDatagram, quiche::Error> {
        let mut out = vec![0u8; self.inner.max_send_udp_payload_size()];
        let (written, info) = self.inner.send(&mut out)?;
        out.truncate(written);
        Ok(SendDatagram::new(out, info))
    }

    /// Returns the next timeout duration for the connection, if any.
    pub fn timeout(&self) -> Option<Duration> {
        self.inner.timeout()
    }
}

#[async_trait]
impl Shutdown for Connection {
    async fn shutdown(&mut self) {
        let _ = self.inner.close(false, 0u64, b"shutdown");
    }
}

impl UniqueID for Connection {
    fn id(&self) -> UniqueIDType {
        #[allow(clippy::cast_possible_truncation)]
        {
            let mut hasher = DefaultHasher::new();
            self.inner.source_id().as_ref().hash(&mut hasher);
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
}

impl GetTimingDigest for Connection {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        vec![Some(TimingDigest {
            established_ts: self.established,
        })]
    }

    fn get_read_pending_time(&self) -> Duration {
        Duration::ZERO
    }

    fn get_write_pending_time(&self) -> Duration {
        Duration::ZERO
    }
}

impl GetProxyDigest for Connection {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.proxy_digest.clone()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.proxy_digest = Some(Arc::new(digest));
    }
}

impl GetSocketDigest for Connection {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.socket_digest.clone()
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.socket_digest = Some(Arc::new(socket_digest));
    }
}

impl From<quiche::Connection> for Connection {
    fn from(connection: quiche::Connection) -> Self {
        Self::new(connection)
    }
}
