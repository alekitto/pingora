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

//! Health Check interface and methods.

use crate::{Backend, BackendProtocol};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::connectors::{http::Connector as HttpConnector, TransportConnector};
use pingora_core::upstreams::peer::{BasicPeer, HttpPeer, Peer};
use pingora_error::{Error, ErrorType, ErrorType::CustomCode, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// [HealthObserve] is an interface for observing health changes of backends,
/// this is what's used for our health observation callback.
#[async_trait]
pub trait HealthObserve {
    /// Observes the health of a [Backend], can be used for monitoring purposes.
    async fn observe(&self, target: &Backend, healthy: bool);
}
/// Provided to a [HealthCheck] to observe changes to [Backend] health.
pub type HealthObserveCallback = Box<dyn HealthObserve + Send + Sync>;

/// Provided to a [HealthCheck] to fetch [Backend] summary for detailed logging.
pub type BackendSummary = Box<dyn Fn(&Backend) -> String + Send + Sync>;

/// [HealthCheck] is the interface to implement health check for backends
#[async_trait]
pub trait HealthCheck {
    /// Check the given backend.
    ///
    /// `Ok(())`` if the check passes, otherwise the check fails.
    async fn check(&self, target: &Backend) -> Result<()>;

    /// Whether this health check supports the given backend protocol.
    fn supports_protocol(&self, protocol: BackendProtocol) -> bool {
        matches!(protocol, BackendProtocol::Tcp)
    }

    /// Validate that the backend can be probed by this health check.
    ///
    /// By default, QUIC backends are rejected because no built-in health
    /// checks support QUIC probing yet.
    fn validate_backend(&self, backend: &Backend) -> Result<()> {
        if matches!(backend.protocol, BackendProtocol::Quic)
            && !self.supports_protocol(BackendProtocol::Quic)
        {
            return Error::e_explain(
                ErrorType::Custom("quic_health_check_unavailable"),
                "health check does not support QUIC backends",
            );
        }

        Ok(())
    }

    /// Called when the health changes for a [Backend].
    async fn health_status_change(&self, _target: &Backend, _healthy: bool) {}

    /// Called when a detailed [Backend] summary is needed.
    fn backend_summary(&self, target: &Backend) -> String {
        format!("{target:?}")
    }

    /// This function defines how many *consecutive* checks should flip the health of a backend.
    ///
    /// For example: with `success``: `true`: this function should return the
    /// number of check need to flip from unhealthy to healthy.
    fn health_threshold(&self, success: bool) -> usize;
}

/// TCP health check
///
/// This health check checks if a TCP (or TLS) connection can be established to a given backend.
pub struct TcpHealthCheck {
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// How to connect to the backend.
    ///
    /// This field defines settings like the connect timeout and src IP to bind.
    /// The SocketAddr of `peer_template` is just a placeholder which will be replaced by the
    /// actual address of the backend when the health check runs.
    ///
    /// By default, this check will try to establish a TCP connection. When the `sni` field is
    /// set, it will also try to establish a TLS connection on top of the TCP connection.
    pub peer_template: BasicPeer,
    connector: TransportConnector,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
}

impl Default for TcpHealthCheck {
    fn default() -> Self {
        let mut peer_template = BasicPeer::new("0.0.0.0:1");
        peer_template.options.connection_timeout = Some(Duration::from_secs(1));
        TcpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            peer_template,
            connector: TransportConnector::new(None),
            health_changed_callback: None,
        }
    }
}

impl TcpHealthCheck {
    /// Create a new [TcpHealthCheck] with the following default values
    /// * connect timeout: 1 second
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    pub fn new() -> Box<Self> {
        Box::<TcpHealthCheck>::default()
    }

    /// Create a new [TcpHealthCheck] that tries to establish a TLS connection.
    ///
    /// The default values are the same as [Self::new()].
    pub fn new_tls(sni: &str) -> Box<Self> {
        let mut new = Self::default();
        new.peer_template.sni = sni.into();
        Box::new(new)
    }

    /// Replace the internal tcp connector with the given [TransportConnector]
    pub fn set_connector(&mut self, connector: TransportConnector) {
        self.connector = connector;
    }
}

#[async_trait]
impl HealthCheck for TcpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        self.connector.get_stream(&peer).await.map(|_| {})
    }

    fn supports_protocol(&self, protocol: BackendProtocol) -> bool {
        matches!(protocol, BackendProtocol::Tcp)
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }
}

type UdpValidator = Box<dyn Fn(&[u8]) -> Result<()> + Send + Sync>;

/// UDP health check
///
/// Sends a UDP datagram to a backend and optionally validates the response.
pub struct UdpHealthCheck {
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// Payload sent as part of the probe.
    pub payload: Vec<u8>,
    /// Optional payload expected in response. When set the received datagram must match.
    pub expected_response: Option<Vec<u8>>,
    /// Optional validator invoked with the received payload.
    pub validator: Option<UdpValidator>,
    /// Optional socket address to bind the probe socket.
    pub bind_addr: Option<StdSocketAddr>,
    /// Timeout for the overall health check operation.
    pub timeout: Duration,
    /// Maximum number of bytes read from the response datagram.
    pub max_response_size: usize,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
}

impl Default for UdpHealthCheck {
    fn default() -> Self {
        UdpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            payload: Vec::new(),
            expected_response: None,
            validator: None,
            bind_addr: None,
            timeout: Duration::from_secs(1),
            max_response_size: 1500,
            health_changed_callback: None,
        }
    }
}

impl UdpHealthCheck {
    /// Create a new [`UdpHealthCheck`] with default configuration.
    pub fn new() -> Box<Self> {
        Box::<UdpHealthCheck>::default()
    }

    fn default_bind(addr: &StdSocketAddr) -> StdSocketAddr {
        match addr {
            StdSocketAddr::V4(_) => StdSocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            StdSocketAddr::V6(_) => StdSocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    }
}

#[async_trait]
impl HealthCheck for UdpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> Result<()> {
        if !matches!(target.protocol, BackendProtocol::Udp) {
            return Error::e_explain(
                ErrorType::InternalError,
                "UDP health check requires UDP backend",
            );
        }

        let addr =
            target.addr.as_inet().cloned().ok_or_else(|| {
                Error::explain(ErrorType::InternalError, "UDP backend must be inet")
            })?;

        let bind_addr = self.bind_addr.unwrap_or_else(|| Self::default_bind(&addr));
        let payload_required = !self.payload.is_empty()
            || self.expected_response.is_some()
            || self.validator.is_some();
        let payload = if payload_required {
            self.payload.as_slice()
        } else {
            &[]
        };
        let max_response = self.max_response_size.max(1);
        let expected = self.expected_response.as_ref();
        let validator = self.validator.as_ref();

        let probe = async {
            let socket = UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| Error::because(ErrorType::BindError, "udp health check bind", e))?;
            socket.connect(addr).await.map_err(|e| {
                Error::because(ErrorType::SocketError, "udp health check connect", e)
            })?;

            if payload_required {
                socket.send(payload).await.map_err(|e| {
                    Error::because(ErrorType::SocketError, "udp health check send", e)
                })?;
            }

            if expected.is_some() || validator.is_some() {
                let mut buf = vec![0u8; max_response];
                let received = socket.recv(&mut buf).await.map_err(|e| {
                    Error::because(ErrorType::SocketError, "udp health check recv", e)
                })?;
                buf.truncate(received);

                if let Some(expected) = expected {
                    if &buf != expected {
                        return Error::e_explain(
                            ErrorType::InternalError,
                            "udp health check unexpected response",
                        );
                    }
                }

                if let Some(validator) = validator {
                    validator(&buf)?;
                }
            }

            Ok(())
        };

        timeout(self.timeout, probe).await.map_err(|_| {
            Error::explain(ErrorType::ConnectTimedout, "udp health check timeout")
        })??;

        Ok(())
    }

    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }

    fn backend_summary(&self, target: &Backend) -> String {
        format!("UDP backend {target:?}")
    }

    fn supports_protocol(&self, protocol: BackendProtocol) -> bool {
        matches!(protocol, BackendProtocol::Udp)
    }
}

type Validator = Box<dyn Fn(&ResponseHeader) -> Result<()> + Send + Sync>;

/// HTTP health check
///
/// This health check checks if it can receive the expected HTTP(s) response from the given backend.
pub struct HttpHealthCheck {
    /// Number of successful checks to flip from unhealthy to healthy.
    pub consecutive_success: usize,
    /// Number of failed checks to flip from healthy to unhealthy.
    pub consecutive_failure: usize,
    /// How to connect to the backend.
    ///
    /// This field defines settings like the connect timeout and src IP to bind.
    /// The SocketAddr of `peer_template` is just a placeholder which will be replaced by the
    /// actual address of the backend when the health check runs.
    ///
    /// Set the `scheme` field to use HTTPs.
    pub peer_template: HttpPeer,
    /// Whether the underlying TCP/TLS connection can be reused across checks.
    ///
    /// * `false` will make sure that every health check goes through TCP (and TLS) handshakes.
    ///   Established connections sometimes hide the issue of firewalls and L4 LB.
    /// * `true` will try to reuse connections across checks, this is the more efficient and fast way
    ///   to perform health checks.
    pub reuse_connection: bool,
    /// The request header to send to the backend
    pub req: RequestHeader,
    connector: HttpConnector,
    /// Optional field to define how to validate the response from the server.
    ///
    /// If not set, any response with a `200 OK` is considered a successful check.
    pub validator: Option<Validator>,
    /// Sometimes the health check endpoint lives one a different port than the actual backend.
    /// Setting this option allows the health check to perform on the given port of the backend IP.
    pub port_override: Option<u16>,
    /// A callback that is invoked when the `healthy` status changes for a [Backend].
    pub health_changed_callback: Option<HealthObserveCallback>,
    /// An optional callback for backend summary reporting.
    pub backend_summary_callback: Option<BackendSummary>,
}

impl HttpHealthCheck {
    /// Create a new [HttpHealthCheck] with the following default settings
    /// * connect timeout: 1 second
    /// * read timeout: 1 second
    /// * req: a GET to the `/` of the given host name
    /// * consecutive_success: 1
    /// * consecutive_failure: 1
    /// * reuse_connection: false
    /// * validator: `None`, any 200 response is considered successful
    pub fn new(host: &str, tls: bool) -> Self {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("Host", host).unwrap();
        let sni = if tls { host.into() } else { String::new() };
        let mut peer_template = HttpPeer::new("0.0.0.0:1", tls, sni);
        peer_template.options.connection_timeout = Some(Duration::from_secs(1));
        peer_template.options.read_timeout = Some(Duration::from_secs(1));
        HttpHealthCheck {
            consecutive_success: 1,
            consecutive_failure: 1,
            peer_template,
            connector: HttpConnector::new(None),
            reuse_connection: false,
            req,
            validator: None,
            port_override: None,
            health_changed_callback: None,
            backend_summary_callback: None,
        }
    }

    /// Replace the internal http connector with the given [HttpConnector]
    pub fn set_connector(&mut self, connector: HttpConnector) {
        self.connector = connector;
    }

    pub fn set_backend_summary<F>(&mut self, callback: F)
    where
        F: Fn(&Backend) -> String + Send + Sync + 'static,
    {
        self.backend_summary_callback = Some(Box::new(callback));
    }
}

#[async_trait]
impl HealthCheck for HttpHealthCheck {
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }

    async fn check(&self, target: &Backend) -> Result<()> {
        let mut peer = self.peer_template.clone();
        peer._address = target.addr.clone();
        if let Some(port) = self.port_override {
            peer._address.set_port(port);
        }
        let session = self.connector.get_http_session(&peer).await?;

        let mut session = session.0;
        let req = Box::new(self.req.clone());
        session.write_request_header(req).await?;
        session.finish_request_body().await?;

        if let Some(read_timeout) = peer.options.read_timeout {
            session.set_read_timeout(Some(read_timeout));
        }

        session.read_response_header().await?;

        let resp = session.response_header().expect("just read");

        if let Some(validator) = self.validator.as_ref() {
            validator(resp)?;
        } else if resp.status != 200 {
            return Error::e_explain(
                CustomCode("non 200 code", resp.status.as_u16()),
                "during http healthcheck",
            );
        };

        while session.read_response_body().await?.is_some() {
            // drain the body if any
        }

        if self.reuse_connection {
            let idle_timeout = peer.idle_timeout();
            self.connector
                .release_http_session(session, &peer, idle_timeout)
                .await;
        }

        Ok(())
    }
    async fn health_status_change(&self, target: &Backend, healthy: bool) {
        if let Some(callback) = &self.health_changed_callback {
            callback.observe(target, healthy).await;
        }
    }
    fn backend_summary(&self, target: &Backend) -> String {
        if let Some(callback) = &self.backend_summary_callback {
            callback(target)
        } else {
            format!("{target:?}")
        }
    }
    fn supports_protocol(&self, protocol: BackendProtocol) -> bool {
        matches!(protocol, BackendProtocol::Tcp)
    }
}

#[derive(Clone)]
struct HealthInner {
    /// Whether the endpoint is healthy to serve traffic
    healthy: bool,
    /// Whether the endpoint is allowed to serve traffic independent of its health
    enabled: bool,
    /// The counter for stateful transition between healthy and unhealthy.
    /// When [healthy] is true, this counts the number of consecutive health check failures
    /// so that the caller can flip the healthy when a certain threshold is met, and vise versa.
    consecutive_counter: usize,
}

/// Health of backends that can be updated atomically
pub(crate) struct Health(ArcSwap<HealthInner>);

impl Default for Health {
    fn default() -> Self {
        Health(ArcSwap::new(Arc::new(HealthInner {
            healthy: true, // TODO: allow to start with unhealthy
            enabled: true,
            consecutive_counter: 0,
        })))
    }
}

impl Clone for Health {
    fn clone(&self) -> Self {
        let inner = self.0.load_full();
        Health(ArcSwap::new(inner))
    }
}

impl Health {
    pub fn ready(&self) -> bool {
        let h = self.0.load();
        h.healthy && h.enabled
    }

    pub fn enable(&self, enabled: bool) {
        let h = self.0.load();
        if h.enabled != enabled {
            // clone the inner
            let mut new_health = (**h).clone();
            new_health.enabled = enabled;
            self.0.store(Arc::new(new_health));
        };
    }

    // return true when the health is flipped
    pub fn observe_health(&self, health: bool, flip_threshold: usize) -> bool {
        let h = self.0.load();
        let mut flipped = false;
        if h.healthy != health {
            // opposite health observed, ready to increase the counter
            // clone the inner
            let mut new_health = (**h).clone();
            new_health.consecutive_counter += 1;
            if new_health.consecutive_counter >= flip_threshold {
                new_health.healthy = health;
                new_health.consecutive_counter = 0;
                flipped = true;
            }
            self.0.store(Arc::new(new_health));
        } else if h.consecutive_counter > 0 {
            // observing the same health as the current state.
            // reset the counter, if it is non-zero, because it is no longer consecutive
            let mut new_health = (**h).clone();
            new_health.consecutive_counter = 0;
            self.0.store(Arc::new(new_health));
        }
        flipped
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::atomic::{AtomicU16, Ordering},
    };

    use super::*;
    use crate::{discovery, BackendProtocol, Backends};
    use async_trait::async_trait;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[allow(dead_code)]
    fn network_tests_enabled() -> bool {
        matches!(
            std::env::var("PINGORA_RUN_NETWORK_TESTS"),
            Ok(val) if val == "1"
        )
    }

    #[tokio::test]
    async fn test_tcp_check() {
        let tcp_check = TcpHealthCheck::default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let backend = Backend::from_std_socket(addr, 1, BackendProtocol::Tcp);

        assert!(tcp_check.check(&backend).await.is_ok());
        accept.await.unwrap();

        let unused_addr = {
            let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tmp.local_addr().unwrap();
            drop(tmp);
            addr
        };
        let backend = Backend::from_std_socket(unused_addr, 1, BackendProtocol::Tcp);

        assert!(tcp_check.check(&backend).await.is_err());
    }

    #[cfg(feature = "any_tls")]
    #[tokio::test]
    async fn test_tls_check() {
        if !network_tests_enabled() {
            return;
        }
        let tls_check = TcpHealthCheck::new_tls("one.one.one.one");
        let backend =
            Backend::from_std_socket("1.1.1.1:443".parse().unwrap(), 1, BackendProtocol::Tcp);

        assert!(tls_check.check(&backend).await.is_ok());
    }

    #[cfg(feature = "any_tls")]
    #[tokio::test]
    async fn test_https_check() {
        if !network_tests_enabled() {
            return;
        }
        let https_check = HttpHealthCheck::new("one.one.one.one", true);

        let backend =
            Backend::from_std_socket("1.1.1.1:443".parse().unwrap(), 1, BackendProtocol::Tcp);

        assert!(https_check.check(&backend).await.is_ok());
    }

    #[tokio::test]
    async fn test_http_custom_check() {
        let mut http_check = HttpHealthCheck::new("localhost", false);
        http_check.validator = Some(Box::new(|resp: &ResponseHeader| {
            if resp.status == 301 {
                Ok(())
            } else {
                Error::e_explain(
                    CustomCode("non 301 code", resp.status.as_u16()),
                    "during http healthcheck",
                )
            }
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf).await.unwrap();
                stream
                    .write_all(b"HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            }
        });

        let backend = Backend::from_std_socket(addr, 1, BackendProtocol::Tcp);

        http_check.check(&backend).await.unwrap();

        assert!(http_check.check(&backend).await.is_ok());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_check() {
        let responder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = responder.local_addr().unwrap();
        let response = b"pong".to_vec();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 32];
            let (len, peer) = responder.recv_from(&mut buf).await.unwrap();
            if &buf[..len] == b"ping" {
                responder.send_to(&response, peer).await.unwrap();
            }
        });

        let udp_check = UdpHealthCheck {
            payload: b"ping".to_vec(),
            expected_response: Some(b"pong".to_vec()),
            ..Default::default()
        };

        let backend = Backend::from_std_socket(addr, 1, BackendProtocol::Udp);
        udp_check.check(&backend).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_health_observe() {
        struct Observe {
            unhealthy_count: Arc<AtomicU16>,
        }
        #[async_trait]
        impl HealthObserve for Observe {
            async fn observe(&self, _target: &Backend, healthy: bool) {
                if !healthy {
                    self.unhealthy_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let good_backend = Backend::new("127.0.0.1:79").unwrap();
        let new_good_backends = || -> (BTreeSet<Backend>, HashMap<u64, bool>) {
            let mut healthy = HashMap::new();
            healthy.insert(good_backend.hash_key(), true);
            let mut backends = BTreeSet::new();
            backends.extend(vec![good_backend.clone()]);
            (backends, healthy)
        };
        // tcp health check
        {
            let unhealthy_count = Arc::new(AtomicU16::new(0));
            let ob = Observe {
                unhealthy_count: unhealthy_count.clone(),
            };
            let bob = Box::new(ob);
            let tcp_check = TcpHealthCheck {
                health_changed_callback: Some(bob),
                ..Default::default()
            };

            let discovery = discovery::Static::default();
            let mut backends = Backends::new(Box::new(discovery));
            backends.set_health_check(Box::new(tcp_check));
            let result = new_good_backends();
            backends.do_update(result.0, result.1, |_backend: Arc<BTreeSet<Backend>>| {});
            // the backend is ready
            assert!(backends.ready(&good_backend));

            // run health check
            backends.run_health_check(false).await;
            assert!(1 == unhealthy_count.load(Ordering::Relaxed));
            // backend is unhealthy
            assert!(!backends.ready(&good_backend));
        }

        // http health check
        {
            let unhealthy_count = Arc::new(AtomicU16::new(0));
            let ob = Observe {
                unhealthy_count: unhealthy_count.clone(),
            };
            let bob = Box::new(ob);

            let mut https_check = HttpHealthCheck::new("one.one.one.one", true);
            https_check.health_changed_callback = Some(bob);

            let discovery = discovery::Static::default();
            let mut backends = Backends::new(Box::new(discovery));
            backends.set_health_check(Box::new(https_check));
            let result = new_good_backends();
            backends.do_update(result.0, result.1, |_backend: Arc<BTreeSet<Backend>>| {});
            // the backend is ready
            assert!(backends.ready(&good_backend));
            // run health check
            backends.run_health_check(false).await;
            assert!(1 == unhealthy_count.load(Ordering::Relaxed));
            assert!(!backends.ready(&good_backend));
        }
    }
}
