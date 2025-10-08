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

//! QUIC datagram service that terminates connections using `quiche` and
//! integrates with Pingora's load balancer selection logic.
//!
//! The service binds to a UDP listener endpoint, accepts incoming QUIC
//! handshakes, and keeps track of connection state required for handling
//! retransmissions, handshake packets and 0-RTT traffic. Each QUIC
//! connection is mapped to a backend selected with
//! [`LoadBalancer::select_with_protocol`], allowing future packets that
//! share the same connection identifier to reuse the backend decision.

#![cfg(feature = "quic")]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::future::{join_all, pending};
use log::{debug, error, info, trace, warn};
use pingora_runtime::current_handle;
use pingora_timeout::fast_timeout::fast_sleep;

use crate::listeners::{
    ListenerEndpoint, ListenerEndpointBuilder, ServerAddress, UdpSocketOptions,
};
use crate::protocols::quic::{Connection, Datagram, Endpoint, ServerConfig, MAX_DATAGRAM_SIZE};
use crate::protocols::Shutdown;
use crate::server::{ListenFds, ShutdownWatch};
use crate::services::Service as ServiceTrait;

use std::net::SocketAddr;

/// Default number of backend selection attempts before giving up.
const DEFAULT_MAX_BACKEND_ITERATIONS: usize = 16;
/// Default number of outgoing datagrams flushed per iteration.
const DEFAULT_MAX_SEND_QUEUE: usize = 32;
/// Default number of incoming datagrams processed per wake up.
const DEFAULT_MAX_RECV_QUEUE: usize = 32;

/// Minimal backend information required by the QUIC service.
#[derive(Clone, Debug)]
pub struct SelectedBackend {
    /// The resolved socket address of the backend server.
    pub address: SocketAddr,
}

/// Trait abstracting backend selection for QUIC traffic.
pub trait QuicBackendSelector: Send + Sync {
    /// Pick a backend for the given selection key.
    fn select_quic_backend(&self, key: &[u8], max_iterations: usize) -> Option<SelectedBackend>;
}

/// QUIC service that accepts downstream connections and maps them to upstream
/// backends selected through Pingora's load balancer infrastructure.
pub struct QuicService {
    name: String,
    listen_addr: String,
    udp_options: Option<UdpSocketOptions>,
    server_config: ServerConfig,
    selector: Arc<dyn QuicBackendSelector>,
    recv_queue_limit: usize,
    send_queue_limit: usize,
    max_backend_iterations: usize,
    threads: Option<usize>,
}

impl QuicService {
    /// Create a new [`QuicService`] listening on the provided UDP address.
    pub fn new(
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        server_config: ServerConfig,
        selector: Arc<dyn QuicBackendSelector>,
    ) -> Self {
        Self {
            name: name.into(),
            listen_addr: listen_addr.into(),
            udp_options: None,
            server_config,
            selector,
            recv_queue_limit: DEFAULT_MAX_RECV_QUEUE,
            send_queue_limit: DEFAULT_MAX_SEND_QUEUE,
            max_backend_iterations: DEFAULT_MAX_BACKEND_ITERATIONS,
            threads: None,
        }
    }

    /// Override the UDP socket options used when binding the listener.
    pub fn set_udp_socket_options(&mut self, options: UdpSocketOptions) {
        self.udp_options = Some(options);
    }

    /// Configure the maximum number of received datagrams processed per wake up
    /// and the maximum number of datagrams flushed back to the client.
    pub fn set_queue_capacities(&mut self, recv: usize, send: usize) {
        self.recv_queue_limit = recv.max(1);
        self.send_queue_limit = send.max(1);
    }

    /// Configure how many attempts the service should make when iterating over
    /// load balancer choices for a new QUIC backend selection.
    pub fn set_max_backend_iterations(&mut self, iterations: usize) {
        self.max_backend_iterations = iterations.max(1);
    }

    /// Override the preferred number of runtime threads for this service.
    pub fn set_threads(&mut self, threads: Option<usize>) {
        self.threads = threads;
    }

    /// Update the advertised ALPN protocol list on the shared server configuration.
    pub fn set_alpn_protocols(
        &self,
        protocols: &[&[u8]],
    ) -> Result<(), crate::protocols::quic::ConfigError> {
        self.server_config
            .transport()
            .with_config_mut(|cfg| cfg.set_application_protos(protocols))?;
        Ok(())
    }

    fn builder(&self) -> ListenerEndpointBuilder {
        let mut builder = ListenerEndpoint::builder();
        builder.listen_addr(ServerAddress::Udp(
            self.listen_addr.clone(),
            self.udp_options.clone(),
        ));
        builder
    }
}

#[async_trait]
impl ServiceTrait for QuicService {
    async fn start_service(
        &mut self,
        #[cfg(unix)] fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        listeners_per_fd: usize,
    ) {
        let runtime = current_handle();

        let endpoint = self
            .builder()
            .listen(
                #[cfg(unix)]
                fds,
            )
            .await
            .expect("Failed to bind QUIC listener");

        let mut tasks = Vec::with_capacity(listeners_per_fd);

        for worker_id in 0..listeners_per_fd {
            let shutdown = shutdown.clone();
            let config = self.server_config.clone();
            let selector = Arc::clone(&self.selector);
            let recv_limit = self.recv_queue_limit;
            let send_limit = self.send_queue_limit;
            let max_backend_iterations = self.max_backend_iterations;
            let listener = endpoint.clone();
            let name = self.name.clone();

            let handle = runtime.spawn(async move {
                let Some(socket) = listener.udp_socket() else {
                    error!(
                        "QUIC service `{}` worker {} started without UDP listener",
                        name, worker_id
                    );
                    return;
                };

                let endpoint = match Endpoint::from_arc(socket) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        error!(
                            "QUIC service `{}` worker {} failed to wrap UDP endpoint: {}",
                            name, worker_id, err
                        );
                        return;
                    }
                };

                let mut worker = QuicWorker::new(
                    config,
                    selector,
                    recv_limit,
                    send_limit,
                    max_backend_iterations,
                );

                worker.run(endpoint, shutdown).await;
            });

            tasks.push(handle);
        }

        join_all(tasks).await;
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        self.threads
    }
}

struct ConnectionState {
    connection: Connection,
    backend: SelectedBackend,
    timeout_at: Option<Instant>,
    aliases: Vec<Vec<u8>>,
}

impl ConnectionState {
    fn new(connection: Connection, backend: SelectedBackend) -> Self {
        Self {
            connection,
            backend,
            timeout_at: None,
            aliases: Vec::new(),
        }
    }

    fn add_alias(&mut self, alias: &[u8], canonical: &[u8]) {
        if alias == canonical {
            return;
        }

        if self
            .aliases
            .iter()
            .any(|existing| existing.as_slice() == alias)
        {
            return;
        }

        self.aliases.push(alias.to_vec());
    }

    fn refresh_server_aliases(&mut self, canonical: &[u8]) {
        let ids: Vec<Vec<u8>> = self
            .connection
            .inner()
            .source_ids()
            .map(|id| id.as_ref().to_vec())
            .collect();

        for scid in ids {
            self.add_alias(scid.as_slice(), canonical);
        }
    }
}

struct QuicEngine {
    server_config: ServerConfig,
    selector: Arc<dyn QuicBackendSelector>,
    connections: HashMap<Vec<u8>, ConnectionState>,
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    recv_queue_limit: usize,
    send_queue_limit: usize,
    max_backend_iterations: usize,
    timeout_cursor: usize,
}

impl QuicEngine {
    fn new(
        server_config: ServerConfig,
        selector: Arc<dyn QuicBackendSelector>,
        recv_queue_limit: usize,
        send_queue_limit: usize,
        max_backend_iterations: usize,
    ) -> Self {
        Self {
            server_config,
            selector,
            connections: HashMap::new(),
            aliases: HashMap::new(),
            recv_queue_limit,
            send_queue_limit,
            max_backend_iterations,
            timeout_cursor: 0,
        }
    }

    fn next_timeout_duration(&self) -> Option<Duration> {
        let now = Instant::now();
        self.connections
            .values()
            .filter_map(|state| state.timeout_at)
            .min()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    async fn process_datagram(&mut self, endpoint: &Endpoint, mut datagram: Datagram) {
        if datagram.payload().is_empty() {
            return;
        }

        let header =
            match quiche::Header::from_slice(datagram.payload_mut(), quiche::MAX_CONN_ID_LEN) {
                Ok(header) => header,
                Err(err) => {
                    warn!("Failed to parse QUIC header: {err}");
                    return;
                }
            };

        let original_conn_id = header.dcid.as_ref().to_vec();
        let mut conn_id = original_conn_id.clone();
        if !self.connections.contains_key(&conn_id) {
            if let Some(mapped) = self.aliases.get(&conn_id) {
                conn_id = mapped.clone();
            }
        }

        if let Some(mut state) = self.connections.remove(&conn_id) {
            trace!(
                "Processing datagram for existing QUIC connection id_len={}",
                conn_id.len()
            );
            match state.connection.recv(&mut datagram) {
                Ok(_) => {
                    if let Err(err) = self.flush_connection(endpoint, &mut state).await {
                        error!("Failed to send QUIC datagram: {err}");
                    }
                }
                Err(quiche::Error::Done) => {}
                Err(err) => {
                    warn!("quiche recv error: {err}");
                }
            }

            state.timeout_at = self.compute_deadline(&state.connection);

            if state.connection.is_closed() {
                self.remove_aliases(&state);
                trace!("QUIC connection closed (id_len={})", conn_id.len());
            } else {
                let canonical = state.connection.source_conn_id();
                state.refresh_server_aliases(&canonical);
                state.add_alias(&original_conn_id, &canonical);
                self.register_state(canonical, state);
            }
            return;
        }

        self.accept_new_connection(endpoint, datagram, header).await;
    }

    async fn accept_new_connection<'a>(
        &mut self,
        endpoint: &Endpoint,
        mut datagram: Datagram,
        header: quiche::Header<'a>,
    ) {
        if !quiche::version_is_supported(header.version) {
            self.send_version_negotiation(endpoint, &datagram, &header)
                .await;
            return;
        }

        if header.ty != quiche::Type::Initial {
            debug!(
                "Ignoring non-initial QUIC datagram for unknown connection: {:?}",
                header.ty
            );
            return;
        }

        let backend = match self.select_backend(header.dcid.as_ref()) {
            Some(backend) => backend,
            None => {
                warn!("No healthy QUIC backend available for incoming connection");
                return;
            }
        };

        let recv_info = datagram.recv_info().clone();
        let scid = quiche::ConnectionId::from_ref(header.dcid.as_ref());

        let connection = match self
            .server_config
            .accept(&scid, None, recv_info.to, recv_info.from)
        {
            Ok(conn) => conn,
            Err(err) => {
                error!("Failed to accept QUIC connection: {err}");
                return;
            }
        };

        let mut state = ConnectionState::new(connection, backend);

        match state.connection.recv(&mut datagram) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(err) => {
                warn!("Error processing initial QUIC datagram: {err}");
            }
        }

        if let Err(err) = self.flush_connection(endpoint, &mut state).await {
            error!("Failed to send QUIC handshake datagram: {err}");
        }

        state.timeout_at = self.compute_deadline(&state.connection);

        let canonical = state.connection.source_conn_id();
        state.refresh_server_aliases(&canonical);
        state.add_alias(header.dcid.as_ref(), &canonical);

        if state.connection.is_closed() {
            self.remove_aliases(&state);
            return;
        }

        let backend_addr = state.backend.address;
        self.register_state(canonical, state);
        info!(
            "Accepted new QUIC connection targeting backend {}",
            backend_addr
        );
    }

    fn select_backend(&self, key: &[u8]) -> Option<SelectedBackend> {
        self.selector
            .select_quic_backend(key, self.max_backend_iterations)
    }

    fn compute_deadline(&self, connection: &Connection) -> Option<Instant> {
        connection
            .timeout()
            .map(|duration| Instant::now() + duration)
    }

    async fn flush_connection(
        &self,
        endpoint: &Endpoint,
        state: &mut ConnectionState,
    ) -> std::io::Result<()> {
        for _ in 0..self.send_queue_limit {
            match state.connection.send() {
                Ok(datagram) => {
                    trace!("Sending QUIC datagram to client");
                    endpoint.send(&datagram).await?;
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    warn!("quiche send error: {err}");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_timeouts(&mut self, endpoint: &Endpoint) {
        let keys: Vec<Vec<u8>> = self.connections.keys().cloned().collect();
        if keys.is_empty() {
            return;
        }

        self.timeout_cursor %= keys.len();

        let limit = self.recv_queue_limit.max(1).min(keys.len());

        for offset in 0..limit {
            let idx = (self.timeout_cursor + offset) % keys.len();
            let key = keys[idx].clone();
            let Some(mut state) = self.connections.remove(&key) else {
                continue;
            };

            let Some(deadline) = state.timeout_at else {
                let canonical = state.connection.source_conn_id();
                state.refresh_server_aliases(&canonical);
                self.register_state(canonical, state);
                continue;
            };

            if deadline > Instant::now() {
                let canonical = state.connection.source_conn_id();
                state.refresh_server_aliases(&canonical);
                self.register_state(canonical, state);
                continue;
            }

            state.connection.on_timeout();
            state.timeout_at = self.compute_deadline(&state.connection);

            if let Err(err) = self.flush_connection(endpoint, &mut state).await {
                error!("Failed to send timeout datagram: {err}");
            }

            if state.connection.is_closed() {
                self.remove_aliases(&state);
            } else {
                let canonical = state.connection.source_conn_id();
                state.refresh_server_aliases(&canonical);
                state.add_alias(&key, &canonical);
                self.register_state(canonical, state);
            }
        }

        self.timeout_cursor = (self.timeout_cursor + limit) % self.connections.len().max(1);
    }

    async fn shutdown_all(&mut self, endpoint: &Endpoint) {
        let mut states: Vec<_> = self.connections.drain().collect();
        for (_, mut state) in states.drain(..) {
            state.connection.shutdown().await;
            if let Err(err) = self.flush_connection(endpoint, &mut state).await {
                error!("Failed to flush shutdown datagram: {err}");
            }
            self.remove_aliases(&state);
        }
    }

    fn register_state(&mut self, canonical: Vec<u8>, state: ConnectionState) {
        let aliases = state.aliases.clone();
        for alias in &aliases {
            if alias != &canonical {
                self.aliases.insert(alias.clone(), canonical.clone());
            }
        }
        self.connections.insert(canonical, state);
    }

    fn remove_aliases(&mut self, state: &ConnectionState) {
        for alias in &state.aliases {
            self.aliases.remove(alias);
        }
    }

    async fn send_version_negotiation(
        &self,
        endpoint: &Endpoint,
        datagram: &Datagram,
        header: &quiche::Header<'_>,
    ) {
        let mut payload = [0u8; MAX_DATAGRAM_SIZE];
        let scid = quiche::ConnectionId::from_ref(header.scid.as_ref());
        let dcid = quiche::ConnectionId::from_ref(header.dcid.as_ref());
        let Ok(len) = quiche::negotiate_version(&scid, &dcid, &mut payload) else {
            return;
        };

        if let Err(err) = endpoint
            .socket()
            .send_to(&payload[..len], datagram.recv_info().from)
            .await
        {
            warn!("Failed to send QUIC version negotiation: {err}");
        }
    }
}

struct QuicWorker {
    engine: QuicEngine,
}

impl QuicWorker {
    fn new(
        server_config: ServerConfig,
        selector: Arc<dyn QuicBackendSelector>,
        recv_queue_limit: usize,
        send_queue_limit: usize,
        max_backend_iterations: usize,
    ) -> Self {
        Self {
            engine: QuicEngine::new(
                server_config,
                selector,
                recv_queue_limit,
                send_queue_limit,
                max_backend_iterations,
            ),
        }
    }

    async fn run(&mut self, endpoint: Endpoint, mut shutdown: ShutdownWatch) {
        loop {
            let timeout_future: Pin<Box<dyn Future<Output = ()> + Send>> =
                match self.engine.next_timeout_duration() {
                    Some(duration) if duration > Duration::ZERO => Box::pin(fast_sleep(duration)),
                    Some(_) => Box::pin(fast_sleep(Duration::from_millis(1))),
                    None => Box::pin(pending::<()>()),
                };

            tokio::pin!(timeout_future);

            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("QUIC service worker shutting down");
                        self.engine.shutdown_all(&endpoint).await;
                        break;
                    }
                }
                result = endpoint.recv() => {
                    match result {
                        Ok(datagram) => {
                            self.engine.process_datagram(&endpoint, datagram).await;
                        }
                        Err(err) => {
                            warn!("UDP receive error: {err}");
                        }
                    }
                }
                _ = &mut timeout_future => {
                    self.engine.handle_timeouts(&endpoint).await;
                }
            }
        }
    }
}
