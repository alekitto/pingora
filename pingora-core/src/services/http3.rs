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

//! HTTP/3 service scaffolding.
//!
//! This module wires the server runtime with a UDP listener that is expected to
//! terminate QUIC connections and dispatch HTTP/3 sessions to an
//! [`HttpServerApp`]. The current logic intentionally keeps the QUIC and
//! HTTP/3 state machines minimal; follow-up patches will flesh out the
//! protocol-specific behaviour.

#![cfg(feature = "quic")]

use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, error, info, warn};
use pingora_runtime::current_handle;
use tokio::time::{sleep, Duration};

use crate::apps::HttpServerApp;
use crate::listeners::{
    ListenerEndpoint, ListenerEndpointBuilder, ServerAddress, UdpSocketOptions,
};
use crate::protocols::http::v3::server::HttpSession;
use crate::protocols::http::ServerSession;
use crate::protocols::quic::{Endpoint, ServerConfig};
use crate::protocols::Digest;
use crate::server::{ListenFds, ShutdownWatch};
use crate::services::Service as ServiceTrait;

/// Default number of worker send attempts when flushing handshake datagrams.
const DEFAULT_MAX_SEND_QUEUE: usize = 8;

#[cfg(unix)]
type EndpointFds = Option<ListenFds>;
#[cfg(not(unix))]
type EndpointFds = ();

/// Configuration for a single HTTP/3 listener endpoint.
#[derive(Clone)]
pub struct Http3Endpoint {
    listen_addr: String,
    udp_options: Option<UdpSocketOptions>,
    server_config: ServerConfig,
    send_queue_limit: usize,
}

impl Http3Endpoint {
    /// Create a new HTTP/3 endpoint bound to the provided address.
    pub fn new(listen_addr: impl Into<String>, server_config: ServerConfig) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            udp_options: None,
            server_config,
            send_queue_limit: DEFAULT_MAX_SEND_QUEUE,
        }
    }

    /// Override the UDP socket options used when binding the listener.
    pub fn set_udp_socket_options(&mut self, options: UdpSocketOptions) {
        self.udp_options = Some(options);
    }

    /// Configure the maximum number of received datagrams processed per wake up
    /// and the maximum number of datagrams flushed back to the client.
    pub fn set_queue_capacities(&mut self, _recv: usize, send: usize) {
        self.send_queue_limit = send.max(1);
    }

    /// Update the advertised ALPN protocol list on the shared server configuration
    /// to include the HTTP/3 token.
    pub fn set_alpn_h3(&self) -> Result<(), crate::protocols::quic::ConfigError> {
        self.server_config
            .transport()
            .with_config_mut(|cfg| cfg.set_application_protos(&[b"h3"]))?;
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

    fn server_config(&self) -> ServerConfig {
        self.server_config.clone()
    }

    fn send_queue_limit(&self) -> usize {
        self.send_queue_limit
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn spawn_workers<A>(
        &self,
        runtime: &tokio::runtime::Handle,
        #[cfg_attr(not(unix), allow(unused_variables))] fds: EndpointFds,
        shutdown: ShutdownWatch,
        listeners_per_fd: usize,
        app: Arc<A>,
        service_name: &str,
    ) -> Vec<tokio::task::JoinHandle<()>>
    where
        A: HttpServerApp + Send + Sync + 'static,
    {
        let listener = {
            let mut builder = self.builder();
            #[cfg(unix)]
            let endpoint = builder
                .listen(fds)
                .await
                .expect("Failed to bind HTTP/3 listener");
            #[cfg(not(unix))]
            let endpoint = builder
                .listen()
                .await
                .expect("Failed to bind HTTP/3 listener");
            endpoint
        };

        let mut tasks = Vec::with_capacity(listeners_per_fd);

        for worker_id in 0..listeners_per_fd {
            let shutdown = shutdown.clone();
            let config = self.server_config();
            let app = Arc::clone(&app);
            let send_limit = self.send_queue_limit();
            let listener = listener.clone();
            let name = service_name.to_string();

            let handle = runtime.spawn(async move {
                let Some(socket) = listener.udp_socket() else {
                    error!(
                        "HTTP/3 service `{}` worker {} started without UDP listener",
                        name, worker_id
                    );
                    return;
                };

                let endpoint = match Endpoint::from_arc(socket) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        error!(
                            "HTTP/3 service `{}` worker {} failed to wrap UDP endpoint: {}",
                            name, worker_id, err
                        );
                        return;
                    }
                };

                let mut worker = Http3Worker::new(config, app, send_limit);
                worker.run(endpoint, shutdown).await;
            });

            tasks.push(handle);
        }

        tasks
    }
}

/// HTTP/3 service that binds a UDP listener and dispatches placeholder
/// `HttpSession`s into the provided [`HttpServerApp`].
pub struct Http3Service<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    name: String,
    endpoints: Vec<Http3Endpoint>,
    app: Arc<A>,
    threads: Option<usize>,
}

impl<A> Http3Service<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    /// Create a new [`Http3Service`] listening on the provided UDP address.
    pub fn new(
        name: impl Into<String>,
        listen_addr: impl Into<String>,
        server_config: ServerConfig,
        app: Arc<A>,
    ) -> Self {
        Self {
            name: name.into(),
            endpoints: vec![Http3Endpoint::new(listen_addr, server_config)],
            app,
            threads: None,
        }
    }

    /// Override the UDP socket options used when binding the listener.
    pub fn set_udp_socket_options(&mut self, options: UdpSocketOptions) {
        self.primary_endpoint_mut().set_udp_socket_options(options);
    }

    /// Configure the maximum number of received datagrams processed per wake up
    /// and the maximum number of datagrams flushed back to the client.
    pub fn set_queue_capacities(&mut self, _recv: usize, send: usize) {
        self.primary_endpoint_mut()
            .set_queue_capacities(_recv, send);
    }

    /// Override the preferred number of runtime threads for this service.
    pub fn set_threads(&mut self, threads: Option<usize>) {
        self.threads = threads;
    }

    /// Update the advertised ALPN protocol list on the shared server configuration.
    pub fn set_alpn_h3(&self) -> Result<(), crate::protocols::quic::ConfigError> {
        self.primary_endpoint().set_alpn_h3()
    }

    /// Add an additional HTTP/3 endpoint to this service and return a mutable
    /// handle for further configuration.
    pub fn add_endpoint(
        &mut self,
        listen_addr: impl Into<String>,
        server_config: ServerConfig,
    ) -> &mut Http3Endpoint {
        self.endpoints
            .push(Http3Endpoint::new(listen_addr, server_config));
        self.endpoints
            .last_mut()
            .expect("just pushed an HTTP/3 endpoint")
    }

    fn primary_endpoint(&self) -> &Http3Endpoint {
        self.endpoints
            .first()
            .expect("HTTP/3 service must have at least one endpoint configured")
    }

    fn primary_endpoint_mut(&mut self) -> &mut Http3Endpoint {
        self.endpoints
            .first_mut()
            .expect("HTTP/3 service must have at least one endpoint configured")
    }
}

#[async_trait]
impl<A> ServiceTrait for Http3Service<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    async fn start_service(
        &mut self,
        #[cfg(unix)] fds: Option<ListenFds>,
        shutdown: ShutdownWatch,
        listeners_per_fd: usize,
    ) {
        let runtime = current_handle();
        #[cfg(unix)]
        let http3_fds: EndpointFds = fds.clone();
        #[cfg(not(unix))]
        let http3_fds: EndpointFds = ();

        let mut tasks = Vec::new();

        for endpoint in &self.endpoints {
            let mut endpoint_tasks = endpoint
                .spawn_workers(
                    &runtime,
                    http3_fds.clone(),
                    shutdown.clone(),
                    listeners_per_fd,
                    Arc::clone(&self.app),
                    &self.name,
                )
                .await;
            tasks.append(&mut endpoint_tasks);
        }

        for task in tasks {
            if let Err(err) = task.await {
                warn!("HTTP/3 worker task terminated: {err}");
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn threads(&self) -> Option<usize> {
        self.threads
    }
}

pub(crate) struct Http3Worker<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    server_config: ServerConfig,
    app: Arc<A>,
    send_queue_limit: usize,
}

impl<A> Http3Worker<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    fn new(server_config: ServerConfig, app: Arc<A>, send_queue_limit: usize) -> Self {
        Self {
            server_config,
            app,
            send_queue_limit,
        }
    }

    async fn run(&mut self, endpoint: Endpoint, mut shutdown: ShutdownWatch) {
        let mut backoff = Duration::from_millis(1);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("HTTP/3 service worker shutting down");
                        break;
                    }
                }
                result = endpoint.recv() => {
                    match result {
                        Ok(datagram) => {
                            backoff = Duration::from_millis(1);
                            self.handle_datagram(&endpoint, datagram, shutdown.clone()).await;
                        }
                        Err(err) => {
                            warn!("UDP receive error: {err}");
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(1));
                        }
                    }
                }
            }
        }
    }

    async fn handle_datagram(
        &self,
        endpoint: &Endpoint,
        mut datagram: crate::protocols::quic::Datagram,
        mut shutdown: ShutdownWatch,
    ) {
        if datagram.payload().is_empty() {
            return;
        }

        let header =
            match quiche::Header::from_slice(datagram.payload_mut(), quiche::MAX_CONN_ID_LEN) {
                Ok(header) => header,
                Err(err) => {
                    debug!("Failed to parse QUIC header: {err}");
                    return;
                }
            };

        if header.ty != quiche::Type::Initial {
            // Future revisions will drive the full state machine and deliver
            // datagrams to the existing connections. Right now the worker only
            // reacts to the initial flight so the remainder of the service can
            // be wired up without yet implementing full QUIC handling.
            return;
        }

        let scid = quiche::ConnectionId::from_ref(header.dcid.as_ref());
        let odcid = Some(quiche::ConnectionId::from_ref(header.scid.as_ref()));

        let mut transport = match self.server_config.accept(
            &scid,
            odcid.as_ref(),
            datagram.recv_info().to,
            datagram.recv_info().from,
        ) {
            Ok(conn) => conn,
            Err(err) => {
                debug!("Failed to accept QUIC connection: {err}");
                return;
            }
        };

        if let Err(err) = transport.recv(&mut datagram) {
            debug!("Failed to process QUIC datagram: {err}");
            return;
        }

        self.flush_pending_datagrams(endpoint, &mut transport).await;

        let h3_config = match quiche::h3::Config::new() {
            Ok(cfg) => cfg,
            Err(err) => {
                warn!("Failed to create HTTP/3 config: {err}");
                return;
            }
        };

        let h3_conn =
            match quiche::h3::Connection::with_transport(transport.inner_mut(), &h3_config) {
                Ok(conn) => conn,
                Err(err) => {
                    warn!("Failed to create HTTP/3 connection: {err}");
                    return;
                }
            };

        self.flush_pending_datagrams(endpoint, &mut transport).await;

        // Create a placeholder HTTP/3 session and hand it to the application.
        let digest = Arc::new(Digest::default());
        let session = HttpSession::placeholder(transport, h3_conn, digest);
        let app = Arc::clone(&self.app);

        current_handle().spawn(async move {
            let _ = app
                .process_new_http(ServerSession::new_http3(session), &shutdown)
                .await;
        });
    }
}

impl<A> Http3Worker<A>
where
    A: HttpServerApp + Send + Sync + 'static,
{
    async fn flush_pending_datagrams(
        &self,
        endpoint: &Endpoint,
        transport: &mut crate::protocols::quic::Connection,
    ) {
        for _ in 0..self.send_queue_limit {
            match transport.send() {
                Ok(datagram) => {
                    if let Err(err) = endpoint.send(&datagram).await {
                        warn!("Failed to send QUIC datagram: {err}");
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    warn!("quiche send error: {err}");
                    break;
                }
            }
        }
    }
}
