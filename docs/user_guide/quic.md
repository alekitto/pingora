# HTTP/3 and QUIC services

Pingora ships two complementary QUIC building blocks powered by
[`quiche`](https://github.com/cloudflare/quiche):

* the **HTTP/3 service**, which terminates QUIC handshakes, upgrades them to
  HTTP/3 sessions, and dispatches them to an [`HttpServerApp`] implementation;
* the **generic QUIC service**, which accepts QUIC connections, picks an
  upstream through the load balancer, and forwards packets on behalf of the
  selected backend.

This guide walks through feature flags, certificate requirements, listener and
backend configuration, and the fallback story for HTTP/1.1 / HTTP/2 clients.

## Prerequisites and feature flags

* Compile the workspace with the `quic` feature to pull in `quiche` support for
  both `pingora-core` and `pingora-proxy`.
* To run examples or the proxy helpers alongside QUIC, enable the `lb` feature
  (for load balancing) and whichever TLS backend you rely on (`rustls`,
  `boringssl`, or `openssl_derived`).
* QUIC listeners require TLS 1.3 certificates and private keys encoded as PEM
  files. Provide the full certificate chain your clients expect.

The `quic_lb` example can be launched with the required features enabled:

```bash
cargo run -p pingora --example quic_lb --features "lb quic" -- \
    --listen 0.0.0.0:4433 \
    --backend quic://10.0.0.10:4433 --backend quic://10.0.0.11:4433
```

## Configuring HTTP/3 listeners

An HTTP/3 listener is backed by an `Http3Service` and one or more UDP
endpoints. Build a `ServerConfig` with `TransportConfigBuilder`, load the PEM
certificate and key, advertise the `h3` ALPN token, and enable datagram support
if your application depends on it:

```rust
use pingora_core::protocols::quic::TransportConfigBuilder;

let mut builder = TransportConfigBuilder::new()?;
builder = builder
    .load_cert_chain_from_pem_file(cert_path)?
    .load_priv_key_from_pem_file(key_path)?
    .verify_peer(false);
let builder = builder
    .application_protos(&[b"h3"])?;
let server_config = builder.build_server()?;
server_config
    .transport()
    .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32))?;

let mut service = Http3Service::new("http3 frontend", "0.0.0.0:443", server_config, app);
service.set_alpn_h3()?;
```

Existing listening services created through `Service::with_listeners` can attach
an HTTP/3 endpoint via `add_http3_endpoint`, letting the same application logic
handle HTTP/1.x, HTTP/2, and HTTP/3 side-by-side.

## Configuring QUIC backends

The generic `QuicService` integrates with `LoadBalancer::select_with_protocol`
to pick an upstream endpoint for each QUIC connection. Declare QUIC backends
with the `quic://` URI prefix; they accept the same weight and metadata options
as TCP backends:

```rust
use pingora_load_balancing::{Backend, LoadBalancer};
use pingora_load_balancing::selection::RoundRobin;
use pingora_core::services::quic::{QuicBackendSelector, QuicService};

let backends = vec![Backend::new_quic("quic://127.0.0.1:9443")?];
let lb = LoadBalancer::<RoundRobin>::try_from_iter(backends)?;
let selector = std::sync::Arc::new(lb) as std::sync::Arc<dyn QuicBackendSelector>;

let mut service = QuicService::new("quic-forwarder", "0.0.0.0:4433", server_config, selector);
service.set_max_backend_iterations(8);
```

You can tune queue limits and UDP socket options to align with your expected
traffic profile.

## Fallback behaviour

Clients that cannot complete a QUIC handshake (for example because of blocked
UDP ports) should automatically fall back to your HTTP/1.1 or HTTP/2 endpoints.
Keep TCP listeners configured on the same service and make sure TLS ALPN
advertises the right combinations. When selecting upstreams through the
load-balancer, call `LoadBalancer::select_with_protocol` to attempt a QUIC pick
first, then fall back to `BackendProtocol::Tcp` if no healthy QUIC backend is
available. Integration tests under `pingora-core/tests/http3_service.rs` and
`pingora-proxy/tests/test_http3.rs` illustrate the handshake path and the
fallback to HTTP/1.1 once UDP is unavailable.

## Health checks

Built-in checkers do not yet support native QUIC probes. A health check invoked
against a QUIC backend returns the `quic_health_check_unavailable` error. Use an
external monitoring system to update backend state or run lightweight TCP
checks against the same pool to keep lifecycle management aligned.

## Migration notes

Earlier releases only exposed an L4 QUIC forwarder. Upgrading to the HTTP/3
service requires a few configuration changes:

* Update listener definitions to add `Http3Service` or call
  `Service::add_http3_endpoint` alongside your existing TCP/TLS endpoints.
* Provide full TLS 1.3 certificate chains. QUIC handshakes fail fast when
  intermediate certificates are missing.
* Ensure the `h3` ALPN token is advertised from both the QUIC listener and any
  alternative TCP/TLS endpoints that should offer HTTP/3 via Alt-Svc.
* Review firewall policies: the HTTP/3 listener binds a UDP socket and requires
  bidirectional UDP reachability in addition to any TCP listeners used for
  fallback.
* CI should execute the QUIC-aware tests (`cargo test --features quic`)
  whenever new code paths are introduced, because `quiche` pulls in additional
  native dependencies.

The existing L4 service and the new HTTP/3 listener can run side-by-side. Use
them in tandem while migrating traffic or to keep bespoke QUIC backends
available for specialised workloads.
