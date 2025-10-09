# QUIC service

Pingora's QUIC service offers a UDP listener built on top of [`quiche`](https://github.com/cloudflare/quiche) that terminates
incoming connections and forwards them to a backend selected through the `LoadBalancer`. This guide walks through prerequisites,
certificate and listener configuration, and the operational limits to keep in mind.

## Prerequisites and feature flags

* Support is available only when compiling with the `quic` feature, which links `quiche` into both `pingora-core` and
  `pingora-load-balancing`.
* To use the load balancer recipes enable the `lb` feature as well when running examples or binaries.
* The listener requires TLS 1.3 certificates in PEM format.

Example command to run the example binary with both features enabled:

```bash
cargo run -p pingora --example quic_lb --features "lb quic"
```

## Transport and certificate configuration

Building a `ServerConfig` from `TransportConfigBuilder` lets you load a PEM certificate and private key and declare the ALPN
protocols announced to clients. After creation you can explicitly enable QUIC datagram support:

```rust
use pingora_core::protocols::quic::TransportConfigBuilder;

let mut builder = TransportConfigBuilder::new()?;
builder = builder
    .load_cert_chain_from_pem_file(cert_path)?
    .load_priv_key_from_pem_file(key_path)?
    .application_protos(&[b"h3"])?
    .verify_peer(false);
let server_config = builder.build_server()?;
server_config
    .transport()
    .with_config_mut(|cfg| cfg.enable_dgram(true, 32, 32))?;
```

Use the same approach for client configuration in tests or QUIC connectors. The keys must match what backends present and the
security requirements of your environment.

## LoadBalancer integration

`LoadBalancer` implements the `QuicBackendSelector` trait, so you can pass it directly into the service constructor. QUIC
backends are declared with the `quic://` prefix and keep the same properties (weight, metadata) as other supported protocols.

```rust
use pingora_load_balancing::{Backend, LoadBalancer};
use pingora_load_balancing::selection::RoundRobin;
use pingora_core::services::quic::QuicService;

let backends = vec![Backend::new_quic("quic://127.0.0.1:9443")?];
let lb = LoadBalancer::<RoundRobin>::try_from_iter(backends)?;
let selector = std::sync::Arc::new(lb) as std::sync::Arc<dyn QuicBackendSelector>;

let mut service = QuicService::new("QUIC LB", listen_addr, server_config, selector);
service.set_max_backend_iterations(8);
```

You can customize UDP socket options and receive/transmit queue limits to align with the expected load.

## Full example

The `quic_lb` example shows how to start a Pingora server that listens on QUIC, populates a round-robin load balancer, and wires
the backend selection into the service. The default certificate and key reuse the test material included in the repository and
can be overridden at the command line.

```bash
cargo run -p pingora --example quic_lb \
    --features "lb quic" \
    -- --listen 0.0.0.0:4433 \
    --backend quic://10.0.0.10:4433 --backend quic://10.0.0.11:4433
```

## Health checks and fallback

Built-in checkers do not yet support native QUIC probes: running a health check on a QUIC backend returns the
`quic_health_check_unavailable` error. You can:

* Delegate monitoring to an external system (for example Prometheus or an orchestrator) that updates backend state through
  dynamic discovery.
* Run lightweight UDP/TCP reachability checks against the same hosts to keep lifecycle management aligned.

When a QUIC backend becomes unavailable you can call `LoadBalancer::select_with_protocol` to fall back to existing TCP endpoints
(HTTP/1.1 or HTTP/2), or instruct the application to degrade traffic toward a traditional HTTP service while preserving client
tracking.

## Known limitations

* The service terminates QUIC transport and delegates application logic (HTTP/3, gRPC, etc.) to the selected backend; there is
  no direct integration with Pingora's built-in HTTP handlers yet.
* First-party QUIC health checks are not available.
* Configuration requires PEM-formatted TLS certificates readable from disk.
* Enabling the `quic` feature pulls in the `quiche` crate, which may require a compatible C toolchain on the build system.
