use std::sync::Arc;

use clap::Parser;
use pingora::server::Server;
use pingora_core::protocols::quic::TransportConfigBuilder;
use pingora_core::services::quic::QuicBackendSelector;
use pingora_core::services::quic::QuicService;
use pingora_load_balancing::selection::RoundRobin;
use pingora_load_balancing::LoadBalancer;

const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/keys/server.crt");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/keys/key.pem");

#[derive(Parser, Debug)]
#[command(author, version, about = "Pingora QUIC load balancer", long_about = None)]
struct Args {
    /// Address to bind the QUIC listener to.
    #[arg(long, default_value = "0.0.0.0:4433")]
    listen: String,

    /// Path to the PEM encoded certificate chain served to clients.
    #[arg(long, default_value = DEFAULT_CERT)]
    cert: String,

    /// Path to the PEM encoded private key associated with the certificate chain.
    #[arg(long, default_value = DEFAULT_KEY)]
    key: String,

    /// Comma separated list of ALPN identifiers to advertise (e.g. "h3,hq-29").
    #[arg(long, default_value = "h3")]
    alpn: String,

    /// QUIC backends that should receive the traffic. Accepts multiple occurrences.
    #[arg(long = "backend", required = true)]
    backends: Vec<String>,

    /// Maximum number of attempts when iterating over the backend list.
    #[arg(long, default_value_t = 16)]
    max_backend_iterations: usize,
}

fn build_server_config(
    args: &Args,
) -> Result<pingora_core::protocols::quic::ServerConfig, Box<dyn std::error::Error>> {
    let mut builder = TransportConfigBuilder::new()?;
    builder = builder
        .load_cert_chain_from_pem_file(&args.cert)?
        .load_priv_key_from_pem_file(&args.key)?
        .verify_peer(false);

    let alpns: Vec<Vec<u8>> = args
        .alpn
        .split(',')
        .map(|proto| proto.trim().as_bytes().to_vec())
        .collect();
    let alpn_refs: Vec<&[u8]> = alpns.iter().map(|p| p.as_slice()).collect();
    let builder = if alpn_refs.is_empty() {
        builder
    } else {
        builder.application_protos(&alpn_refs)?
    };

    let server_config = builder.build_server()?;
    server_config
        .transport()
        .with_config_mut(|cfg| cfg.enable_dgram(true, 64, 64))?;
    Ok(server_config)
}

fn build_selector(args: &Args) -> Result<Arc<dyn QuicBackendSelector>, Box<dyn std::error::Error>> {
    if args.backends.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one --backend must be provided",
        )
        .into());
    }

    let lb = LoadBalancer::<RoundRobin>::try_from_iter(args.backends.iter().map(|s| s.as_str()))?;
    Ok(Arc::new(lb))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    let server_config = build_server_config(&args)?;
    let selector = build_selector(&args)?;

    let mut quic_service =
        QuicService::new("QUIC Load Balancer", &args.listen, server_config, selector);
    quic_service.set_max_backend_iterations(args.max_backend_iterations);

    let mut server = Server::new(None)?;
    server.bootstrap();
    server.add_service(quic_service);
    server.run_forever();
    Ok(())
}
