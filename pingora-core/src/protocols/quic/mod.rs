//! QUIC transport support built on top of `quiche`.

mod config;
mod connection;
mod datagram;
mod endpoint;

pub use config::{
    ClientConfig, ConfigError, ServerConfig, TransportConfig, TransportConfigBuilder,
};
pub use connection::Connection;
pub use datagram::{
    Datagram, DatagramParts, DatagramPayload, SendDatagram, SendDatagramParts, MAX_DATAGRAM_SIZE,
};
pub use endpoint::Endpoint;
