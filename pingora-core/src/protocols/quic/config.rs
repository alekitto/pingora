use std::path::Path;
use std::sync::{Arc, Mutex};

use super::connection::Connection;

/// Error returned when building a QUIC [`TransportConfig`].
#[derive(Debug)]
pub enum ConfigError {
    /// The provided certificate chain or private key was not configured.
    MissingServerCertificate,
    /// Failed to convert the provided path to a UTF-8 string.
    InvalidPath(std::path::PathBuf),
    /// Errors bubbled up from the underlying `quiche` configuration.
    Quiche(quiche::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingServerCertificate => {
                write!(f, "missing certificate or private key for QUIC server")
            }
            ConfigError::InvalidPath(path) => {
                write!(f, "unable to convert path `{}` to UTF-8", path.display())
            }
            ConfigError::Quiche(err) => write!(f, "quiche configuration error: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Quiche(err) => Some(err),
            _ => None,
        }
    }
}

impl From<quiche::Error> for ConfigError {
    fn from(value: quiche::Error) -> Self {
        ConfigError::Quiche(value)
    }
}

fn path_to_str(path: &Path) -> Result<&str, ConfigError> {
    path.to_str()
        .ok_or_else(|| ConfigError::InvalidPath(path.to_path_buf()))
}

/// Shared QUIC configuration used by endpoints and connections.
#[derive(Clone)]
pub struct TransportConfig {
    inner: Arc<Mutex<quiche::Config>>,
}

impl TransportConfig {
    pub(crate) fn new(config: quiche::Config) -> Self {
        Self {
            inner: Arc::new(Mutex::new(config)),
        }
    }

    /// Access the underlying `quiche` configuration.
    pub fn with_config<R, F>(&self, func: F) -> R
    where
        F: FnOnce(&quiche::Config) -> R,
    {
        let guard = self
            .inner
            .lock()
            .expect("poisoned QUIC transport configuration mutex");
        func(&guard)
    }

    /// Execute a closure with mutable access to the underlying configuration.
    pub fn with_config_mut<R, F>(&self, func: F) -> R
    where
        F: FnOnce(&mut quiche::Config) -> R,
    {
        let mut guard = self
            .inner
            .lock()
            .expect("poisoned QUIC transport configuration mutex");
        func(&mut guard)
    }
}

/// Builder used to create [`TransportConfig`] instances.
pub struct TransportConfigBuilder {
    config: quiche::Config,
    has_certificate: bool,
    has_private_key: bool,
}

impl TransportConfigBuilder {
    /// Create a new builder using the default QUIC protocol version.
    pub fn new() -> Result<Self, quiche::Error> {
        Self::with_version(quiche::PROTOCOL_VERSION)
    }

    /// Create a builder for a specific QUIC version.
    pub fn with_version(version: u32) -> Result<Self, quiche::Error> {
        Ok(Self {
            config: quiche::Config::new(version)?,
            has_certificate: false,
            has_private_key: false,
        })
    }

    /// Configure the list of application protocols advertised via ALPN.
    pub fn application_protos(mut self, protos: &[&[u8]]) -> Result<Self, ConfigError> {
        self.config.set_application_protos(protos)?;
        Ok(self)
    }

    /// Enable or disable peer certificate verification.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.verify_peer(verify);
        self
    }

    /// Load a certificate chain from a PEM file on disk.
    pub fn load_cert_chain_from_pem_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, ConfigError> {
        let as_str = path_to_str(path.as_ref())?;
        self.config.load_cert_chain_from_pem_file(as_str)?;
        self.has_certificate = true;
        Ok(self)
    }

    /// Load a private key from a PEM file on disk.
    pub fn load_priv_key_from_pem_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, ConfigError> {
        let as_str = path_to_str(path.as_ref())?;
        self.config.load_priv_key_from_pem_file(as_str)?;
        self.has_private_key = true;
        Ok(self)
    }

    /// Build a [`TransportConfig`] without enforcing any certificate requirements.
    pub fn build(self) -> TransportConfig {
        TransportConfig::new(self.config)
    }

    /// Build a [`ClientConfig`] instance.
    pub fn build_client(self) -> ClientConfig {
        ClientConfig {
            config: self.build(),
        }
    }

    /// Build a [`ServerConfig`] instance, ensuring that TLS 1.3 certificate material is present.
    pub fn build_server(self) -> Result<ServerConfig, ConfigError> {
        if !(self.has_certificate && self.has_private_key) {
            return Err(ConfigError::MissingServerCertificate);
        }

        Ok(ServerConfig {
            config: self.build(),
        })
    }
}

/// Client-side QUIC configuration wrapper.
#[derive(Clone)]
pub struct ClientConfig {
    config: TransportConfig,
}

impl ClientConfig {
    /// Access the underlying shared configuration.
    pub fn transport(&self) -> &TransportConfig {
        &self.config
    }

    /// Create a new QUIC client connection using the stored configuration.
    pub fn connect(
        &self,
        server_name: Option<&str>,
        scid: &quiche::ConnectionId<'_>,
        local: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) -> Result<Connection, quiche::Error> {
        self.config
            .with_config_mut(|cfg| quiche::connect(server_name, scid, local, peer, cfg))
            .map(Connection::new)
    }
}

/// Server-side QUIC configuration wrapper.
#[derive(Clone)]
pub struct ServerConfig {
    config: TransportConfig,
}

impl ServerConfig {
    /// Access the underlying shared configuration.
    pub fn transport(&self) -> &TransportConfig {
        &self.config
    }

    /// Accept an incoming QUIC connection using the stored configuration.
    pub fn accept(
        &self,
        scid: &quiche::ConnectionId<'_>,
        odcid: Option<&quiche::ConnectionId<'_>>,
        local: std::net::SocketAddr,
        peer: std::net::SocketAddr,
    ) -> Result<Connection, quiche::Error> {
        self.config
            .with_config_mut(|cfg| quiche::accept(scid, odcid, local, peer, cfg))
            .map(Connection::new)
    }
}
