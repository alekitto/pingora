use std::sync::Arc;

use pingora_error::{Error, ErrorType, Result};

use crate::connectors::quic::QuicConnector;
use crate::connectors::ConnectorOptions;
use crate::protocols::http::v3::client::HttpSession;
use crate::protocols::quic::TransportConfigBuilder;
use crate::upstreams::peer::Peer;

const H3_ERROR: ErrorType = ErrorType::new("H3Error");

pub struct Connector {
    quic: QuicConnector,
    h3_config: Arc<quiche::h3::Config>,
}

impl Connector {
    pub fn new(_options: Option<ConnectorOptions>) -> Self {
        let protos: [&[u8]; 1] = [quiche::h3::APPLICATION_PROTOCOL];
        let builder = TransportConfigBuilder::new()
            .unwrap_or_else(|err| panic!("failed to construct QUIC transport config: {err}"));
        let builder = builder
            .application_protos(&protos)
            .unwrap_or_else(|err| panic!("failed to configure QUIC ALPN: {err}"));
        let quic = QuicConnector::new(builder.build_client());
        let h3_config = Arc::new(
            quiche::h3::Config::new()
                .unwrap_or_else(|err| panic!("failed to create HTTP/3 config: {err}")),
        );

        Self { quic, h3_config }
    }

    pub async fn get_http_session<P>(&self, peer: &P) -> Result<(HttpSession, bool)>
    where
        P: Peer + Send + Sync,
    {
        let mut upstream = self.quic.connect(peer).await?;
        let mut h3_conn = quiche::h3::Connection::with_transport(
            upstream.connection_mut().inner_mut(),
            &self.h3_config,
        )
        .map_err(|err| {
            Error::new(
                H3_ERROR,
                format!("failed to start HTTP/3 connection: {err}"),
            )
        })?;
        let mut session = HttpSession::new(upstream, h3_conn);
        session.ensure_handshake().await?;
        Ok((session, false))
    }

    pub async fn reused_http_session<P>(&self, _peer: &P) -> Option<HttpSession>
    where
        P: Peer + Send + Sync,
    {
        None
    }

    pub async fn release_http_session<P>(&self, mut session: HttpSession, _peer: &P)
    where
        P: Peer + Send + Sync,
    {
        session.shutdown().await;
    }
}
