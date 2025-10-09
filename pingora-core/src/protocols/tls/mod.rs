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

//! The TLS layer implementations

pub mod digest;
pub use digest::*;

#[cfg(feature = "openssl_derived")]
mod boringssl_openssl;

#[cfg(feature = "openssl_derived")]
pub use boringssl_openssl::*;

#[cfg(feature = "rustls")]
mod rustls;

#[cfg(feature = "rustls")]
pub use rustls::*;

#[cfg(not(feature = "any_tls"))]
pub mod noop_tls;

#[cfg(not(feature = "any_tls"))]
pub use noop_tls::*;

/// Supported HTTP application protocols for ALPN/QUIC negotiation.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum HttpProtocol {
    /// HTTP/1.1
    Http1,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl HttpProtocol {
    fn as_str(&self) -> &'static str {
        match self {
            HttpProtocol::Http1 => "H1",
            HttpProtocol::Http2 => "H2",
            HttpProtocol::Http3 => "H3",
        }
    }

    fn http_version(&self) -> u8 {
        match self {
            HttpProtocol::Http1 => 1,
            HttpProtocol::Http2 => 2,
            HttpProtocol::Http3 => 3,
        }
    }

    #[cfg(any(feature = "openssl_derived", feature = "rustls"))]
    fn tls_wire(&self) -> Option<&'static [u8]> {
        match self {
            HttpProtocol::Http1 => Some(b"http/1.1"),
            HttpProtocol::Http2 => Some(b"h2"),
            // HTTP/3 is negotiated via QUIC, not TLS
            HttpProtocol::Http3 => None,
        }
    }

    #[cfg(feature = "quic")]
    fn quic_wire(&self) -> &'static [u8] {
        match self {
            HttpProtocol::Http1 => b"http/1.1",
            HttpProtocol::Http2 => b"h2",
            HttpProtocol::Http3 => b"h3",
        }
    }
}

/// The protocol preference list for Application-Layer Protocol Negotiation
#[derive(Hash, Clone, Debug, PartialEq, Eq)]
pub struct ALPN {
    order: Vec<HttpProtocol>,
}

impl ALPN {
    /// Create a new ALPN preference from an explicit ordering.
    pub fn with_preference(order: Vec<HttpProtocol>) -> Self {
        assert!(!order.is_empty(), "ALPN preference list cannot be empty");
        Self { order }
    }

    /// Create a new ALPN according to the `max` and `min` version constraints.
    pub fn new(max: u8, min: u8) -> Self {
        let mut order = Vec::new();
        if max < min {
            return Self::with_preference(vec![HttpProtocol::Http1]);
        }
        for version in (min..=max).rev() {
            match version {
                1 => order.push(HttpProtocol::Http1),
                2 => order.push(HttpProtocol::Http2),
                3 => order.push(HttpProtocol::Http3),
                _ => {}
            }
        }
        if order.is_empty() {
            order.push(HttpProtocol::Http1);
        }
        Self::with_preference(order)
    }

    /// Convenience constructor for HTTP/1.1 only.
    pub fn h1() -> Self {
        Self::with_preference(vec![HttpProtocol::Http1])
    }

    /// Convenience constructor for HTTP/2 only.
    pub fn h2() -> Self {
        Self::with_preference(vec![HttpProtocol::Http2])
    }

    /// Convenience constructor for HTTP/2 preferred over HTTP/1.1.
    pub fn h2_h1() -> Self {
        Self::with_preference(vec![HttpProtocol::Http2, HttpProtocol::Http1])
    }

    /// Convenience constructor for HTTP/3 only.
    pub fn h3() -> Self {
        Self::with_preference(vec![HttpProtocol::Http3])
    }

    /// Convenience constructor for HTTP/3 preferred over HTTP/2 and HTTP/1.1.
    pub fn h3_h2_h1() -> Self {
        Self::with_preference(vec![
            HttpProtocol::Http3,
            HttpProtocol::Http2,
            HttpProtocol::Http1,
        ])
    }

    /// Return the protocols in preference order.
    pub fn preference(&self) -> &[HttpProtocol] {
        &self.order
    }

    /// Return the max http version this [`ALPN`] allows
    pub fn get_max_http_version(&self) -> u8 {
        self.order
            .first()
            .map(HttpProtocol::http_version)
            .unwrap_or(1)
    }

    /// Return the min http version this [`ALPN`] allows
    pub fn get_min_http_version(&self) -> u8 {
        self.order
            .last()
            .map(HttpProtocol::http_version)
            .unwrap_or(1)
    }

    /// Whether the preference allows HTTP/3.
    pub fn supports_http3(&self) -> bool {
        self.order.contains(&HttpProtocol::Http3)
    }

    /// Whether the preference is HTTP/1.1 only.
    pub fn is_http1_only(&self) -> bool {
        self.order.len() == 1 && self.order[0] == HttpProtocol::Http1
    }

    /// Whether the preference is HTTP/2 only.
    pub fn is_http2_only(&self) -> bool {
        self.order.len() == 1 && self.order[0] == HttpProtocol::Http2
    }

    /// The most preferred protocol if any.
    pub fn preferred(&self) -> Option<HttpProtocol> {
        self.order.first().copied()
    }

    #[cfg(feature = "openssl_derived")]
    pub(crate) fn to_wire_preference(&self) -> Vec<u8> {
        // https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_alpn_select_cb.html
        // "vector of nonempty, 8-bit length-prefixed, byte strings"
        let mut wire = Vec::new();
        for proto in self.order.iter().filter_map(HttpProtocol::tls_wire) {
            wire.push(proto.len() as u8);
            wire.extend_from_slice(proto);
        }
        wire
    }

    #[cfg(feature = "any_tls")]
    pub(crate) fn from_wire_selected(raw: &[u8]) -> Option<Self> {
        match raw {
            b"http/1.1" => Some(Self::h1()),
            b"h2" => Some(Self::h2()),
            _ => None,
        }
    }

    #[cfg(feature = "rustls")]
    pub(crate) fn to_wire_protocols(&self) -> Vec<Vec<u8>> {
        self.order
            .iter()
            .filter_map(HttpProtocol::tls_wire)
            .map(|p| p.to_vec())
            .collect()
    }

    #[cfg(feature = "quic")]
    pub(crate) fn to_quic_protocols(&self) -> Vec<Vec<u8>> {
        self.order.iter().map(|p| p.quic_wire().to_vec()).collect()
    }
}

impl Default for ALPN {
    fn default() -> Self {
        Self::h1()
    }
}

impl std::fmt::Display for ALPN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut iter = self.order.iter();
        if let Some(first) = iter.next() {
            write!(f, "{}", first.as_str())?;
        }
        for proto in iter {
            write!(f, "{}", proto.as_str())?;
        }
        Ok(())
    }
}
