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

//! Minimal HTTP/3 server session abstraction.
//!
//! The current implementation focuses on providing a `Session` API surface
//! compatible with the existing HTTP/1 and HTTP/2 variants so higher level
//! components can be wired without pulling in the full QUIC pipeline yet.
//! The struct keeps track of downstream request metadata and response
//! bookkeeping, while delegating the actual QUIC I/O to future follow ups.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method};
use pingora_error::Result;
use pingora_http::{RequestHeader, ResponseHeader};

use crate::protocols::http::v1::client::http_req_header_to_wire;
use crate::protocols::http::HttpTask;
use crate::protocols::quic::Connection as QuicTransport;
use crate::protocols::{Digest, SocketAddr};

/// HTTP/3 server session placeholder built on top of `quiche::h3::Connection`.
#[cfg_attr(not(feature = "quic"), allow(dead_code))]
pub struct HttpSession {
    transport: QuicTransport,
    connection: quiche::h3::Connection,
    digest: Arc<Digest>,
    request_header: RequestHeader,
    request_body: VecDeque<Bytes>,
    request_body_finished: bool,
    response_written: Option<ResponseHeader>,
    response_trailers: Option<HeaderMap>,
    ended: bool,
    body_read: usize,
    body_sent: usize,
    keepalive: Option<u64>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    total_drain_timeout: Option<Duration>,
    min_send_rate: Option<usize>,
    ignore_info_resp: bool,
    close_on_early_response: bool,
}

impl HttpSession {
    /// Create a new HTTP/3 session wrapper around a `quiche::h3::Connection` and
    /// an associated [`Digest`].
    pub fn new(
        transport: QuicTransport,
        connection: quiche::h3::Connection,
        digest: Arc<Digest>,
    ) -> Result<Self> {
        let request_header = RequestHeader::build_no_case(Method::GET, b"/", None)?;
        Ok(Self {
            transport,
            connection,
            digest,
            request_header,
            request_body: VecDeque::new(),
            request_body_finished: true,
            response_written: None,
            response_trailers: None,
            ended: false,
            body_read: 0,
            body_sent: 0,
            keepalive: None,
            read_timeout: None,
            write_timeout: None,
            total_drain_timeout: None,
            min_send_rate: None,
            ignore_info_resp: true,
            close_on_early_response: false,
        })
    }

    /// Construct a placeholder HTTP/3 session for scaffolding purposes.
    ///
    /// This helper intentionally bypasses detailed header parsing so that the
    /// service layer can be wired before the full protocol implementation
    /// lands.
    pub fn placeholder(
        transport: QuicTransport,
        connection: quiche::h3::Connection,
        digest: Arc<Digest>,
    ) -> Self {
        Self::new(transport, connection, digest)
            .unwrap_or_else(|err| panic!("failed to construct placeholder HTTP/3 session: {err}"))
    }

    /// Replace the stored request header. This helper is primarily intended for
    /// code that parses headers from the underlying HTTP/3 connection.
    pub fn set_request_header(&mut self, header: RequestHeader) {
        self.request_header = header;
    }

    /// Queue a request body chunk that will be observed by
    /// [`Self::read_body_bytes`].
    pub fn queue_request_body(&mut self, chunk: Bytes, finished: bool) {
        if !chunk.is_empty() {
            self.request_body.push_back(chunk);
        }
        self.request_body_finished = finished;
    }

    /// Expose the underlying `quiche::h3::Connection`.
    pub fn connection(&self) -> &quiche::h3::Connection {
        &self.connection
    }

    /// Mutable access to the underlying `quiche::h3::Connection`.
    pub fn connection_mut(&mut self) -> &mut quiche::h3::Connection {
        &mut self.connection
    }

    /// The request sent from the client.
    pub fn req_header(&self) -> &RequestHeader {
        &self.request_header
    }

    /// A mutable reference to the request sent from the client.
    pub fn req_header_mut(&mut self) -> &mut RequestHeader {
        &mut self.request_header
    }

    /// Read request body bytes. `None` when there is no more body to read.
    pub async fn read_body_bytes(&mut self) -> Result<Option<Bytes>> {
        if let Some(chunk) = self.request_body.pop_front() {
            self.body_read += chunk.len();
            Ok(Some(chunk))
        } else if self.request_body_finished {
            Ok(None)
        } else {
            Ok(None)
        }
    }

    /// Drain the remaining request body chunks.
    pub async fn drain_request_body(&mut self) -> Result<()> {
        self.request_body.clear();
        self.request_body_finished = true;
        Ok(())
    }

    /// Write the response header to the client.
    pub async fn write_response_header(&mut self, resp: Box<ResponseHeader>) -> Result<()> {
        if !resp.status.is_informational() || resp.status == 101 {
            self.response_written = Some((*resp).clone());
        }
        let _ = resp;
        Ok(())
    }

    /// Write the response header to the client by reference.
    pub async fn write_response_header_ref(&mut self, resp: &ResponseHeader) -> Result<()> {
        self.write_response_header(Box::new(resp.clone())).await
    }

    /// Write the response body to the client.
    pub async fn write_response_body(&mut self, data: Bytes, end: bool) -> Result<()> {
        self.body_sent += data.len();
        if end {
            self.ended = true;
        }
        Ok(())
    }

    /// Write response trailers to the client.
    pub async fn write_response_trailers(&mut self, trailers: HeaderMap) -> Result<()> {
        self.response_trailers = Some(trailers);
        self.ended = true;
        Ok(())
    }

    /// Finish the life of this request.
    pub async fn finish(&mut self) -> Result<()> {
        self.ended = true;
        Ok(())
    }

    /// Consume a batch of [`HttpTask`] items.
    pub async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> Result<bool> {
        let mut end_stream = false;
        for task in tasks {
            end_stream = match task {
                HttpTask::Header(header, end) => {
                    self.write_response_header(header).await?;
                    end
                }
                HttpTask::Body(data, end) => {
                    if let Some(chunk) = data {
                        if !chunk.is_empty() {
                            self.write_response_body(chunk, end).await?;
                        } else if end {
                            self.finish_body().await?;
                        }
                    } else if end {
                        self.finish_body().await?;
                    }
                    end
                }
                HttpTask::Trailer(Some(trailers)) => {
                    self.write_response_trailers(*trailers).await?;
                    true
                }
                HttpTask::Trailer(None) => {
                    self.finish_body().await?;
                    true
                }
                HttpTask::Done => true,
                HttpTask::Failed(err) => {
                    return Err(err);
                }
            } || end_stream;
        }
        if end_stream {
            self.finish_body().await?;
        }
        Ok(end_stream)
    }

    /// Set connection reuse semantics.
    pub fn set_server_keepalive(&mut self, duration: Option<u64>) {
        self.keepalive = duration;
    }

    /// Retrieve the keepalive timeout if any.
    pub fn get_keepalive_timeout(&self) -> Option<u64> {
        self.keepalive
    }

    /// Sets the downstream read timeout.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Gets the downstream read timeout if set.
    pub fn get_read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// Sets the downstream write timeout.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    /// Gets the downstream write timeout if set.
    pub fn get_write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    /// Sets the total drain timeout.
    pub fn set_total_drain_timeout(&mut self, timeout: Option<Duration>) {
        self.total_drain_timeout = timeout;
    }

    /// Gets the total drain timeout if set.
    pub fn get_total_drain_timeout(&self) -> Option<Duration> {
        self.total_drain_timeout
    }

    /// Sets the minimum downstream send rate in bytes per second.
    pub fn set_min_send_rate(&mut self, rate: Option<usize>) {
        self.min_send_rate = rate;
    }

    /// Sets whether informational responses are ignored.
    pub fn set_ignore_info_resp(&mut self, ignore: bool) {
        self.ignore_info_resp = ignore;
    }

    /// Sets whether keepalive should be disabled if response is written early.
    pub fn set_close_on_response_before_downstream_finish(&mut self, close: bool) {
        self.close_on_early_response = close;
    }

    /// Return a digest of the request including the method and path.
    pub fn request_summary(&self) -> String {
        let method = self.request_header.method.as_str();
        let path = self
            .request_header
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let host = self
            .request_header
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if host.is_empty() {
            format!("{method} {path}")
        } else {
            format!("{method} {path}, Host: {host}")
        }
    }

    /// Return the written response header if any.
    pub fn response_written(&self) -> Option<&ResponseHeader> {
        self.response_written.as_ref()
    }

    /// Give up the HTTP/3 session abruptly.
    pub async fn shutdown(&mut self) {
        self.ended = true;
    }

    /// Return a pseudo HTTP/1 representation of the headers.
    pub fn to_h1_raw(&self) -> Bytes {
        http_req_header_to_wire(&self.request_header)
            .unwrap_or_default()
            .freeze()
    }

    /// Whether the whole request body is sent.
    pub fn is_body_done(&self) -> bool {
        self.request_body_finished && self.request_body.is_empty()
    }

    /// Whether there is any body to read. `true` means there is no body in the request.
    pub fn is_body_empty(&self) -> bool {
        self.body_read == 0 && self.request_body_finished
    }

    /// Whether the retry buffer truncated.
    pub fn retry_buffer_truncated(&self) -> bool {
        false
    }

    /// Enable buffering of the request body for retries.
    pub fn enable_retry_buffering(&mut self) {}

    /// Return any buffered request body for retries.
    pub fn get_retry_buffer(&self) -> Option<Bytes> {
        None
    }

    /// Read the body or idle until downstream closes.
    pub async fn read_body_or_idle(&mut self, no_body_expected: bool) -> Result<Option<Bytes>> {
        if no_body_expected || self.is_body_done() {
            Ok(None)
        } else {
            self.read_body_bytes().await
        }
    }

    /// Write a 100 Continue response to the client.
    pub async fn write_continue_response(&mut self) -> Result<()> {
        let resp = ResponseHeader::build(100, None)?;
        self.write_response_header(Box::new(resp)).await
    }

    /// Whether this request is for upgrade (e.g., websocket).
    pub fn is_upgrade_req(&self) -> bool {
        false
    }

    /// Return how many response body bytes (application, not wire) already sent downstream.
    pub fn body_bytes_sent(&self) -> usize {
        self.body_sent
    }

    /// Return how many request body bytes (application, not wire) already read from downstream.
    pub fn body_bytes_read(&self) -> usize {
        self.body_read
    }

    /// Return the [`Digest`] of the connection.
    pub fn digest(&self) -> Option<&Digest> {
        Some(&self.digest)
    }

    /// Return a mutable [`Digest`] reference for the connection.
    pub fn digest_mut(&mut self) -> Option<&mut Digest> {
        Arc::get_mut(&mut self.digest)
    }

    /// Return the client (peer) address recorded in the digest.
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.digest
            .socket_digest
            .as_ref()
            .and_then(|d| d.peer_addr())
    }

    /// Return the server (local) address recorded in the digest.
    pub fn server_addr(&self) -> Option<&SocketAddr> {
        self.digest
            .socket_digest
            .as_ref()
            .and_then(|d| d.local_addr())
    }

    /// HTTP/3 sessions do not expose an underlying [`Stream`].
    pub fn stream(&self) -> Option<&crate::protocols::Stream> {
        None
    }

    /// Finish the response body if it hasn't already been marked as ended.
    pub async fn finish_body(&mut self) -> Result<()> {
        self.ended = true;
        Ok(())
    }
}
