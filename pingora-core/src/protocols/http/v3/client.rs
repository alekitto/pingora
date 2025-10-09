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

//! Minimal HTTP/3 client session abstraction built on top of `quiche`.
//!
//! The current implementation focuses on providing an API surface that mirrors
//! the existing HTTP/1 and HTTP/2 client sessions. It encapsulates a QUIC
//! transport connection managed by [`QuicUpstream`] alongside a
//! `quiche::h3::Connection`, exposing helpers to write requests and read
//! responses. The implementation purposefully keeps the logic conservative so
//! that it can serve as a scaffold for further feature work such as more
//! advanced flow-control handling or concurrent stream multiplexing.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::header::{HeaderName, HeaderValue};
use pingora_error::{Error, ErrorType, ErrorType::*, OrErr, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_timeout::timeout;
use quiche::h3::NameValue;

use crate::connectors::quic::QuicUpstream;
use crate::protocols::http::HttpTask;
use crate::protocols::{Digest, GetProxyDigest, GetSocketDigest, GetTimingDigest, SocketAddr};

const H3_ERROR: ErrorType = ErrorType::new("H3Error");
const H3_STREAM_RESET: ErrorType = ErrorType::new("H3StreamReset");

/// HTTP/3 client session backed by a QUIC connection.
pub struct HttpSession {
    upstream: QuicUpstream,
    h3: quiche::h3::Connection,
    stream_id: Option<u64>,
    response_header: Option<ResponseHeader>,
    buffered_body: VecDeque<Bytes>,
    response_finished: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    digest: Box<Digest>,
}

impl HttpSession {
    /// Create a new HTTP/3 session from an established QUIC upstream and an
    /// HTTP/3 connection.
    pub fn new(upstream: QuicUpstream, h3: quiche::h3::Connection) -> Self {
        let digest = Box::new(Digest {
            ssl_digest: None,
            timing_digest: upstream.connection().get_timing_digest(),
            proxy_digest: upstream.connection().get_proxy_digest(),
            socket_digest: upstream.connection().get_socket_digest(),
        });

        Self {
            upstream,
            h3,
            stream_id: None,
            response_header: None,
            buffered_body: VecDeque::new(),
            response_finished: false,
            read_timeout: None,
            write_timeout: None,
            digest,
        }
    }

    /// Mutable access to the underlying digest.
    pub fn digest_mut(&mut self) -> &mut Digest {
        &mut self.digest
    }

    /// Immutable access to the digest.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn request_stream(&self) -> Result<u64> {
        self.stream_id
            .ok_or_else(|| Error::explain(InternalError, "HTTP/3 stream not initialised"))
    }

    fn convert_request_headers(req: &RequestHeader) -> Result<Vec<quiche::h3::Header>> {
        let mut headers = Vec::new();

        headers.push(quiche::h3::Header::new(
            b":method",
            req.method.as_str().as_bytes(),
        ));

        let scheme = req
            .uri
            .scheme()
            .map(|s| s.as_str().as_bytes().to_vec())
            .unwrap_or_else(|| b"https".to_vec());
        headers.push(quiche::h3::Header::new(b":scheme", scheme.as_slice()));

        let authority = match req.uri.authority() {
            Some(authority) => authority.as_str().as_bytes().to_vec(),
            None => req
                .headers
                .get(http::header::HOST)
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
        };
        if !authority.is_empty() {
            headers.push(quiche::h3::Header::new(b":authority", authority.as_slice()));
        }

        headers.push(quiche::h3::Header::new(
            b":path",
            req.raw_path().to_vec().as_slice(),
        ));

        for (name, value) in req.headers.iter() {
            if name == http::header::HOST {
                continue;
            }
            headers.push(quiche::h3::Header::new(
                name.as_str().as_bytes(),
                value.as_bytes(),
            ));
        }

        Ok(headers)
    }

    fn convert_response_headers(list: Vec<quiche::h3::Header>) -> Result<ResponseHeader> {
        let mut status = None;
        let mut fields = Vec::new();

        for header in list {
            let name_bytes = header.name();
            if name_bytes == b":status" {
                let value = std::str::from_utf8(header.value())
                    .or_err(H3_ERROR, "invalid HTTP/3 status header")?;
                status = Some(
                    value
                        .parse::<u16>()
                        .or_err(H3_ERROR, "invalid status code")?,
                );
                continue;
            }
            fields.push((
                HeaderName::from_bytes(name_bytes).or_err(H3_ERROR, "invalid header name")?,
                HeaderValue::from_bytes(header.value()).or_err(H3_ERROR, "invalid header value")?,
            ));
        }

        let mut response =
            ResponseHeader::build_no_case(status.unwrap_or(200), Some(fields.len()))?;
        for (name, value) in fields {
            response
                .append_header(name, value)
                .or_err(H3_ERROR, "append header")?;
        }
        Ok(response)
    }

    async fn flush_quic(&mut self) -> Result<()> {
        loop {
            match self.upstream.connection_mut().send() {
                Ok(packet) => {
                    let send_future = self.upstream.send(&packet);
                    match self.write_timeout {
                        Some(timeout_duration) => {
                            timeout(timeout_duration, send_future)
                                .await
                                .or_err(WriteTimedout, "timeout while flushing HTTP/3 datagram")?
                                .map_err(|e| Error::because(H3_ERROR, "write error", e))?;
                        }
                        None => {
                            send_future
                                .await
                                .or_err(WriteError, "sending HTTP/3 datagram")?;
                        }
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    return Error::e_because(H3_ERROR, "quiche send", err);
                }
            }
        }

        Ok(())
    }

    async fn recv_datagram(&mut self) -> Result<bool> {
        let recv_future = self.upstream.recv();
        let datagram = match self.read_timeout {
            Some(timeout_duration) => {
                match timeout(timeout_duration, recv_future)
                    .await
                    .or_err(ReadTimedout, "timeout while receiving HTTP/3 datagram")
                {
                    Ok(res) => res,
                    Err(err) => return Err(err),
                }
            }
            None => recv_future.await,
        };

        let mut datagram = match datagram {
            Ok(d) => d,
            Err(err) => {
                return Err(Error::because(ReadError, "receiving HTTP/3 datagram", err));
            }
        };

        match self.upstream.connection_mut().recv(&mut datagram) {
            Ok(_) => {
                self.flush_quic().await?;
                Ok(true)
            }
            Err(quiche::Error::Done) => Ok(false),
            Err(err) => Error::e_because(H3_ERROR, "quiche recv", err),
        }
    }

    async fn next_event(&mut self) -> Result<Option<(u64, quiche::h3::Event)>> {
        loop {
            match self.h3.poll(self.upstream.connection_mut().inner_mut()) {
                Ok((stream_id, event)) => return Ok(Some((stream_id, event))),
                Err(quiche::h3::Error::Done) => {
                    if !self.recv_datagram().await? {
                        return Ok(None);
                    }
                }
                Err(err) => return Error::e_because(H3_ERROR, "HTTP/3 poll", err),
            }
        }
    }

    async fn read_body_frames(&mut self, stream_id: u64) -> Result<()> {
        let mut buffer = BytesMut::with_capacity(4096);
        buffer.resize(4096, 0);

        loop {
            match self.h3.recv_body(
                self.upstream.connection_mut().inner_mut(),
                stream_id,
                &mut buffer,
            ) {
                Ok(read) => {
                    if read == 0 {
                        break;
                    }
                    self.buffered_body
                        .push_back(Bytes::copy_from_slice(&buffer[..read]));
                    if read < buffer.len() {
                        break;
                    }
                }
                Err(quiche::h3::Error::Done) => break,
                Err(err) => return Error::e_because(H3_ERROR, "HTTP/3 recv_body", err),
            }
        }

        Ok(())
    }

    pub(crate) async fn ensure_handshake(&mut self) -> Result<()> {
        if self.upstream.connection().is_established() {
            return Ok(());
        }

        let start = Instant::now();
        let deadline = self.upstream.handshake_timeout();

        while !self.upstream.connection().is_established() {
            if let Some(timeout_duration) = deadline {
                let elapsed = start.elapsed();
                if elapsed >= timeout_duration {
                    return Err(Error::explain(ConnectTimedout, "QUIC handshake timed out"));
                }

                let remaining = match timeout_duration.checked_sub(elapsed) {
                    Some(remaining) if !remaining.is_zero() => remaining,
                    _ => return Err(Error::explain(ConnectTimedout, "QUIC handshake timed out")),
                };

                match timeout(remaining, self.recv_datagram()).await {
                    Ok(result) => {
                        result?;
                    }
                    Err(_) => {
                        return Err(Error::explain(ConnectTimedout, "QUIC handshake timed out"));
                    }
                }
            } else {
                self.recv_datagram().await?;
            }
        }

        Ok(())
    }

    /// Write the request header to the backend.
    pub async fn write_request_header(&mut self, req: Box<RequestHeader>, end: bool) -> Result<()> {
        self.ensure_handshake().await?;
        let headers = Self::convert_request_headers(&req)?;
        let stream_id = self
            .h3
            .send_request(self.upstream.connection_mut().inner_mut(), &headers, end)
            .map_err(|err| Error::because(H3_ERROR, "HTTP/3 send_request", err))?;
        self.stream_id = Some(stream_id);
        self.flush_quic().await
    }

    /// Write a chunk of the request body.
    pub async fn write_request_body(&mut self, data: Bytes, end: bool) -> Result<()> {
        let stream_id = self.request_stream()?;
        self.ensure_handshake().await?;

        self.h3
            .send_body(
                self.upstream.connection_mut().inner_mut(),
                stream_id,
                data.as_ref(),
                end,
            )
            .map_err(|err| Error::because(H3_ERROR, "HTTP/3 send_body", err))?;
        self.flush_quic().await
    }

    /// Signal that the request body has finished.
    pub async fn finish_request_body(&mut self) -> Result<()> {
        if let Ok(stream_id) = self.request_stream() {
            self.h3
                .send_body(
                    self.upstream.connection_mut().inner_mut(),
                    stream_id,
                    &[],
                    true,
                )
                .map_err(|err| Error::because(H3_ERROR, "HTTP/3 finish body", err))?;
            self.flush_quic().await?;
        }
        Ok(())
    }

    /// Configure the per-operation read timeout.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    /// Configure the per-operation write timeout.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    /// Read the response header.
    pub async fn read_response_header(&mut self) -> Result<()> {
        if self.response_header.is_some() {
            return Ok(());
        }

        loop {
            let Some((stream_id, event)) = self.next_event().await? else {
                return Err(Error::explain(H3_ERROR, "HTTP/3 connection closed"));
            };

            if Some(stream_id) != self.stream_id {
                continue;
            }

            match event {
                quiche::h3::Event::Headers { list, .. } => {
                    let header = Self::convert_response_headers(list)?;
                    self.response_header = Some(header);
                    return Ok(());
                }
                quiche::h3::Event::Data => {
                    self.read_body_frames(stream_id).await?;
                }
                quiche::h3::Event::Finished => {
                    self.response_finished = true;
                    return Ok(());
                }
                quiche::h3::Event::Reset(err_code) => {
                    return Error::e_explain(
                        H3_STREAM_RESET,
                        format!("HTTP/3 stream reset: {err_code}"),
                    );
                }
                quiche::h3::Event::PriorityUpdate | quiche::h3::Event::GoAway => {}
            }
        }
    }

    /// Read the next response body chunk.
    pub async fn read_response_body(&mut self) -> Result<Option<Bytes>> {
        if let Some(chunk) = self.buffered_body.pop_front() {
            return Ok(Some(chunk));
        }

        if self.response_finished {
            return Ok(None);
        }

        loop {
            let Some((stream_id, event)) = self.next_event().await? else {
                self.response_finished = true;
                return Ok(None);
            };

            if Some(stream_id) != self.stream_id {
                continue;
            }

            match event {
                quiche::h3::Event::Headers { .. } => {
                    // Additional informational headers are currently ignored.
                    continue;
                }
                quiche::h3::Event::Data => {
                    self.read_body_frames(stream_id).await?;
                    if let Some(chunk) = self.buffered_body.pop_front() {
                        return Ok(Some(chunk));
                    }
                }
                quiche::h3::Event::Finished => {
                    self.response_finished = true;
                    return Ok(None);
                }
                quiche::h3::Event::Reset(err_code) => {
                    return Error::e_explain(
                        H3_STREAM_RESET,
                        format!("HTTP/3 stream reset: {err_code}"),
                    );
                }
                quiche::h3::Event::GoAway | quiche::h3::Event::PriorityUpdate => {}
            }
        }
    }

    /// Whether the response body has been fully consumed.
    pub fn response_finished(&self) -> bool {
        self.response_finished && self.buffered_body.is_empty()
    }

    /// Access the parsed response header.
    pub fn response_header(&self) -> Option<&ResponseHeader> {
        self.response_header.as_ref()
    }

    /// Abort the underlying QUIC connection.
    pub async fn shutdown(&mut self) {
        let _ = self
            .upstream
            .connection_mut()
            .inner_mut()
            .close(false, 0, b"HTTP/3 shutdown");
        let _ = self.flush_quic().await;
    }

    /// Helper to drive the response into discrete tasks similar to the HTTP/1
    /// and HTTP/2 counterparts.
    pub async fn response_duplex_vec(&mut self) -> Result<Option<HttpTask>> {
        if self.response_header.is_none() {
            self.read_response_header().await?;
            if let Some(resp) = self.response_header.as_ref() {
                let header = Box::new(resp.clone());
                return Ok(Some(HttpTask::Header(header, self.response_finished())));
            }
        }

        if let Some(chunk) = self.read_response_body().await? {
            let end = self.response_finished();
            return Ok(Some(HttpTask::Body(Some(chunk), end)));
        }

        if self.response_finished() {
            return Ok(Some(HttpTask::Done));
        }

        Ok(None)
    }

    /// Return the server (peer) address.
    pub fn server_addr(&self) -> Option<&SocketAddr> {
        self.digest
            .socket_digest
            .as_ref()
            .and_then(|d| d.peer_addr())
    }

    /// Return the client (local) address.
    pub fn client_addr(&self) -> Option<&SocketAddr> {
        self.digest
            .socket_digest
            .as_ref()
            .and_then(|d| d.local_addr())
    }

    /// Access to the underlying QUIC upstream.
    pub fn upstream(&self) -> &QuicUpstream {
        &self.upstream
    }

    /// Mutable access to the underlying QUIC upstream.
    pub fn upstream_mut(&mut self) -> &mut QuicUpstream {
        &mut self.upstream
    }
}
