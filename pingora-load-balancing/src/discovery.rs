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

//! Service discovery interface and implementations

use arc_swap::ArcSwap;
use async_trait::async_trait;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_error::Result;
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use crate::{Backend, BackendProtocol};

/// [ServiceDiscovery] is the interface to discover [Backend]s.
#[async_trait]
pub trait ServiceDiscovery {
    /// Return the discovered collection of backends.
    /// And *optionally* whether these backends are enabled to serve or not in a `HashMap`. Any backend
    /// that is not explicitly in the set is considered enabled.
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)>;
}

// TODO: add DNS base discovery

/// A static collection of [Backend]s for service discovery.
#[derive(Default)]
pub struct Static {
    backends: ArcSwap<BTreeSet<Backend>>,
}

impl Static {
    /// Create a new boxed [Static] service discovery with the given backends.
    pub fn new(backends: BTreeSet<Backend>) -> Box<Self> {
        Box::new(Static {
            backends: ArcSwap::new(Arc::new(backends)),
        })
    }

    /// Create a new boxed [Static] from a given iterator of items that implements [ToSocketAddrs].
    pub fn try_from_iter<A, T: IntoIterator<Item = A>>(iter: T) -> IoResult<Box<Self>>
    where
        A: IntoStaticBackends,
    {
        let mut upstreams = BTreeSet::new();
        for target in iter.into_iter() {
            upstreams.extend(target.into_backends()?);
        }
        Ok(Self::new(upstreams))
    }

    /// return the collection to backends
    pub fn get(&self) -> BTreeSet<Backend> {
        BTreeSet::clone(&self.backends.load())
    }

    // Concurrent set/add/remove might race with each other
    // TODO: use a queue to avoid racing

    // TODO: take an impl iter
    #[allow(dead_code)]
    pub(crate) fn set(&self, backends: BTreeSet<Backend>) {
        self.backends.store(backends.into())
    }

    #[allow(dead_code)]
    pub(crate) fn add(&self, backend: Backend) {
        let mut new = self.get();
        new.insert(backend);
        self.set(new)
    }

    #[allow(dead_code)]
    pub(crate) fn remove(&self, backend: &Backend) {
        let mut new = self.get();
        new.remove(backend);
        self.set(new)
    }
}

#[async_trait]
impl ServiceDiscovery for Static {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // no readiness
        let health = HashMap::new();
        Ok((self.get(), health))
    }
}

/// Helper trait to build a static set of [Backend]s from various inputs.
pub trait IntoStaticBackends {
    /// Convert the target into concrete backends.
    fn into_backends(self) -> IoResult<Vec<Backend>>;
}

fn parse_host_with_protocol(addr: &str, protocol: BackendProtocol) -> IoResult<Vec<Backend>> {
    let addrs = addr.to_socket_addrs()?;
    Ok(addrs
        .map(|addr| Backend::from_std_socket(addr, 1, protocol))
        .collect())
}

impl IntoStaticBackends for Backend {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![self])
    }
}

impl IntoStaticBackends for &Backend {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![self.clone()])
    }
}

impl IntoStaticBackends for SocketAddr {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_socket(self, 1, BackendProtocol::Tcp)])
    }
}

impl IntoStaticBackends for std::net::SocketAddr {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_std_socket(
            self,
            1,
            BackendProtocol::Tcp,
        )])
    }
}

impl IntoStaticBackends for (SocketAddr, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_socket(self.0, 1, self.1)])
    }
}

impl IntoStaticBackends for (std::net::SocketAddr, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_std_socket(self.0, 1, self.1)])
    }
}

impl IntoStaticBackends for &str {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        if let Some(udp) = self.strip_prefix("udp://") {
            return parse_host_with_protocol(udp, BackendProtocol::Udp);
        }

        if let Some(quic) = self.strip_prefix("quic://") {
            return parse_host_with_protocol(quic, BackendProtocol::Quic);
        }

        let host = self.strip_prefix("tcp://").unwrap_or(self);
        parse_host_with_protocol(host, BackendProtocol::Tcp)
    }
}

impl IntoStaticBackends for String {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        self.as_str().into_backends()
    }
}

impl IntoStaticBackends for (&str, u16) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        let addr = format!("{}:{}", self.0, self.1);
        addr.into_backends()
    }
}

impl IntoStaticBackends for (String, u16) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        let addr = format!("{}:{}", self.0, self.1);
        addr.into_backends()
    }
}

impl IntoStaticBackends for (&str, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        match self.1 {
            BackendProtocol::Tcp => self.0.into_backends(),
            BackendProtocol::Udp => {
                if let Some(host) = self.0.strip_prefix("udp://") {
                    parse_host_with_protocol(host, BackendProtocol::Udp)
                } else {
                    parse_host_with_protocol(self.0, BackendProtocol::Udp)
                }
            }
            BackendProtocol::Quic => {
                if let Some(host) = self.0.strip_prefix("quic://") {
                    parse_host_with_protocol(host, BackendProtocol::Quic)
                } else {
                    parse_host_with_protocol(self.0, BackendProtocol::Quic)
                }
            }
        }
    }
}

impl IntoStaticBackends for (String, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        (self.0.as_str(), self.1).into_backends()
    }
}

impl IntoStaticBackends for (std::net::SocketAddr, usize, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_std_socket(self.0, self.1, self.2)])
    }
}

impl IntoStaticBackends for (SocketAddr, usize, BackendProtocol) {
    fn into_backends(self) -> IoResult<Vec<Backend>> {
        Ok(vec![Backend::from_socket(self.0, self.1, self.2)])
    }
}
