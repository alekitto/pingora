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

//! Consistent Hashing

use super::*;
use crate::BackendProtocol;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_ketama::{Bucket, Continuum};
use std::collections::HashSet;
use std::io::Write;

/// Weighted Ketama consistent hashing
pub struct KetamaHashing {
    ring: Continuum,
    backends: Vec<Backend>,
}

impl BackendSelection for KetamaHashing {
    type Iter = OwnedNodeIterator;

    fn build(backends: &BTreeSet<Backend>) -> Self {
        let mut buckets = Vec::new();
        let mut new_backends = Vec::new();

        for backend in backends {
            // FIXME: ketama only supports Inet addr, UDS addrs are ignored here
            if let SocketAddr::Inet(addr) = backend.addr {
                let mut hash_key = Vec::with_capacity(3 + 1 + 39 + 1 + 5);
                let tag = match backend.protocol {
                    BackendProtocol::Tcp => b"tcp".as_slice(),
                    BackendProtocol::Udp => b"udp".as_slice(),
                };
                hash_key.extend_from_slice(tag);
                hash_key.push(0);
                write!(&mut hash_key, "{}", addr.ip()).unwrap();
                hash_key.push(0);
                write!(&mut hash_key, "{}", addr.port()).unwrap();

                buckets.push(Bucket::with_hash_key(addr, backend.weight as u32, hash_key));
                new_backends.push(backend.clone());
            }
        }

        KetamaHashing {
            ring: Continuum::new(&buckets),
            backends: new_backends,
        }
    }

    fn iter(self: &Arc<Self>, key: &[u8]) -> Self::Iter {
        OwnedNodeIterator {
            idx: self.ring.node_idx(key),
            ring: self.clone(),
            seen: HashSet::new(),
        }
    }
}

/// Iterator over a Continuum
pub struct OwnedNodeIterator {
    idx: usize,
    ring: Arc<KetamaHashing>,
    seen: HashSet<usize>,
}

impl BackendIter for OwnedNodeIterator {
    fn next(&mut self) -> Option<&Backend> {
        while let Some((node_idx, _addr)) = self.ring.ring.get_point(&mut self.idx) {
            if self.seen.insert(node_idx) {
                if let Some(backend) = self.ring.backends.get(node_idx) {
                    return Some(backend);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ketama() {
        let b1 = Backend::new("1.1.1.1:80").unwrap();
        let b2 = Backend::new("1.0.0.1:80").unwrap();
        let b3 = Backend::new("1.0.0.255:80").unwrap();
        let backends = BTreeSet::from_iter([b1.clone(), b2.clone(), b3.clone()]);
        let hash = Arc::new(KetamaHashing::build(&backends));

        let mut iter = hash.iter(b"test0");
        assert_eq!(iter.next(), Some(&b3));
        let mut iter = hash.iter(b"test1");
        assert_eq!(iter.next(), Some(&b3));
        let mut iter = hash.iter(b"test2");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test3");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test4");
        assert_eq!(iter.next(), Some(&b2));
        let mut iter = hash.iter(b"test5");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test6");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test7");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test8");
        assert_eq!(iter.next(), Some(&b2));
        let mut iter = hash.iter(b"test9");
        assert_eq!(iter.next(), Some(&b1));

        // remove b3
        let backends = BTreeSet::from_iter([b1.clone(), b2.clone()]);
        let hash = Arc::new(KetamaHashing::build(&backends));
        let mut iter = hash.iter(b"test0");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test1");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test2");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test3");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test4");
        assert_eq!(iter.next(), Some(&b2));
        let mut iter = hash.iter(b"test5");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test6");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test7");
        assert_eq!(iter.next(), Some(&b1));
        let mut iter = hash.iter(b"test8");
        assert_eq!(iter.next(), Some(&b2));
        let mut iter = hash.iter(b"test9");
        assert_eq!(iter.next(), Some(&b1));
    }

    #[test]
    fn test_ketama_includes_protocol() {
        use std::collections::HashSet;

        let tcp = Backend::new("10.0.0.1:443").unwrap();
        let udp_addr = "10.0.0.1:443".parse().unwrap();
        let udp = Backend::from_std_socket(udp_addr, 1, BackendProtocol::Udp);

        let backends = BTreeSet::from_iter([tcp.clone(), udp.clone()]);
        let hash = Arc::new(KetamaHashing::build(&backends));

        let mut iter = hash.iter(b"shared");
        let mut seen = HashSet::new();

        for _ in 0..4 {
            if let Some(backend) = iter.next() {
                seen.insert(backend.protocol);
                if seen.len() == 2 {
                    break;
                }
            } else {
                break;
            }
        }

        assert!(seen.contains(&BackendProtocol::Tcp));
        assert!(seen.contains(&BackendProtocol::Udp));
    }
}
