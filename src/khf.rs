use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use itertools::Itertools;
use kms::{KeyManagementScheme, Persist};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet, fmt};

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
pub struct Khf<R, H, const N: usize> {
    // The public state of a `Khf`.
    state: KhfState<H, N>,
    // The CSPRNG used to generate random keys and roots.
    rng: R,
}

#[derive(Deserialize, Serialize)]
struct KhfState<H, const N: usize> {
    // The topology of a `Khf`.
    topology: Topology,
    // The root that updated keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    updated_key_root: Node<H, N>,
    // The root that appended keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    appended_key_root: Node<H, N>,
    // Tracks updated keys.
    updated_keys: BTreeSet<u64>,
    // The list of roots.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    roots: Vec<Node<H, N>>,
    // The number of keys a `Khf` currently provides.
    keys: u64,
}

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Construct a new KHF using the given rng
    pub fn new(mut rng: R, fanouts: &[u64]) -> Self {
        Self {
            state: KhfState {
                topology: Topology::new(&fanouts),
                updated_key_root: Self::random_root(&mut rng),
                appended_key_root: Self::random_root(&mut rng),
                updated_keys: BTreeSet::new(),
                roots: vec![],
                keys: 0,
            },
            rng,
        }
    }

    /// Returns a key filled with bytes from the supplied CSPRNG.
    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    /// Returns a root with a pseudorandom key.
    fn random_root(rng: &mut R) -> Node<H, N> {
        Node::new(Self::random_key(rng))
    }

    /// Returns the number of roots in the forest's root list.
    pub fn fragmentation(&self) -> u64 {
        self.state.roots.len() as u64
    }
}

impl<H, const N: usize> KhfState<H, N>
where
    H: Hasher<N>,
{
    /// Returns `true` if the forest is consolidated.
    fn is_consolidated(&self) -> bool {
        self.roots.len() == 1 && self.roots[0].pos == (0, 0)
    }

    /// Appends a key, deriving it from the root for appended keys.
    fn append_key(&mut self, key: u64) -> Key<N> {
        // No need to append additional roots the forest is already consolidated.
        if self.is_consolidated() {
            self.keys = self.keys.max(key);
            return self.roots[0].derive(&self.topology, self.topology.leaf_position(key));
        }

        // First, add any roots needed to reach a full L1 root.
        // For example: assume a topology of [4] and the following roots:
        //
        // (2,0) (2,1)
        //
        // Then we will need 2 additional roots to reach a full L1.
        //
        //          (1,0)
        //            |
        //   +-----+--+--+-----+
        //   |     |     |     |
        // (2,0) (2,1) (2,2) (2,3)
        //
        // Doing this will allow us to append more keys later by simply adding L1 roots.
        let needed = self.topology.descendants(1) - (self.keys % self.topology.descendants(1));
        self.roots.append(&mut self.appended_key_root.coverage(
            &self.topology,
            self.keys,
            self.keys + needed,
        ));
        self.keys += needed;

        // Add L1 roots until we have one that covers the desired key.
        while self.keys < key {
            let pos = (1, self.keys / self.topology.descendants(1));
            let key = self.appended_key_root.derive(&self.topology, pos);
            self.roots.push(Node::with_pos(pos, key));
            self.keys += self.topology.descendants(1);
        }

        self.derive_key(key)
    }

    /// Updates a key, deriving it from the root for updated keys.
    fn update_key(&mut self, key: u64) -> Key<N> {
        self.updated_keys.insert(key);
        self.updated_key_root
            .derive(&self.topology, self.topology.leaf_position(key))
    }

    /// Derives a key from an existing root in the root list.
    fn derive_key(&mut self, key: u64) -> Key<N> {
        let pos = self.topology.leaf_position(key);
        let index = self
            .roots
            .binary_search_by(|root| {
                if self.topology.is_ancestor(root.pos, pos) {
                    Ordering::Equal
                } else if self.topology.end(root.pos) <= self.topology.start(pos) {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            })
            .unwrap();
        self.roots[index].derive(&self.topology, pos)
    }

    /// Returns a `Vec` of ranges of updated keys.
    fn updated_ranges(&self) -> Vec<(u64, u64)> {
        self.updated_keys
            .iter()
            .peekable()
            .batching(|it| match it.peek() {
                Some(&key) => {
                    let num_keys = it
                        .enumerate()
                        .map(|(i, nkey)| (i as u64, nkey))
                        .peekable()
                        .peeking_take_while(|(i, nkey)| key + *i + 1 == **nkey)
                        .count() as u64;
                    Some((*key, key + num_keys + 1))
                }
                None => None,
            })
            .collect()
    }

    /// Updates a range of keys using the forest's root for updated keys.
    fn update_range(&mut self, start: u64, end: u64) {
        // Updates cause consolidated forests to fragment.
        if self.is_consolidated() {
            if self.keys == 0 {
                self.keys = end;
            }
            self.roots = self.roots[0].coverage(&self.topology, 0, self.keys + 1);
        }

        // We need to create a new set of roots and store updated roots.
        let mut roots = Vec::new();
        let mut updated = Vec::new();

        // Find the first root affected by the update.
        let update_start = self
            .roots
            .iter()
            .position(|root| start < self.topology.end(root.pos))
            .unwrap_or(self.roots.len() - 1);
        let update_root = &self.roots[update_start];
        if self.topology.start(update_root.pos) != start {
            updated.append(&mut update_root.coverage(
                &self.topology,
                self.topology.start(update_root.pos),
                start,
            ));
        }

        // Save roots before the first root affected by the update, then add the updated roots.
        roots.extend(&mut self.roots.drain(..update_start));
        updated.append(&mut self.updated_key_root.coverage(&self.topology, start, end));

        // Find the last root affected by the update.
        let mut update_end = self.roots.len();
        if end < self.topology.end(self.roots[self.roots.len() - 1].pos) {
            update_end = self
                .roots
                .iter()
                .position(|root| end <= self.topology.end(root.pos))
                .unwrap_or(self.roots.len())
                + 1;
            let update_root = &self.roots[update_end - 1];
            if self.topology.end(update_root.pos) != end {
                updated.append(&mut update_root.coverage(
                    &self.topology,
                    end,
                    self.topology.end(update_root.pos),
                ));
            }
        }

        // Save the updated roots and add any remaining roots.
        roots.append(&mut updated);
        roots.extend(&mut self.roots.drain(update_end..));

        // Update roots and number of keys.
        self.roots = roots;
        self.keys = self.topology.end(self.roots.last().unwrap().pos);
    }
}

impl<'a, 'b, R, H, const N: usize> KeyManagementScheme for Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Keys have the same size as the hash digest size.
    type Key = Key<N>;
    /// Keys are uniquely identified with `u64`s.
    type KeyId = u64;
    /// Bespoke error type.
    type Error = Error;

    fn derive(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Three cases for any key derivation:
        //  1) The key has been updated.
        //  2) The key needs to be appended.
        //  3) The key already exists in the root list.
        if self.state.updated_keys.contains(&key) {
            Ok(self.state.update_key(key))
        } else if key >= self.state.keys {
            Ok(self.state.append_key(key))
        } else {
            Ok(self.state.derive_key(key))
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Append keys if we don't cover the key yet.
        if key >= self.state.keys {
            self.state.append_key(key);
        }
        Ok(self.state.update_key(key))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        let mut changed = vec![];

        for (start, end) in self.state.updated_ranges() {
            self.state.update_range(start, end);
            changed.extend(start..end);
        }
        self.state.updated_key_root = Self::random_root(&mut self.rng);
        self.state.appended_key_root = Self::random_root(&mut self.rng);
        self.state.updated_keys.clear();

        changed
    }
}

impl<Io: Read + Write, R, H, const N: usize> Persist<Io> for Khf<R, H, N> {
    type Init = R;

    fn persist(&mut self, mut sink: Io) -> Result<(), Io::Error> {
        // TODO: stream serialization
        let ser = bincode::serialize(&self.state).unwrap();
        sink.write_all(&ser)
    }

    fn load(rng: Self::Init, mut source: Io) -> Result<Self, Io::Error> {
        let mut raw = vec![];
        loop {
            let mut block = [0; 0x4000];
            let n = source.read(&mut block)?;

            if n == 0 {
                break;
            }

            raw.extend(&block[..n]);
        }

        // TODO: stream serialization
        Ok(Khf {
            state: bincode::deserialize(&raw).unwrap(),
            rng,
        })
    }
}

impl<R, H, const N: usize> fmt::Display for Khf<R, H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, root) in self.state.roots.iter().enumerate() {
            root.fmt(f, &self.state.topology)?;
            if i + 1 != self.state.roots.len() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
