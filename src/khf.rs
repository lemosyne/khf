use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use inachus::Persist;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashSet, fmt};

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
#[derive(Deserialize, Serialize)]
pub struct Khf<R, H, const N: usize> {
    // The topology of a `Khf`.
    topology: Topology,
    // Tracks updated keys.
    updated_keys: HashSet<u64>,
    // The list of roots.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    roots: Vec<Node<H, N>>,
    // The number of keys a `Khf` currently provides.
    keys: u64,
    // The CSPRNG used to generate random keys and roots.
    #[serde(skip)]
    rng: R,
}

/// A list of different mechanisms, or ways, to consolidate a `Khf`.
pub enum Consolidation {
    /// Fully consolidate a `Khf` to a single root.
    Full,
    /// Consolidate roots corresponding to a range of keys in a `Khf`.
    Ranged { start: u64, end: u64 },
}

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Constructs a new `Khf`.
    pub fn new(mut rng: R, fanouts: &[u64]) -> Self {
        Self {
            topology: Topology::new(fanouts),
            updated_keys: HashSet::new(),
            roots: vec![Node::with_rng(&mut rng)],
            keys: 0,
            rng,
        }
    }

    /// Returns the number of roots in the `Khf`'s root list.
    pub fn fragmentation(&self) -> u64 {
        self.roots.len() as u64
    }

    /// Returns `true` if the `Khf` is consolidated.
    pub fn is_consolidated(&self) -> bool {
        self.roots.len() == 1 && self.roots[0].pos == (0, 0)
    }

    /// Consolidates the `Khf` and returns the affected keys.
    pub fn consolidate(&mut self, mechanism: Consolidation) -> Vec<u64> {
        match mechanism {
            Consolidation::Full => self.consolidate_full(),
            Consolidation::Ranged { start, end } => self.consolidate_ranged(start, end),
        }
    }

    // Consolidates back into a single root.
    fn consolidate_full(&mut self) -> Vec<u64> {
        let affected = (0..self.keys).into_iter().collect();

        // Restore the `Khf` back to a clean state.
        self.updated_keys.clear();
        self.roots = vec![Node::with_rng(&mut self.rng)];
        self.keys = 0;

        affected
    }

    // Consolidates the roots for a range of keys.
    fn consolidate_ranged(&mut self, start: u64, end: u64) -> Vec<u64> {
        let affected = (start..end).into_iter().collect();

        // Make sure we cover the range of keys.
        if self.keys < end {
            self.append_key(end);
        }

        // "Update" the range of keys.
        self.update_keys(start, end);

        // The consolidated range of keys shouldn't be considered as updated.
        for key in &affected {
            self.updated_keys.remove(key);
        }

        affected
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
        // The roots will be derived from a new, random root.
        let root = Node::with_rng(&mut self.rng);
        let needed = self.topology.descendants(1) - (self.keys % self.topology.descendants(1));
        self.roots
            .append(&mut root.coverage(&self.topology, self.keys, self.keys + needed));
        self.keys += needed;

        // Add L1 roots until we have one that covers the desired key.
        while self.keys < key {
            let pos = (1, self.keys / self.topology.descendants(1));
            let key = root.derive(&self.topology, pos);
            self.roots.push(Node::with_pos(pos, key));
            self.keys += self.topology.descendants(1);
        }

        self.derive_key(key)
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

    /// Updates a range of keys using the forest's root for updated keys.
    fn update_keys(&mut self, start: u64, end: u64) {
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

        // Save roots before the first root affected by the update.
        roots.extend(&mut self.roots.drain(..update_start));

        // Added updated roots derived from a new random root.
        let root = Node::with_rng(&mut self.rng);
        updated.append(&mut root.coverage(&self.topology, start, end));

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
        self.updated_keys.extend(start..end);
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
        // Two cases for key derivation:
        //  1) The key needs to be appended.
        //  2) The key already exists in the root list.
        if key >= self.keys {
            Ok(self.append_key(key))
        } else {
            Ok(self.derive_key(key))
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Append the key if we don't cover it yet.
        if key >= self.keys {
            self.append_key(key);
        }

        // It's a pity that we must fragment the tree here for security.
        self.update_keys(key, key + 1);

        Ok(self.derive_key(key))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        let updated = self.updated_keys.clone();
        self.updated_keys.clear();
        updated.into_iter().collect()
    }
}

impl<Io: Read + Write, R, H, const N: usize> Persist<Io> for Khf<R, H, N>
where
    R: Default,
{
    type Init = R;

    fn persist(&mut self, mut sink: Io) -> Result<(), Io::Error> {
        // TODO: Stream serialization.
        let ser = bincode::serialize(&self).unwrap();
        sink.write_all(&ser)
    }

    fn load(mut source: Io) -> Result<Self, Io::Error> {
        // TODO: Stream deserialization.
        let mut raw = vec![];
        source.read_to_end(&mut raw)?;
        Ok(bincode::deserialize(&raw).unwrap())
    }
}

impl<R, H, const N: usize> fmt::Display for Khf<R, H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, root) in self.roots.iter().enumerate() {
            root.fmt(f, &self.topology)?;
            if i + 1 != self.roots.len() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
