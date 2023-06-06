use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use kms::KeyManagementScheme;
use persistence::Persist;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashSet, fmt};

/// The default level for roots created when mutating a `Khf`.
const DEFAULT_ROOT_LEVEL: u64 = 1;

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
#[derive(Deserialize, Serialize, Clone)]
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
    // The CSPRNG used to generate random roots.
    #[serde(skip)]
    rng: R,
}

/// A list of different mechanisms, or ways, to consolidate a `Khf`.
pub enum Consolidation {
    /// Consolidate a `Khf` to a single root.
    Full,
    /// Consolidate a `Khf` to roots of a certain level.
    Leveled { level: u64 },
    /// Consolidate roots corresponding to a range of keys in a `Khf`.
    Ranged { start: u64, end: u64 },
    /// Consolidate roots to a certain level corresponding to a range of keys in a `Khf`.
    RangedLeveled { level: u64, start: u64, end: u64 },
}

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Constructs a new `Khf`.
    pub fn new(fanouts: &[u64], mut rng: R) -> Self {
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
            Consolidation::Leveled { level } => self.consolidate_leveled(level),
            Consolidation::Ranged { start, end } => self.consolidate_ranged(start, end),
            Consolidation::RangedLeveled { level, start, end } => {
                self.consolidate_ranged_leveled(level, start, end)
            }
        }
    }

    // Consolidates back into a single root.
    fn consolidate_full(&mut self) -> Vec<u64> {
        self.consolidate_leveled(0)
    }

    // Consolidates to roots of a certain level.
    fn consolidate_leveled(&mut self, level: u64) -> Vec<u64> {
        let affected = (0..self.keys).into_iter().collect();

        // Unmark keys as updated and update the whole range of keys.
        self.updated_keys.clear();
        self.update_keys(level, 0, self.keys);

        affected
    }

    // Consolidates the roots for a range of keys.
    fn consolidate_ranged(&mut self, start: u64, end: u64) -> Vec<u64> {
        self.consolidate_ranged_leveled(DEFAULT_ROOT_LEVEL, start, end)
    }

    // Consolidates the roots for a range of keys to roots of a certain level.
    fn consolidate_ranged_leveled(&mut self, level: u64, start: u64, end: u64) -> Vec<u64> {
        let affected = (start..end).into_iter().collect();

        // Make sure we cover the range of keys.
        if self.keys < end {
            self.append_key(level, end);
        }

        // "Update" the range of keys.
        self.update_keys(level, start, end);

        // The consolidated range of keys shouldn't be considered as updated.
        for key in &affected {
            self.updated_keys.remove(key);
        }

        affected
    }

    /// Truncates the `Khf` so it only covers a specified number of keys.
    pub fn truncate(&mut self, keys: u64) {
        // Mark new number of keys if consolidated and we already cover some keys.
        if self.is_consolidated() {
            if self.keys > 0 && keys < self.keys {
                self.keys = keys;
                self.roots =
                    self.roots[0].coverage(&self.topology, DEFAULT_ROOT_LEVEL, 0, self.keys);
            }
            return;
        }

        // Can't truncate to a larger amount of keys.
        if keys >= self.keys {
            return;
        }

        // TODO: is there a better way to find this?
        let index = self
            .roots
            .iter()
            .position(|root| self.topology.end(root.pos) > keys)
            .unwrap();
        let start = self.topology.start(self.roots[index].pos);
        let root = self.roots.drain(index..).next().unwrap();

        // Update keys and roots.
        self.keys = keys;
        self.roots
            .append(&mut root.coverage(&self.topology, DEFAULT_ROOT_LEVEL, start, keys))
    }

    /// Appends a key, appending roots as necessary from the specified level.
    fn append_key(&mut self, level: u64, key: u64) -> Key<N> {
        // No need to append additional roots if the forest is already consolidated.
        if self.is_consolidated() {
            self.keys = self.keys.max(key + 1);
            return self.roots[0].derive(&self.topology, self.topology.leaf_position(key));
        }

        let root = Node::with_rng(&mut self.rng);
        self.roots
            .append(&mut root.coverage(&self.topology, level, self.keys, key + 1));
        self.keys = self.keys.max(key + 1);

        // First, add any roots needed to reach a full root of the specified level.
        // For example: assume a topology of [4], a target of L1, and the following roots:
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
        // This allows us to append more keys later by adding roots of the specified level.
        //
        // First, compute the number of keys needed to reach a full root of the specified level.
        // let needed =
        //     self.topology.descendants(level) - (self.keys % self.topology.descendants(level));
        // self.keys += needed;

        // // Then, add in the roots of the specified level (each derived from a random root).
        // let root = Node::with_rng(&mut self.rng);
        // self.roots
        //     .append(&mut root.coverage(&self.topology, level, self.keys, self.keys + needed));

        // // Add roots of the specified level until we have one that covers the desired key.
        // while self.keys < key {
        //     let pos = (level, self.keys / self.topology.descendants(level));
        //     let key = root.derive(&self.topology, pos);
        //     self.roots.push(Node::with_pos(pos, key));
        //     self.keys += self.topology.descendants(level);
        // }

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
    fn update_keys(&mut self, level: u64, start: u64, end: u64) {
        // Level 0 means consolidating to a single root.
        if level == 0 {
            self.roots = vec![Node::with_rng(&mut self.rng)];
            self.keys = end;
            self.updated_keys.extend(start..end);
            return;
        }

        // Updates cause consolidated forests to fragment.
        if self.is_consolidated() {
            self.keys = self.keys.max(end);
            self.roots = self.roots[0].coverage(&self.topology, level, 0, self.keys);
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
                level,
                self.topology.start(update_root.pos),
                start,
            ));
        }

        // Save roots before the first root affected by the update.
        roots.extend(&mut self.roots.drain(..update_start));

        // Added updated roots derived from a new random root.
        let root = Node::with_rng(&mut self.rng);
        updated.append(&mut root.coverage(&self.topology, level, start, end));

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
                    level,
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
        self.updated_keys.extend(start..end);
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
            Ok(self.append_key(DEFAULT_ROOT_LEVEL, key))
        } else {
            Ok(self.derive_key(key))
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Append the key if we don't cover it yet.
        if key >= self.keys {
            self.append_key(DEFAULT_ROOT_LEVEL, key);
        }

        // It's a pity that we must fragment the tree here for security.
        self.update_keys(DEFAULT_ROOT_LEVEL, key, key + 1);

        Ok(self.derive_key(key))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        self.updated_keys.drain().collect()
    }
}

impl<Io, R, H, const N: usize> Persist<Io> for Khf<R, H, N>
where
    R: Default,
    Io: Read + Write,
{
    type Error = Error;

    fn persist(&mut self, mut sink: Io) -> Result<(), Self::Error> {
        // TODO: Stream serialization.
        let ser = bincode::serialize(&self)?;
        sink.write_all(&ser).map_err(|_| Error::Io)
    }

    fn load(mut source: Io) -> Result<Self, Self::Error> {
        // TODO: Stream deserialization.
        let mut raw = vec![];
        source.read_to_end(&mut raw).map_err(|_| Error::Io)?;
        Ok(bincode::deserialize(&raw)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use hasher::openssl::*;
    use rand::rngs::ThreadRng;

    #[test]
    fn it_works() {
        let mut khf =
            Khf::<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::new(&[2, 2], ThreadRng::default());
        let key = khf.update(0);
        let key = khf.derive(1);
    }
}
