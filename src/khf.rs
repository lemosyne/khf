use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use kms::KeyManagementScheme;
use persistence::Persist;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet, fmt};

/// The default level for roots created when mutating a `Khf`.
const DEFAULT_ROOT_LEVEL: u64 = 1;

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
#[derive(Deserialize, Serialize)]
pub struct Khf<R, H, const N: usize> {
    // The topology of a `Khf`.
    topology: Topology,
    // Root that appended keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    appending_root: Node<H, N>,
    // Root that updated keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    updating_root: Node<H, N>,
    // Tracks updated keys.
    updated_keys: BTreeSet<u64>,
    // The list of roots.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    roots: Vec<Node<H, N>>,
    // The number of keys a `Khf` currently provides.
    pub(crate) keys: u64,
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
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    /// Constructs a new `Khf`.
    pub fn new(fanouts: &[u64], mut rng: R) -> Self {
        Self {
            topology: Topology::new(fanouts),
            appending_root: Node::with_rng(&mut rng),
            updating_root: Node::with_rng(&mut rng),
            updated_keys: BTreeSet::new(),
            roots: vec![Node::with_rng(&mut rng)],
            keys: 0,
            rng: rng.clone(),
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

    /// Returns the keys that have been updated since the last epoch
    pub fn updated_keys(&self) -> &BTreeSet<u64> {
        &self.updated_keys
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
        // Commit any pending changes before we truncate.
        if !self.updated_keys.is_empty() {
            self.commit();
        }

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

        // Append new roots to cover appended keys.
        self.roots.append(&mut self.appending_root.coverage(
            &self.topology,
            level,
            self.keys,
            key + 1,
        ));

        // Update the number of keys.
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

    /// Derives a key.
    fn derive_key(&mut self, key: u64) -> Key<N> {
        let pos = self.topology.leaf_position(key);

        // We may have updated this key.
        if self.updated_keys.contains(&key) {
            return self.updating_root.derive(&self.topology, pos);
        }

        // Append the key if we don't cover it yet.
        if key >= self.keys {
            return self.append_key(DEFAULT_ROOT_LEVEL, key);
        }

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

    fn updated_key_ranges(&self) -> Vec<(u64, u64)> {
        if self.updated_keys.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut first = true;
        let mut start = 0;
        let mut prev = 0;
        let mut leaves = 1;

        for leaf in &self.updated_keys {
            if first {
                first = false;
                start = *leaf;
            } else if *leaf == prev + 1 {
                leaves += 1;
            } else {
                ranges.push((start, start + leaves));
                leaves = 1;
                start = *leaf;
            }
            prev = *leaf;
        }

        ranges.push((start, start + leaves));
        ranges
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

        // Add updated roots derived from the updating root.
        updated.append(
            &mut self
                .updating_root
                .coverage(&self.topology, level, start, end),
        );

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
    R: RngCore + CryptoRng + Clone,
    H: Hasher<N>,
{
    /// Keys have the same size as the hash digest size.
    type Key = Key<N>;
    /// Keys are uniquely identified with `u64`s.
    type KeyId = u64;
    /// Bespoke error type.
    type Error = Error;

    fn derive(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        Ok(self.derive_key(key))
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // It's possible that we update a key that isn't yet in our root list, so we first append
        // it to ensure that we will still have a valid root list.
        if key >= self.keys {
            self.append_key(DEFAULT_ROOT_LEVEL, key);
        }

        // We delay the fragmentation of the `Khf` until it is committed. This assumes that the
        // resultant key is properly used (i.e., with a unique nonce).
        self.keys = self.keys.max(key + 1);
        self.updated_keys.insert(key);
        Ok(self
            .updating_root
            .derive(&self.topology, self.topology.leaf_position(key)))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        let mut updated_keys = vec![];

        // Update keys in each of the updated key ranges.
        for (start, end) in self.updated_key_ranges() {
            self.update_keys(DEFAULT_ROOT_LEVEL, start, end);
            updated_keys.extend(start..end);
        }

        // Clear updated keys and get a new updating root and appending root.
        self.updated_keys.clear();
        self.updating_root = Node::with_rng(&mut self.rng);
        self.appending_root = Node::with_rng(&mut self.rng);

        updated_keys
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
    use anyhow::Result;
    use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
    use rand::{rngs::ThreadRng, thread_rng};

    #[test]
    fn it_works() -> Result<()> {
        let mut khf = Khf::<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::new(&[2, 2], thread_rng());

        // We start off with one root.
        assert_eq!(khf.fragmentation(), 1);

        // Deriving any key is strictly an append, so no additional fragmentation.
        let key4 = khf.derive(4)?;
        assert_eq!(khf.fragmentation(), 1);

        // Updating keys won't cause fragmentation until commit.
        let key1 = khf.update(1)?;
        let key2 = khf.update(2)?;
        assert_eq!(khf.fragmentation(), 1);

        // Committing should yield the two updated keys.
        assert_eq!(vec![1, 2], khf.commit());

        // The `Khf` should be entirely fragmented now.
        // This means we should have 5 roots since we have keys [0..4].
        assert_eq!(khf.fragmentation(), 5);

        // We should be able to derive the previously derived/updated keys.
        let key1_updated = khf.derive(1)?;
        let key2_updated = khf.derive(2)?;
        let key4_rederived = khf.derive(4)?;
        assert_eq!(key1, key1_updated);
        assert_eq!(key2, key2_updated);
        assert_eq!(key4, key4_rederived);

        // Deriving appended keys now should cause fragmentation.
        // 0 1 2 3 4 5 [6 7] [[8 9] [10 11]]
        let key11 = khf.derive(11)?;
        assert_eq!(khf.fragmentation(), 8);

        // Committing should yield no keys.
        assert!(khf.commit().is_empty());

        // We can update a key we don't yet cover and still derive appended keys in between.
        // 0 1 2 3 4 5 [6 7] [[8 9] [10 11]] [[12 13] [14 15]]
        let key15 = khf.update(15)?;
        let key15_derived = khf.derive(15)?;
        let key13 = khf.derive(13)?;
        assert_eq!(khf.keys, 16);
        assert_eq!(key15, key15_derived);
        assert_eq!(khf.fragmentation(), 9);

        // Committing should yield the one update key.
        assert_eq!(vec![15], khf.commit());

        // We can still derive the old stuff.
        let key11_rederived = khf.derive(11)?;
        let key13_rederived = khf.derive(13)?;
        let key15_rederived = khf.derive(15)?;
        assert_eq!(key11, key11_rederived);
        assert_eq!(key13, key13_rederived);
        assert_eq!(key15, key15_rederived);

        // One more check on appending.
        // 0 1 2 3 4 5 [6 7] [[8 9] [10 11]] [12 13] 14 15 16
        let key16 = khf.derive(16)?;
        assert_eq!(khf.fragmentation(), 12);

        // Committing should yield no keys.
        assert!(khf.commit().is_empty());

        let key16_rederived = khf.derive(16)?;
        assert_eq!(key16, key16_rederived);

        Ok(())
    }
}
