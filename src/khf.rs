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
    // The number of keys in flight.
    #[serde(skip)]
    in_flight_keys: u64,
    // Tracks updated keys.
    #[serde(skip)]
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
            in_flight_keys: 0,
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

    /// The keys that have been updated since the last epoch
    pub fn updated_keys(&self) -> &BTreeSet<u64> {
        &self.updated_keys
    }

    /// The keys that have been updated since the last epoch
    pub fn updated_keys_mut(&mut self) -> &mut BTreeSet<u64> {
        &mut self.updated_keys
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

        let node = Node::with_rng(&mut self.rng);
        self.replace_keys(level, 0, self.keys, &node);

        // Unmark keys as updated and update the whole range of keys.
        self.updated_keys.clear();

        affected
    }

    // Consolidates the roots for a range of keys.
    fn consolidate_ranged(&mut self, start: u64, end: u64) -> Vec<u64> {
        self.consolidate_ranged_leveled(DEFAULT_ROOT_LEVEL, start, end)
    }

    // Consolidates the roots for a range of keys to roots of a certain level.
    fn consolidate_ranged_leveled(&mut self, level: u64, start: u64, end: u64) -> Vec<u64> {
        let affected = (start..end).into_iter().collect();

        // Update the range of keys.
        let node = Node::with_rng(&mut self.rng);
        self.replace_keys(level, start, end, &node);

        // The consolidated range of keys shouldn't be considered as updated.
        for key in &affected {
            self.updated_keys.remove(key);
        }

        affected
    }

    /// Truncates the `Khf` so it only covers a specified number of keys.
    pub fn truncate(&mut self, keys: u64) {
        self.in_flight_keys = keys;
    }

    /// Derives a key.
    fn derive_key(&mut self, key: u64) -> Key<N> {
        let pos = self.topology.leaf_position(key);

        // Derive the key from the appending root if it should be appended.
        if key >= self.keys {
            self.in_flight_keys = key;
            return self.appending_root.derive(&self.topology, pos);
        }

        // Binary search for the index of the root covering the key.
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

    /// Updates a key.
    fn update_key(&mut self, key: u64) -> Key<N> {
        self.updated_keys.insert(key);
        self.derive_key(key)
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

    /// Replaces a range of keys with keys derived from a given root.
    fn replace_keys(&mut self, level: u64, start: u64, end: u64, root: &Node<H, N>) {
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

        // Add replacement roots derived from the given root.
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
        self.roots = roots;
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
        Ok(self.update_key(key))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        let mut updated_keys = vec![];

        if self.in_flight_keys >= self.keys {
            // Fragment in the appended keys if we're not consolidated.
            if !self.is_consolidated() {
                self.replace_keys(
                    DEFAULT_ROOT_LEVEL,
                    self.keys,
                    self.in_flight_keys,
                    &self.appending_root.clone(),
                );
            }

            // Fragment in updated keys.
            let updating_root = Node::with_rng(&mut self.rng);
            for (start, end) in self.updated_key_ranges() {
                self.replace_keys(DEFAULT_ROOT_LEVEL, start, end, &updating_root);
                updated_keys.extend(start..end);
            }
        } else {
            // If we're consolidated, we'll just truncate using the top level root. Otherwise, we
            // need to find the root that covers the last key and truncate it.
            if self.is_consolidated() {
                self.roots = self.roots[0].coverage(
                    &self.topology,
                    DEFAULT_ROOT_LEVEL,
                    0,
                    self.in_flight_keys,
                );
            } else {
                let index = self
                    .roots
                    .iter()
                    .position(|root| self.topology.end(root.pos) > self.in_flight_keys)
                    .unwrap();
                let start = self.topology.start(self.roots[index].pos);
                let root = self.roots.drain(index..).next().unwrap();

                self.roots.append(&mut root.coverage(
                    &self.topology,
                    DEFAULT_ROOT_LEVEL,
                    start,
                    self.in_flight_keys,
                ))
            }
        }

        // Clear updated keys and get a new updating root and appending root.
        self.updated_keys.clear();
        self.appending_root = Node::with_rng(&mut self.rng);
        self.keys = self.in_flight_keys;

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
