use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use hasher::Hasher;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    fmt,
};

/// The default level for roots created when mutating a `Khf`.
const DEFAULT_ROOT_LEVEL: u64 = 1;

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
#[derive(Deserialize, Serialize)]
pub struct Khf<H, const N: usize> {
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
    keys: u64,
    // Holds keys computed between commits
    #[serde(skip)]
    cached_keys: HashMap<u64, Key<N>>,
}

impl<H, const N: usize> Clone for Khf<H, N> {
    fn clone(&self) -> Self {
        Self {
            topology: self.topology.clone(),
            appending_root: self.appending_root.clone(),
            in_flight_keys: self.in_flight_keys,
            updated_keys: self.updated_keys.clone(),
            roots: self.roots.clone(),
            keys: self.keys,
            cached_keys: self.cached_keys.clone(),
        }
    }
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

impl<H, const N: usize> Khf<H, N>
where
    H: Hasher<N>,
{
    /// Constructs a new `Khf`.
    pub fn new(fanouts: &[u64], mut rng: impl RngCore + CryptoRng) -> Self {
        Self {
            topology: Topology::new(fanouts),
            appending_root: Node::with_rng(&mut rng),
            in_flight_keys: 0,
            updated_keys: BTreeSet::new(),
            roots: vec![Node::with_rng(&mut rng)],
            keys: 0,
            cached_keys: HashMap::new(),
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
    pub fn consolidate(
        &mut self,
        mechanism: Consolidation,
        rng: impl RngCore + CryptoRng,
    ) -> Vec<u64> {
        match mechanism {
            Consolidation::Full => self.consolidate_full(rng),
            Consolidation::Leveled { level } => self.consolidate_leveled(level, rng),
            Consolidation::Ranged { start, end } => self.consolidate_ranged(start, end, rng),
            Consolidation::RangedLeveled { level, start, end } => {
                self.consolidate_ranged_leveled(level, start, end, rng)
            }
        }
    }

    // Consolidates back into a single root.
    fn consolidate_full(&mut self, rng: impl RngCore + CryptoRng) -> Vec<u64> {
        self.consolidate_leveled(0, rng)
    }

    // Consolidates to roots of a certain level.
    fn consolidate_leveled(&mut self, level: u64, mut rng: impl RngCore + CryptoRng) -> Vec<u64> {
        let affected = (0..self.keys).into_iter().collect();

        let node = Node::with_rng(&mut rng);
        self.replace_keys(level, 0, self.keys, node);

        // Unmark keys as updated and update the whole range of keys.
        self.updated_keys.clear();

        affected
    }

    // Consolidates the roots for a range of keys.
    fn consolidate_ranged(
        &mut self,
        start: u64,
        end: u64,
        rng: impl RngCore + CryptoRng,
    ) -> Vec<u64> {
        self.consolidate_ranged_leveled(DEFAULT_ROOT_LEVEL, start, end, rng)
    }

    // Consolidates the roots for a range of keys to roots of a certain level.
    fn consolidate_ranged_leveled(
        &mut self,
        level: u64,
        start: u64,
        end: u64,
        mut rng: impl RngCore + CryptoRng,
    ) -> Vec<u64> {
        let affected = (start..end).into_iter().collect();

        // Update the range of keys.
        let node = Node::with_rng(&mut rng);
        self.replace_keys(level, start, end, node);

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
            self.in_flight_keys = self.in_flight_keys.max(key + 1);
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

    fn derive_key_immutable(&self, key: u64) -> Key<N> {
        if let Some(key) = self.cached_keys.get(&key) {
            return *key;
        }

        let pos = self.topology.leaf_position(key);

        // Derive the key from the appending root if it should be appended.
        if key >= self.keys {
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
    fn replace_keys(&mut self, level: u64, start: u64, end: u64, root: Node<H, N>) {
        // Level 0 means consolidating to a single root.
        if level == 0 {
            self.roots = vec![root];
            return;
        }

        // Fragment the forest to cover all the keys.
        if self.is_consolidated() {
            self.roots =
                self.roots[0].coverage(&self.topology, level, 0, self.in_flight_keys.max(end));
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

impl<H, const N: usize> KeyManagementScheme for Khf<H, N>
where
    H: Hasher<N>,
{
    /// Keys have the same size as the hash digest size.
    type Key = Key<N>;
    /// Keys are uniquely identified with `u64`s.
    type KeyId = u64;
    /// Bespoke error type.
    type Error = Error;

    fn derive(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        if let Some(k) = self.cached_keys.get(&key) {
            Ok(*k)
        } else {
            let k = self.derive_key(key);
            self.cached_keys.insert(key, k);
            Ok(k)
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        self.updated_keys.insert(key);
        self.derive(key)
    }

    fn commit(
        &mut self,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<(Self::KeyId, Self::Key)>, Self::Error> {
        // We're effectively getting rid of the tree, so consolidate to a new root.
        let res = if self.in_flight_keys == 0 {
            let res = self
                .updated_keys
                .iter()
                .map(|block| (*block, self.derive_key_immutable(*block)))
                .collect();

            let node = Node::with_rng(&mut rng);
            self.replace_keys(0, 0, 0, node);

            res
        }
        // We need to append keys.
        else if self.in_flight_keys >= self.keys {
            // If we've updated every single key since the last commit, we can consolidate
            // everything to a new root.
            if self.updated_keys.len() as u64 == self.in_flight_keys {
                let res = self
                    .updated_keys
                    .iter()
                    .map(|block| (*block, self.derive_key_immutable(*block)))
                    .collect();

                let node = Node::with_rng(&mut rng);
                self.replace_keys(0, 0, 0, node);

                res
            }
            // Otherwise, we need to fragment in appended keys and then updated keys.
            else {
                let res = self
                    .updated_keys
                    .iter()
                    .map(|block| (*block, self.derive_key_immutable(*block)))
                    .collect();

                // Fragment in the appended keys.
                self.replace_keys(
                    DEFAULT_ROOT_LEVEL,
                    self.keys,
                    self.in_flight_keys,
                    self.appending_root.clone(),
                );

                // Fragment in updated keys.
                for (start, end) in self.updated_key_ranges() {
                    let node = Node::with_rng(&mut rng);
                    self.replace_keys(DEFAULT_ROOT_LEVEL, start, end, node);
                }

                res
            }
        }
        // We need to truncate keys.
        else {
            // We can forget about updated keys that have been truncated.
            self.updated_keys.retain(|key| *key < self.in_flight_keys);

            // If we've touched every key post-truncation, we can just consolidate to a new root.
            if self.updated_keys.len() as u64 == self.in_flight_keys {
                let res = self
                    .updated_keys
                    .iter()
                    .map(|block| (*block, self.derive_key_immutable(*block)))
                    .collect();

                let node = Node::with_rng(&mut rng);
                self.replace_keys(0, 0, 0, node);

                res
            }
            // Otherwise, we'll need to actually truncate something.
            else {
                // If we're consolidated, we'll just truncate using the top level root.
                if self.is_consolidated() {
                    let res = self
                        .updated_keys
                        .iter()
                        .map(|block| (*block, self.derive_key_immutable(*block)))
                        .collect();

                    self.roots = self.roots[0].coverage(
                        &self.topology,
                        DEFAULT_ROOT_LEVEL,
                        0,
                        self.in_flight_keys,
                    );

                    res
                }
                // Otherwise, we need to find the root that covers the last key and truncate it.
                else {
                    let res = self
                        .updated_keys
                        .iter()
                        .map(|block| (*block, self.derive_key_immutable(*block)))
                        .collect();

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
                    ));

                    res
                }
            }
        };

        // Clear out our cache.
        self.cached_keys.clear();

        // Get a new appending root, and update our known number of keys.
        self.appending_root = Node::with_rng(&mut rng);
        self.keys = self.in_flight_keys;

        // Clear out the updated keys.
        self.updated_keys.clear();

        Ok(res)
    }
}

impl<H, const N: usize> fmt::Display for Khf<H, N>
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
    use hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE};
    // use rand::rngs::ThreadRng;

    // #[test]
    // fn it_works() -> Result<()> {
    //     let mut rng = ThreadRng::default();
    //     let mut khf = Khf::<Sha3_256, SHA3_256_MD_SIZE>::new(&[2, 2], &mut rng);

    //     // We'll check that we can re-derive this after commit.
    //     let key4 = khf.derive(4)?;

    //     // Keys updated/derived during the same epoch should be the same.
    //     let key5 = khf.derive(5)?;
    //     let key5_updated = khf.update(5)?;
    //     assert_eq!(key5, key5_updated);
    //     assert_eq!(khf.commit(&mut rng)?, vec![(5, key5)]);

    //     // Should still be able to derive old keys, but not updated keys.
    //     let key4_rederived = khf.derive(4)?;
    //     let key5_rederived = khf.derive(5)?;
    //     assert_eq!(key4, key4_rederived);
    //     assert_ne!(key5, key5_rederived);

    //     // Truncating down to 2 keys won't change the value of keys derived before the next commit.
    //     // It will also get rid of any prior updates to larger keys.
    //     khf.update(5)?;
    //     khf.truncate(2);
    //     let key0 = khf.derive(0)?;
    //     let key1 = khf.derive(1)?;
    //     let key4_rederived_again = khf.derive(4)?;
    //     let key5_rederived_again = khf.derive(5)?;
    //     assert_eq!(key4_rederived_again, key4_rederived);
    //     assert_eq!(key5_rederived_again, key5_rederived);

    //     assert_eq!(khf.commit(&mut rng), vec![]);
    //     let key0_rederived = khf.derive(0)?;
    //     let key1_rederived = khf.derive(1)?;
    //     let key4_rederived_yet_again = khf.derive(4)?;
    //     let key5_rederived_yet_again = khf.derive(5)?;
    //     assert_eq!(key0, key0_rederived);
    //     assert_eq!(key1, key1_rederived);
    //     assert_ne!(key4_rederived_yet_again, key4_rederived_again);
    //     assert_ne!(key5_rederived_yet_again, key5_rederived_again);

    //     Ok(())
    // }

    use rand::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn random_commit() -> Result<()> {
        fn all_keys(khf: &mut Khf<Sha3_256, SHA3_256_MD_SIZE>) -> Vec<[u8; SHA3_256_MD_SIZE]> {
            (0..100).map(|i| khf.derive(i).unwrap()).collect()
        }

        let mut rng = thread_rng();
        let mut khf = Khf::<Sha3_256, SHA3_256_MD_SIZE>::new(&[4, 4, 4, 4], &mut rng);

        for _ in 0..10000 {
            let old = all_keys(&mut khf);

            let ks: HashSet<u64> = HashSet::from_iter((0..10).map(|_| {
                let k = rng.gen_range(0..100);
                khf.update(k).unwrap();
                khf.commit(&mut rng).unwrap();
                k
            }));

            let new = all_keys(&mut khf);

            for (i, (o, n)) in old.iter().zip(&new).enumerate() {
                if !ks.contains(&(i as u64)) {
                    assert_eq!(o, n);
                }
            }
        }

        Ok(())
    }
}
