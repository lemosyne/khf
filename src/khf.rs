use crate::{aliases::Key, node::Node, topology::Topology};
use hasher::prelude::Hasher;
use itertools::Itertools;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::{cmp::Ordering, collections::BTreeSet, fmt};

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
pub struct Khf<R, H, const N: usize> {
    topology: Topology,
    master_key: Key<N>,
    updated_key_root: Node<H, N>,
    appended_key_root: Node<H, N>,
    updated_keys: BTreeSet<u64>,
    roots: Vec<Node<H, N>>,
    keys: u64,
    rng: R,
}

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Returns the number of keys supplied by the forest.
    pub fn len(&self) -> u64 {
        self.keys
    }

    /// Returns the number of roots in the forest's root list.
    pub fn fragmentation(&self) -> u64 {
        self.roots.len() as u64
    }

    /// Returns `true` if the forest is consolidated.
    fn is_consolidated(&self) -> bool {
        self.roots
            .first()
            .filter(|root| root.pos == (0, 0))
            .is_some()
    }

    /// Returns a key filled with bytes from the supplied PRNG.
    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    /// Returns a root with a pseudorandom key.
    fn random_root(rng: &mut R) -> Node<H, N> {
        Node::new(Self::random_key(rng))
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

        self.derive(key)
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
            .batching(|it| {
                it.next().map(|key| {
                    let start = *key;
                    let mut curr = start;
                    let keys = it
                        .take_while(|key| {
                            let is_contiguous = curr + 1 == **key;
                            curr += 1;
                            is_contiguous
                        })
                        .count() as u64;
                    (start, start + keys + 1)
                })
            })
            .collect()
    }

    /// Updates a range of keys using the forest's root for updated keys.
    fn update_range(&mut self, start: u64, end: u64) {
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

        // Save the updated roots, add the remaining roots, and use the new set of roots.
        roots.append(&mut updated);
        roots.extend(&mut self.roots.drain(update_end..));
        self.roots = roots;
    }
}

impl<R, H, const N: usize> KeyManagementScheme for Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    type Init = (Vec<u64>, R);
    type Key = Key<N>;
    type Id = u64;

    fn setup((fanouts, mut rng): Self::Init) -> Self {
        Self {
            topology: Topology::new(&fanouts),
            master_key: Self::random_key(&mut rng),
            updated_key_root: Self::random_root(&mut rng),
            appended_key_root: Self::random_root(&mut rng),
            updated_keys: BTreeSet::new(),
            roots: vec![Self::random_root(&mut rng)],
            keys: 0,
            rng,
        }
    }

    fn derive(&mut self, key: Self::Id) -> Self::Key {
        // Three cases for any key derivation:
        //  1) The key has been updated
        //  2) The key needs to be appended
        //  3) The key already exists in the root list
        if self.updated_keys.contains(&key) {
            self.update_key(key)
        } else if key >= self.len() {
            self.append_key(key)
        } else {
            self.derive_key(key)
        }
    }

    fn update(&mut self, key: Self::Id) -> Self::Key {
        self.update_key(key)
    }

    fn epoch(&mut self) {
        for (start, end) in self.updated_ranges() {
            self.update_range(start, end);
        }
        self.master_key = Self::random_key(&mut self.rng);
        self.updated_key_root = Self::random_root(&mut self.rng);
        self.appended_key_root = Self::random_root(&mut self.rng);
        self.updated_keys.clear();
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
    use hasher::prelude::*;
    use rand::rngs::ThreadRng;

    #[test]
    fn it_works() {
        let rng = ThreadRng::default();
        let fanouts = vec![2, 2];
        let mut khf = Khf::<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::setup((fanouts, rng));

        let k0 = khf.derive(0);
        let k0_prime = khf.update(0);
        assert_ne!(k0, k0_prime);

        khf.epoch();
        println!("{khf}");

        let k0 = khf.derive(0);
        let k0_prime = khf.update(0);
        assert_ne!(k0, k0_prime);

        let k1 = khf.derive(1);
        let k1_prime = khf.update(1);
        assert_ne!(k1, k1_prime);

        let k2 = khf.derive(2);
        let k2_prime = khf.update(2);
        assert_ne!(k2, k2_prime);

        let k3 = khf.derive(3);
        let k3_prime = khf.update(3);
        assert_ne!(k3, k3_prime);

        khf.epoch();
        println!("{khf}");
    }
}
