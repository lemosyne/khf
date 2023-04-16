use crate::{aliases::Key, node::Node, topology::Topology};
use hasher::prelude::Hasher;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::{cmp::Ordering, collections::BTreeSet, fmt};

pub struct Khf<R, H, const N: usize> {
    topology: Topology,
    master_key: Key<N>,
    updated_root: Node<H, N>,
    updated: BTreeSet<u64>,
    appended_root: Node<H, N>,
    appended: BTreeSet<u64>,
    roots: Vec<Node<H, N>>,
    rng: R,
}

enum Modification {
    Update,
    Append,
}

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    pub fn len(&self) -> u64 {
        self.roots
            .last()
            .map(|root| self.topology.end(root.pos))
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn fragmentation(&self) -> u64 {
        self.roots.len() as u64
    }

    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    fn append_key(&mut self, leaf: u64) -> Key<N> {
        self.appended.insert(leaf);
        self.appended_root
            .derive(&self.topology, self.topology.leaf_position(leaf))
    }

    fn update_key(&mut self, leaf: u64) -> Key<N> {
        self.appended.remove(&leaf);
        self.updated.insert(leaf);
        self.updated_root
            .derive(&self.topology, self.topology.leaf_position(leaf))
    }

    fn update_master_key(&mut self) {
        self.master_key = Self::random_key(&mut self.rng);
    }

    fn patch_range(&mut self, modification: Modification, start: u64, end: u64) {
        let mut roots = Vec::new();
        let mut patch = Vec::new();

        let patch_start = self
            .roots
            .iter()
            .position(|root| start < self.topology.end(root.pos))
            .unwrap_or(self.roots.len() - 1);
        let patch_root = &self.roots[patch_start];
        if self.topology.start(patch_root.pos) != start {
            patch.append(&mut patch_root.coverage(
                &self.topology,
                self.topology.start(patch_root.pos),
                start,
            ));
        }

        let root = match modification {
            Modification::Update => &self.updated_root,
            Modification::Append => &self.appended_root,
        };

        roots.extend(&mut self.roots.drain(..patch_start));
        patch.append(&mut root.coverage(&self.topology, start, end));

        let mut patch_end = self.roots.len();
        if end < self.topology.end(self.roots[self.roots.len() - 1].pos) {
            patch_end = self
                .roots
                .iter()
                .position(|root| end <= self.topology.end(root.pos))
                .unwrap_or(self.roots.len())
                + 1;
            let patch_root = &self.roots[patch_end - 1];
            if self.topology.end(patch_root.pos) != end {
                patch.append(&mut patch_root.coverage(
                    &self.topology,
                    end,
                    self.topology.end(patch_root.pos),
                ));
            }
        }

        roots.append(&mut patch);
        roots.extend(&mut self.roots.drain(patch_end..));

        self.roots = roots;
    }

    fn patched_ranges(&self, modification: Modification) -> Vec<(u64, u64)> {
        let set = match modification {
            Modification::Update => &self.updated,
            Modification::Append => &self.appended,
        };

        if set.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut first = true;
        let mut start = 0;
        let mut prev = 0;
        let mut leaves = 1;

        for leaf in set {
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
}

impl<R, H, const N: usize> KeyManagementScheme for Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    type Init = R;
    type Key = Key<N>;
    type Id = u64;

    fn setup(mut rng: Self::Init) -> Self {
        Self {
            topology: Topology::default(),
            master_key: Self::random_key(&mut rng),
            updated_root: Node::new(Self::random_key(&mut rng)),
            updated: BTreeSet::new(),
            appended_root: Node::new(Self::random_key(&mut rng)),
            appended: BTreeSet::new(),
            roots: vec![Node::new(Self::random_key(&mut rng))],
            rng,
        }
    }

    fn derive(&mut self, x: Self::Id) -> Self::Key {
        if self.is_empty() || x >= self.len() {
            self.append_key(x)
        } else if self.updated.contains(&x) {
            self.update_key(x)
        } else {
            let pos = self.topology.leaf_position(x);
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
    }

    fn update(&mut self, x: Self::Id) -> Self::Key {
        self.update_key(x)
    }

    fn epoch(&mut self) {
        for (start, end) in self.patched_ranges(Modification::Update) {
            self.patch_range(Modification::Update, start, end);
        }
        self.updated.clear();

        for (start, end) in self.patched_ranges(Modification::Append) {
            self.patch_range(Modification::Append, start, end);
        }
        self.appended.clear();

        self.update_master_key();
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
        let mut khf = Khf::<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::setup(rng);

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
