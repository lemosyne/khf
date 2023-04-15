use crate::{
    aliases::{Key, Pos},
    error::Error,
    node::Node,
    topology::Topology,
    KeyManagementScheme,
};
use hasher::prelude::*;
use rand::{CryptoRng, RngCore};
use std::{cmp::Ordering, collections::BTreeSet, fmt};

pub struct Khf<R, H, const N: usize> {
    master_key: Key<N>,
    master_root: Node<H, N>,
    topology: Topology,
    updated: BTreeSet<u64>,
    roots: Vec<Node<H, N>>,
    rng: R,
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

    pub fn fragmentation(&self) -> u64 {
        self.roots.len() as u64
    }

    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    fn update_master_key(&mut self) {
        self.master_key = Self::random_key(&mut self.rng);
    }

    fn update_range(&mut self, start: u64, end: u64) {
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

        roots.extend(&mut self.roots.drain(..patch_start));
        patch.append(&mut self.master_root.coverage(&self.topology, start, end));

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

    fn updated_ranges(&self) -> Vec<(u64, u64)> {
        if self.updated.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut first = true;
        let mut start = 0;
        let mut prev = 0;
        let mut leaves = 1;

        for leaf in &self.updated {
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
    type Error = Error;
    type Init = R;
    type Key = Key<N>;
    type Id = u64;

    fn setup(mut rng: Self::Init) -> Self {
        Self {
            master_key: Self::random_key(&mut rng),
            master_root: Node::new(Self::random_key(&mut rng)),
            topology: Topology::default(),
            updated: BTreeSet::new(),
            roots: Vec::new(),
            rng,
        }
    }

    fn derive(&mut self, x: Self::Id) -> Self::Key {
        if self.updated.contains(&x) || x >= self.len() {
            self.update(x)
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
        self.updated.insert(x);
        self.master_root
            .derive(&self.topology, self.topology.leaf_position(x))
    }

    fn epoch(&mut self) {
        for (start, end) in self.updated_ranges() {
            self.update_range(start, end);
        }
        self.updated.clear();
        self.update_master_key();
    }

    fn persist<W: std::io::Write>(&mut self, _loc: W) -> Result<(), Self::Error> {
        todo!()
    }
}

impl<R, H, const N: usize> fmt::Display for Khf<R, H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn fmt_root<H, const N: usize>(
            f: &mut fmt::Formatter,
            root: &Node<H, N>,
            topology: &Topology,
            prefix: String,
            pos: Pos,
            last: bool,
        ) -> fmt::Result
        where
            H: Hasher<N>,
        {
            if let Some(width) = f.width() {
                write!(f, "{}", " ".repeat(width))?;
            }

            if pos == root.pos {
                write!(f, "> {} ({}, {})", hex::encode(&root.key), pos.0, pos.1)?;
            } else {
                write!(f, "{}{} ", prefix, if last { "└───" } else { "├───" })?;
                write!(
                    f,
                    "{} ({}, {})",
                    hex::encode(root.derive(topology, pos)),
                    pos.0,
                    pos.1
                )?;
            }

            if root.pos != (0, 0) && pos != (topology.height() - 1, topology.end(root.pos) - 1) {
                writeln!(f)?;
            }

            if pos.0 < topology.height() - 1 {
                for i in 0..topology.fanout(pos.0) {
                    let prefix = prefix.clone()
                        + if pos == root.pos {
                            ""
                        } else if last {
                            "     "
                        } else {
                            "│    "
                        };
                    fmt_root::<H, N>(
                        f,
                        root,
                        topology,
                        prefix,
                        (pos.0 + 1, pos.1 * topology.fanout(pos.0) + i),
                        i + 1 == topology.fanout(pos.0),
                    )?;
                }
            }

            Ok(())
        }

        for (i, root) in self.roots.iter().enumerate() {
            fmt_root::<H, N>(f, root, &self.topology, "".into(), root.pos, true)?;
            if i + 1 != self.roots.len() {
                writeln!(f)?;
            }
        }

        Ok(())
    }
}
