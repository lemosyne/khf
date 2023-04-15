use crate::{aliases::Key, node::Node, topology::Topology};
use hasher::prelude::*;
use std::fmt;

pub struct Kht<H, const N: usize> {
    root: Node<H, N>,
    topology: Topology,
}

impl<H, const N: usize> Kht<H, N>
where
    H: Hasher<N>,
{
    pub fn new(key: Key<N>) -> Self {
        Self {
            root: Node::new(key),
            topology: Topology::default(),
        }
    }

    pub fn derive(&self, leaf: u64) -> Key<N> {
        self.topology
            .path(self.root.pos, self.topology.leaf_position(leaf))
            .fold(self.root.key, |key, pos| {
                let mut hasher = H::new();
                hasher.update(&key);
                hasher.update(&pos.0.to_le_bytes());
                hasher.update(&pos.1.to_le_bytes());
                hasher.finish()
            })
    }
}

impl<H, const N: usize> fmt::Display for Kht<H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f, &self.topology)
    }
}
