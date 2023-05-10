use crate::{aliases::Key, node::Node, topology::Topology};
use hasher::Hasher;
use num_traits::PrimInt;
use std::fmt;

pub struct Kht<H, O, const N: usize> {
    root: Node<H, O, N>,
    topology: Topology<O>,
}

impl<H, O, const N: usize> Kht<H, O, N>
where
    H: Hasher<N>,
    O: PrimInt,
{
    pub fn new(key: Key<N>) -> Self {
        Self {
            root: Node::new(key),
            topology: Topology::default(),
        }
    }

    pub fn derive(&self, leaf: O) -> Key<N> {
        self.root
            .derive(&self.topology, self.topology.leaf_position(leaf))
    }
}

impl<H, O, const N: usize> fmt::Display for Kht<H, O, N>
where
    H: Hasher<N>,
    O: PrimInt + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f, &self.topology)
    }
}
