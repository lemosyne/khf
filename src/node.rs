use crate::{
    aliases::{Key, Pos},
    topology::Topology,
};
use hasher::prelude::*;
use std::marker::PhantomData;

pub struct Node<H, const N: usize> {
    pub pos: Pos,
    pub key: Key<N>,
    phantoms: PhantomData<H>,
}

impl<H, const N: usize> Node<H, N> {
    pub fn new(key: Key<N>) -> Self {
        Self {
            pos: (0, 0),
            key,
            phantoms: PhantomData,
        }
    }

    pub fn derive(&self, topology: &Topology, pos: Pos) -> Key<N>
    where
        H: Hasher<N>,
    {
        if self.pos == pos {
            self.key
        } else {
            topology.path(self.pos, pos).fold(self.key, |key, pos| {
                let mut hasher = H::new();
                hasher.update(&key);
                hasher.update(&pos.0.to_le_bytes());
                hasher.update(&pos.1.to_le_bytes());
                hasher.finish()
            })
        }
    }

    pub fn coverage(
        &self,
        topology: &Topology,
        start: u64,
        end: u64,
    ) -> Vec<Self>
    where
        H: Hasher<N>,
    {
        topology
            .coverage(start, end)
            .map(|pos| Self {
                pos,
                key: self.derive(topology, pos),
                phantoms: PhantomData,
            })
            .collect()
    }
}
