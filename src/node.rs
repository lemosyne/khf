use crate::{
    aliases::{Key, Pos},
    topology::Topology,
};
use hasher::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{fmt, marker::PhantomData};

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Node<H, const N: usize> {
    pub pos: Pos,
    #[serde_as(as = "[_; N]")]
    pub key: Key<N>,
    phantoms: PhantomData<H>,
}

impl<H, const N: usize> Node<H, N>
where
    H: Hasher<N>,
{
    pub fn new(key: Key<N>) -> Self {
        Self {
            pos: (0, 0),
            key,
            phantoms: PhantomData,
        }
    }

    pub fn with_pos(pos: Pos, key: Key<N>) -> Self {
        Self {
            pos,
            key,
            phantoms: PhantomData,
        }
    }

    pub fn derive(&self, topology: &Topology, pos: Pos) -> Key<N> {
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

    pub fn coverage(&self, topology: &Topology, start: u64, end: u64) -> Vec<Self> {
        topology
            .coverage(start, end)
            .map(|pos| Self {
                pos,
                key: self.derive(topology, pos),
                phantoms: PhantomData,
            })
            .collect()
    }

    pub(crate) fn fmt(&self, f: &mut fmt::Formatter<'_>, topology: &Topology) -> fmt::Result {
        self.fmt_helper(f, topology, String::new(), self.pos, true)
    }

    fn fmt_helper(
        &self,
        f: &mut fmt::Formatter,
        topology: &Topology,
        prefix: String,
        pos: Pos,
        last: bool,
    ) -> fmt::Result {
        if let Some(width) = f.width() {
            write!(f, "{}", " ".repeat(width))?;
        }

        if pos == self.pos {
            write!(f, "> {} ({}, {})", hex::encode(&self.key), pos.0, pos.1)?;
        } else {
            write!(f, "{}{} ", prefix, if last { "└───" } else { "├───" })?;
            write!(
                f,
                "{} ({}, {})",
                hex::encode(self.derive(topology, pos)),
                pos.0,
                pos.1
            )?;
        }

        if self.pos != (0, 0) && pos != (topology.height() - 1, topology.end(self.pos) - 1) {
            writeln!(f)?;
        }

        if pos.0 < topology.height() - 1 {
            for i in 0..topology.fanout(pos.0) {
                let prefix = prefix.clone()
                    + if pos == self.pos {
                        ""
                    } else if last {
                        "     "
                    } else {
                        "│    "
                    };
                self.fmt_helper(
                    f,
                    topology,
                    prefix,
                    (pos.0 + 1, pos.1 * topology.fanout(pos.0) + i),
                    i + 1 == topology.fanout(pos.0),
                )?;
            }
        }

        Ok(())
    }
}
