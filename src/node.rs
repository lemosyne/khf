use crate::{
    aliases::{Key, Pos},
    topology::Topology,
};
use hasher::Hasher;
use num_traits::PrimInt;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{fmt, marker::PhantomData};

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Node<H, O, const N: usize> {
    pub pos: Pos<O>,
    #[serde_as(as = "[_; N]")]
    pub key: Key<N>,
    phantoms: PhantomData<H>,
}

impl<H, O, const N: usize> Node<H, O, N>
where
    H: Hasher<N>,
    O: PrimInt,
{
    pub fn new(key: Key<N>) -> Self {
        Self {
            pos: (0, O::zero()),
            key,
            phantoms: PhantomData,
        }
    }

    pub fn with_pos(pos: Pos<O>, key: Key<N>) -> Self {
        Self {
            pos,
            key,
            phantoms: PhantomData,
        }
    }

    // TODO: Don't convert to `u128`.
    // This requires the `ToBytes` trait to be added.
    // https://github.com/rust-num/num-traits/pull/224
    pub fn derive(&self, topology: &Topology<O>, pos: Pos<O>) -> Key<N> {
        if self.pos == pos {
            self.key
        } else {
            topology.path(self.pos, pos).fold(self.key, |key, pos| {
                let mut hasher = H::new();
                hasher.update(&key);
                hasher.update(&pos.0.to_le_bytes());
                hasher.update(&pos.1.to_u128().unwrap().to_le_bytes());
                hasher.finish()
            })
        }
    }

    pub fn coverage(&self, topology: &Topology<O>, start: O, end: O) -> Vec<Self> {
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

impl<H, O, const N: usize> Node<H, O, N>
where
    H: Hasher<N>,
    O: PrimInt + fmt::Display,
{
    pub(crate) fn fmt(&self, f: &mut fmt::Formatter<'_>, topology: &Topology<O>) -> fmt::Result {
        self.fmt_helper(f, topology, String::new(), self.pos, true)
    }

    fn fmt_helper(
        &self,
        f: &mut fmt::Formatter,
        topology: &Topology<O>,
        prefix: String,
        pos: Pos<O>,
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
