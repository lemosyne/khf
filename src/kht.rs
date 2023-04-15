use crate::{
    aliases::{Key, Pos},
    node::Node,
    topology::Topology,
};
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

        fmt_root::<H, N>(
            f,
            &self.root,
            &self.topology,
            "".into(),
            self.root.pos,
            true,
        )
    }
}
