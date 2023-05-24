use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use embedded_io::blocking::{Read, Write};
use hasher::Hasher;
use inachus::Persist;
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashSet, fmt};

/// The default level for roots created when mutating a `Khf`.
const DEFAULT_ROOT_LEVEL: u64 = 1;

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
pub struct Khf<R, H, const N: usize> {
    // The persistable state of a `Khf`.
    state: State<H, N>,
    // The CSPRNG used to generate random roots.
    rng: R,
}

/// This is decoupled from the `Khf` struct purely because of the `rng` field. It doesn't make
/// sense to require `rng` to be `Serialize`, and it's less flexible if we require `rng` to be
/// `Default` to allow serialization to skip the `rng` field. Unfortunately, this makes the code
/// quite ugly, since all field accesses (except for `rng`) needs to go through here.
#[derive(Deserialize, Serialize)]
struct State<H, const N: usize> {
    // The topology of a `Khf`.
    topology: Topology,
    // Tracks updated keys.
    updated_keys: HashSet<u64>,
    // The list of roots.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    roots: Vec<Node<H, N>>,
    // The number of keys a `Khf` currently provides.
    keys: u64,
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

impl<R, H, const N: usize> Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Constructs a new `Khf`.
    pub fn new(fanouts: &[u64], mut rng: R) -> Self {
        Self {
            state: State {
                topology: Topology::new(fanouts),
                updated_keys: HashSet::new(),
                roots: vec![Node::with_rng(&mut rng)],
                keys: 0,
            },
            rng,
        }
    }

    /// Returns the number of roots in the `Khf`'s root list.
    pub fn fragmentation(&self) -> u64 {
        self.state.roots.len() as u64
    }

    /// Returns `true` if the `Khf` is consolidated.
    pub fn is_consolidated(&self) -> bool {
        self.state.roots.len() == 1 && self.state.roots[0].pos == (0, 0)
    }

    /// Consolidates the `Khf` and returns the affected keys.
    pub fn consolidate(&mut self, mechanism: Consolidation) -> Vec<u64> {
        match mechanism {
            Consolidation::Full => self.consolidate_full(),
            Consolidation::Leveled { level } => self.consolidate_leveled(level),
            Consolidation::Ranged { start, end } => self.consolidate_ranged(start, end),
            Consolidation::RangedLeveled { level, start, end } => {
                self.consolidate_ranged_leveled(level, start, end)
            }
        }
    }

    // Consolidates back into a single root.
    fn consolidate_full(&mut self) -> Vec<u64> {
        self.consolidate_leveled(0)
    }

    // Consolidates to roots of a certain level.
    fn consolidate_leveled(&mut self, level: u64) -> Vec<u64> {
        let affected = (0..self.state.keys).into_iter().collect();

        // Unmark keys as updated and update the whole range of keys.
        self.state.updated_keys.clear();
        self.update_keys(level, 0, self.state.keys);

        affected
    }

    // Consolidates the roots for a range of keys.
    fn consolidate_ranged(&mut self, start: u64, end: u64) -> Vec<u64> {
        self.consolidate_ranged_leveled(DEFAULT_ROOT_LEVEL, start, end)
    }

    // Consolidates the roots for a range of keys to roots of a certain level.
    fn consolidate_ranged_leveled(&mut self, level: u64, start: u64, end: u64) -> Vec<u64> {
        let affected = (start..end).into_iter().collect();

        // Make sure we cover the range of keys.
        if self.state.keys < end {
            self.append_key(level, end);
        }

        // "Update" the range of keys.
        self.update_keys(level, start, end);

        // The consolidated range of keys shouldn't be considered as updated.
        for key in &affected {
            self.state.updated_keys.remove(key);
        }

        affected
    }

    /// Appends a key, appending roots as necessary from the specified level.
    fn append_key(&mut self, level: u64, key: u64) -> Key<N> {
        // No need to append additional roots the forest is already consolidated.
        if self.is_consolidated() {
            self.state.keys = self.state.keys.max(key);
            return self.state.roots[0]
                .derive(&self.state.topology, self.state.topology.leaf_position(key));
        }

        // First, add any roots needed to reach a full root of the specified level.
        // For example: assume a topology of [4], a target of L1, and the following roots:
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
        // This allows us to append more keys later by adding roots of the specified level.
        //
        // First, compute the number of keys needed to reach a full root of the specified level.
        let needed = self.state.topology.descendants(level)
            - (self.state.keys % self.state.topology.descendants(level));
        self.state.keys += needed;

        // Then, add in the roots of the specified level (each derived from a random root).
        let root = Node::with_rng(&mut self.rng);
        self.state.roots.append(&mut root.coverage(
            &self.state.topology,
            level,
            self.state.keys,
            self.state.keys + needed,
        ));

        // Add roots of the specified level until we have one that covers the desired key.
        while self.state.keys < key {
            let pos = (
                level,
                self.state.keys / self.state.topology.descendants(level),
            );
            let key = root.derive(&self.state.topology, pos);
            self.state.roots.push(Node::with_pos(pos, key));
            self.state.keys += self.state.topology.descendants(level);
        }

        self.derive_key(key)
    }

    /// Derives a key from an existing root in the root list.
    fn derive_key(&mut self, key: u64) -> Key<N> {
        let pos = self.state.topology.leaf_position(key);
        let index = self
            .state
            .roots
            .binary_search_by(|root| {
                if self.state.topology.is_ancestor(root.pos, pos) {
                    Ordering::Equal
                } else if self.state.topology.end(root.pos) <= self.state.topology.start(pos) {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            })
            .unwrap();
        self.state.roots[index].derive(&self.state.topology, pos)
    }

    /// Updates a range of keys using the forest's root for updated keys.
    fn update_keys(&mut self, level: u64, start: u64, end: u64) {
        // Level 0 means consolidating to a single root.
        if level == 0 {
            self.state.roots = vec![Node::with_rng(&mut self.rng)];
            self.state.keys = end;
            self.state.updated_keys.extend(start..end);
            return;
        }

        // Updates cause consolidated forests to fragment.
        if self.is_consolidated() {
            if self.state.keys == 0 {
                self.state.keys = end;
            }
            self.state.roots =
                self.state.roots[0].coverage(&self.state.topology, level, 0, self.state.keys);
        }

        // We need to create a new set of roots and store updated roots.
        let mut roots = Vec::new();
        let mut updated = Vec::new();

        // Find the first root affected by the update.
        let update_start = self
            .state
            .roots
            .iter()
            .position(|root| start < self.state.topology.end(root.pos))
            .unwrap_or(self.state.roots.len() - 1);
        let update_root = &self.state.roots[update_start];
        if self.state.topology.start(update_root.pos) != start {
            updated.append(&mut update_root.coverage(
                &self.state.topology,
                level,
                self.state.topology.start(update_root.pos),
                start,
            ));
        }

        // Save roots before the first root affected by the update.
        roots.extend(&mut self.state.roots.drain(..update_start));

        // Added updated roots derived from a new random root.
        let root = Node::with_rng(&mut self.rng);
        updated.append(&mut root.coverage(&self.state.topology, level, start, end));

        // Find the last root affected by the update.
        let mut update_end = self.state.roots.len();
        if end
            < self
                .state
                .topology
                .end(self.state.roots[self.state.roots.len() - 1].pos)
        {
            update_end = self
                .state
                .roots
                .iter()
                .position(|root| end <= self.state.topology.end(root.pos))
                .unwrap_or(self.state.roots.len())
                + 1;
            let update_root = &self.state.roots[update_end - 1];
            if self.state.topology.end(update_root.pos) != end {
                updated.append(&mut update_root.coverage(
                    &self.state.topology,
                    level,
                    end,
                    self.state.topology.end(update_root.pos),
                ));
            }
        }

        // Save the updated roots and add any remaining roots.
        roots.append(&mut updated);
        roots.extend(&mut self.state.roots.drain(update_end..));

        // Update roots and number of keys.
        self.state.roots = roots;
        self.state.keys = self
            .state
            .topology
            .end(self.state.roots.last().unwrap().pos);
        self.state.updated_keys.extend(start..end);
    }
}

impl<'a, 'b, R, H, const N: usize> KeyManagementScheme for Khf<R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Keys have the same size as the hash digest size.
    type Key = Key<N>;
    /// Keys are uniquely identified with `u64`s.
    type KeyId = u64;
    /// Bespoke error type.
    type Error = Error;

    fn derive(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Two cases for key derivation:
        //  1) The key needs to be appended.
        //  2) The key already exists in the root list.
        if key >= self.state.keys {
            Ok(self.append_key(DEFAULT_ROOT_LEVEL, key))
        } else {
            Ok(self.derive_key(key))
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Result<Self::Key, Self::Error> {
        // Append the key if we don't cover it yet.
        if key >= self.state.keys {
            self.append_key(DEFAULT_ROOT_LEVEL, key);
        }

        // It's a pity that we must fragment the tree here for security.
        self.update_keys(DEFAULT_ROOT_LEVEL, key, key + 1);

        Ok(self.derive_key(key))
    }

    fn commit(&mut self) -> Vec<Self::KeyId> {
        self.state.updated_keys.drain().collect()
    }
}

impl<Io, R, H, const N: usize> Persist<Io> for Khf<R, H, N>
where
    Io: Read + Write,
{
    type Init = R;
    type Error = Error;

    fn persist(&mut self, mut sink: Io) -> Result<(), Self::Error> {
        // TODO: Stream serialization.
        let ser = bincode::serialize(&self.state)?;
        sink.write_all(&ser).map_err(|_| Error::Io)
    }

    fn load(rng: Self::Init, mut source: Io) -> Result<Self, Self::Error> {
        // TODO: Stream deserialization.
        let mut raw = vec![];
        source.read_to_end(&mut raw).map_err(|_| Error::Io)?;
        Ok({
            Self {
                state: bincode::deserialize(&raw)?,
                rng,
            }
        })
    }
}

impl<R, H, const N: usize> fmt::Display for Khf<R, H, N>
where
    H: Hasher<N>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, root) in self.state.roots.iter().enumerate() {
            root.fmt(f, &self.state.topology)?;
            if i + 1 != self.state.roots.len() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}
