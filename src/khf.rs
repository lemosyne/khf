use crate::{aliases::Key, error::Error, node::Node, topology::Topology};
use crypter::Crypter;
use hasher::Hasher;
use itertools::Itertools;
use kms::{
    DeferredKeyManagementScheme, FineGrainedKeyManagementScheme, KeyManagementScheme,
    SecureKeyManagementScheme,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
    os::unix::prelude::FileExt,
    path::PathBuf,
};

/// A keyed hash forest (`Khf`) is a data structure for secure key management built around keyed
/// hash trees (`Kht`s). As a secure key management scheme, a `Khf` is not only capable of deriving
/// keys, but also updating keys such that they cannot be rederived post-update. Updating a key is
/// synonymous to revoking a key.
pub struct Khf<C, R, H, const N: usize> {
    // The key protecting the public state of a persisted `Khf`.
    master_key: Key<N>,
    /// The file the master key is persisted to.
    master_key_file: Option<File>,
    // The public state of a `Khf`.
    state: KhfState<H, N>,
    // The file public state is persisted to.
    state_file: File,
    // The CSPRNG used to generate random keys and roots.
    rng: R,
    // Pretend like we own a `C` (which will be some crypter).
    phantom: PhantomData<C>,
}

#[derive(Deserialize, Serialize)]
struct KhfState<H, const N: usize> {
    // The topology of a `Khf`.
    topology: Topology,
    // The root that updated keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    updated_key_root: Node<H, N>,
    // The root that appended keys are derived from.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    appended_key_root: Node<H, N>,
    // Tracks updated keys.
    updated_keys: BTreeSet<u64>,
    // The list of roots.
    #[serde(bound(serialize = "Node<H, N>: Serialize"))]
    #[serde(bound(deserialize = "Node<H, N>: Deserialize<'de>"))]
    roots: Vec<Node<H, N>>,
    // The number of keys a `Khf` currently provides.
    keys: u64,
}

impl<C, R, H, const N: usize> Khf<C, R, H, N>
where
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// Returns a key filled with bytes from the supplied CSPRNG.
    fn random_key(rng: &mut R) -> Key<N> {
        let mut key = [0; N];
        rng.fill_bytes(&mut key);
        key
    }

    /// Returns a root with a pseudorandom key.
    fn random_root(rng: &mut R) -> Node<H, N> {
        Node::new(Self::random_key(rng))
    }

    /// Returns the number of roots in the forest's root list.
    pub fn fragmentation(&self) -> u64 {
        self.state.roots.len() as u64
    }
}

impl<H, const N: usize> KhfState<H, N>
where
    H: Hasher<N>,
{
    /// Returns `true` if the forest is consolidated.
    fn is_consolidated(&self) -> bool {
        self.roots.len() == 1 && self.roots[0].pos == (0, 0)
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

        self.derive_key(key)
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
            .peekable()
            .batching(|it| match it.peek() {
                Some(&key) => {
                    let num_keys = it
                        .enumerate()
                        .map(|(i, nkey)| (i as u64, nkey))
                        .peekable()
                        .peeking_take_while(|(i, nkey)| key + *i + 1 == **nkey)
                        .count() as u64;
                    Some((*key, key + num_keys + 1))
                }
                None => None,
            })
            .collect()
    }

    /// Updates a range of keys using the forest's root for updated keys.
    fn update_range(&mut self, start: u64, end: u64) {
        // Updates cause consolidated forests to fragment.
        if self.is_consolidated() {
            if self.keys == 0 {
                self.keys = end;
            }
            self.roots = self.roots[0].coverage(&self.topology, 0, self.keys + 1);
        }

        // We need to create a new set of roots and store updated roots.
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

        // Save the updated roots and add any remaining roots.
        roots.append(&mut updated);
        roots.extend(&mut self.roots.drain(update_end..));

        // Update roots and number of keys.
        self.roots = roots;
        self.keys = self.topology.end(self.roots.last().unwrap().pos);
    }
}

impl<'a, 'b, C, R, H, const N: usize> KeyManagementScheme for Khf<C, R, H, N>
where
    C: Crypter,
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
    /// A `Khf` is initialized with a fanout list and CSPRNG.
    type Init = (Option<PathBuf>, PathBuf, Vec<u64>, R);
    /// Keys have the same size as the hash digest size.
    type Key = Key<N>;
    /// Keys are uniquely identified with `u64`s.
    type KeyId = u64;
    /// Bespoke error type.
    type Error = Error;
    /// Allow public state to be encrypted by external keys.
    /// This is useful in a hierarchical use of `Khf`s.
    type PublicParams = Option<Key<N>>;
    /// No additional metadata needed when persisting/loading private state.
    type PrivateParams = ();

    fn setup(
        (master_key_file, state_file, fanouts, mut rng): Self::Init,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            master_key: Self::random_key(&mut rng),
            master_key_file: if let Some(file) = master_key_file {
                Some(
                    File::options()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(file)?,
                )
            } else {
                None
            },
            state: KhfState {
                topology: Topology::new(&fanouts),
                updated_key_root: Self::random_root(&mut rng),
                appended_key_root: Self::random_root(&mut rng),
                updated_keys: BTreeSet::new(),
                roots: vec![Self::random_root(&mut rng)],
                keys: 0,
            },
            state_file: File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(state_file)?,
            rng,
            phantom: PhantomData,
        })
    }

    fn derive(&mut self, key: Self::KeyId) -> Self::Key {
        // Three cases for any key derivation:
        //  1) The key has been updated.
        //  2) The key needs to be appended.
        //  3) The key already exists in the root list.
        if self.state.updated_keys.contains(&key) {
            self.state.update_key(key)
        } else if key >= self.state.keys {
            self.state.append_key(key)
        } else {
            self.state.derive_key(key)
        }
    }

    fn update(&mut self, key: Self::KeyId) -> Self::Key {
        // Append keys if we don't cover the key yet.
        if key >= self.state.keys {
            self.state.append_key(key);
        }
        self.state.update_key(key)
    }

    fn commit(&mut self) {
        for (start, end) in self.state.updated_ranges() {
            self.state.update_range(start, end);
        }
        self.master_key = Self::random_key(&mut self.rng);
        self.state.updated_key_root = Self::random_root(&mut self.rng);
        self.state.appended_key_root = Self::random_root(&mut self.rng);
        self.state.updated_keys.clear();
    }

    fn compact(&mut self) {
        self.state.roots = vec![Self::random_root(&mut self.rng)];
    }

    fn persist_public_state(&mut self, key: Self::PublicParams) -> Result<(), Self::Error> {
        let plaintext = bincode::serialize(&self.state)?;

        let ciphertext = if let Some(key) = key {
            C::onetime_encrypt(&key, &plaintext)?
        } else {
            C::onetime_encrypt(&self.master_key, &plaintext)?
        };

        self.state_file.set_len(0)?;
        self.state_file.write_all_at(&ciphertext, 0)?;

        Ok(())
    }

    fn persist_private_state(&mut self, _: Self::PrivateParams) -> Result<(), Self::Error> {
        if let Some(ref mut master_key_file) = self.master_key_file {
            master_key_file.set_len(0)?;
            master_key_file.write_all_at(&self.master_key, 0)?;
        }
        Ok(())
    }

    fn load_public_state(&mut self, key: Self::PublicParams) -> Result<(), Self::Error> {
        let mut ciphertext = Vec::new();

        self.state_file.seek(SeekFrom::Start(0))?;
        self.state_file.read_to_end(&mut ciphertext)?;

        let plaintext = if let Some(key) = key {
            C::onetime_decrypt(&key, &ciphertext)?
        } else {
            C::onetime_decrypt(&self.master_key, &ciphertext)?
        };

        self.state = bincode::deserialize(&plaintext)?;

        Ok(())
    }

    fn load_private_state(&mut self, _: Self::PrivateParams) -> Result<(), Self::Error> {
        if let Some(ref mut master_key_file) = self.master_key_file {
            master_key_file.seek(SeekFrom::Start(0))?;
            master_key_file.read_exact(&mut self.master_key)?;
        }
        Ok(())
    }
}

impl<C, R, H, const N: usize> SecureKeyManagementScheme for Khf<C, R, H, N>
where
    C: Crypter,
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
}

impl<C, R, H, const N: usize> FineGrainedKeyManagementScheme for Khf<C, R, H, N>
where
    C: Crypter,
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
}

impl<C, R, H, const N: usize> DeferredKeyManagementScheme for Khf<C, R, H, N>
where
    C: Crypter,
    R: RngCore + CryptoRng,
    H: Hasher<N>,
{
}

impl<C, R, H, const N: usize> fmt::Display for Khf<C, R, H, N>
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crypter::prelude::*;
    use hasher::prelude::*;
    use rand::rngs::ThreadRng;

    #[test]
    fn it_works() -> Result<()> {
        let rng = ThreadRng::default();
        let fanouts = vec![2, 2];
        let mut khf = Khf::<Aes256Ctr, ThreadRng, Sha3_256, SHA3_256_MD_SIZE>::setup((
            None,
            "/tmp/0.khf".into(),
            fanouts,
            rng,
        ))?;

        let t1_keys = khf
            .derive_many([0, 5, 7])
            .into_iter()
            .map(|key| hex::encode(key))
            .collect_vec();

        let t2_keys = khf
            .update_many([0, 5, 7])
            .into_iter()
            .map(|key| hex::encode(key))
            .collect_vec();

        khf.commit();

        let k1 = khf.derive(9);

        let t3_keys = khf
            .derive_many([0, 5, 7])
            .into_iter()
            .map(|key| hex::encode(key))
            .collect_vec();

        let t4_keys = khf
            .update_many([0, 5, 7])
            .into_iter()
            .map(|key| hex::encode(key))
            .collect_vec();

        khf.commit();

        let k2 = khf.derive(9);

        assert_ne!(t1_keys, t2_keys);
        assert_eq!(t2_keys, t3_keys);
        assert_ne!(t3_keys, t4_keys);
        assert_eq!(k1, k2);

        Ok(())
    }
}
