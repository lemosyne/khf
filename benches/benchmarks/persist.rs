//! This benchmark aims to compare the latency of persistence between `Khf`s with different levels
//! of framentation. We evaluate this by selecting a single faout list to use for the different
//! `Khf`s. We fragment each `Khf`, consolidate it to roots of a different level, then persist the
//! partially consolidated `Khf`. `Khf`s aren't encrypted when persisted.

use criterion::{criterion_group, Criterion};
use embedded_io::adapters::FromStd;
use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use persistence::Persist;
use rand::rngs::ThreadRng;
use tempfile::NamedTempFile;

// Descendants per level:
//  L1: 65536
//  L2: 16384
//  L3: 4096
//  L4: 256
//  L5: 64
//  L6: 16
//  L7: 4
const FANOUTS: &[u64] = &[4, 4, 4, 4, 4, 4, 4, 4];

// 131072 keys means 2 L1 roots using the fanouts defined above.
const KEYS: usize = 131072;

struct TestCase {
    name: String,
    forest: Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
}

fn setup() -> Vec<TestCase> {
    let mut forest = Khf::new(FANOUTS, ThreadRng::default());

    forest.derive(KEYS as u64 - 1).unwrap();

    (0..FANOUTS.len())
        .map(|level| {
            let mut forest = forest.clone();

            forest.consolidate(Consolidation::Leveled {
                level: level as u64,
            });

            TestCase {
                name: format!("L{level} consolidation"),
                forest,
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("Latency of Persistence ({KEYS} keys)"));

    for test in setup().iter_mut() {
        group.bench_function(&test.name, |b| {
            b.iter(|| {
                let sink = FromStd::new(NamedTempFile::new().unwrap());
                test.forest.persist(sink).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
