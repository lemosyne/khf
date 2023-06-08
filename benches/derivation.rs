//! This benchmark aims to compare the latency of duration between `Khf`s with different levels of
//! fragmentation. We evaluate this by selecting a single fanout list to use for the different
//! `Khf`s. We fragment each `Khf` and consolidate it to roots of a different level.

use criterion::{criterion_group, Criterion};
use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use rand::rngs::ThreadRng;

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
    let mut group = c.benchmark_group(format!("Key Derivation ({KEYS} keys)"));

    for test in setup().iter_mut() {
        group.bench_function(&test.name, |b| {
            b.iter(|| {
                for key in 0..KEYS as u64 {
                    test.forest.derive(key).unwrap();
                }
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
