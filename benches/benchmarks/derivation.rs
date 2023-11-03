//! This benchmark aims to compare the latency of duration between `Khf`s with different levels of
//! fragmentation. We evaluate this by selecting a single fanout list to use for the different
//! `Khf`s. We fragment each `Khf` and consolidate it to roots of a different level.

use criterion::{criterion_group, BatchSize, Criterion};
use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use rand::thread_rng;

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

struct TestCase<F: FnMut() -> Khf<Sha3_256, SHA3_256_MD_SIZE>> {
    name: String,
    forest: F,
}

fn setup() -> Vec<TestCase<impl FnMut() -> Khf<Sha3_256, SHA3_256_MD_SIZE>>> {
    (0..FANOUTS.len())
        .map(|level| TestCase {
            name: format!("L{level} consolidation"),
            forest: move || {
                let mut forest = Khf::new(FANOUTS, thread_rng());

                forest.derive(KEYS as u64 - 1).unwrap();
                forest.consolidate(
                    Consolidation::Leveled {
                        level: level as u64,
                    },
                    thread_rng(),
                );

                forest
            },
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("Key Derivation ({KEYS} keys)"));

    for test in setup().iter_mut() {
        group.bench_function(&test.name, |b| {
            b.iter_batched(
                &mut test.forest,
                |mut forest| {
                    for key in 0..KEYS as u64 {
                        forest.derive(key).unwrap();
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
