//! This benchmarks aims to compare the rate of fragmentation between `Khf`s with different
//! topologies. Each topology has the same number of L1 descendants.

use criterion::{criterion_group, Criterion};
use hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use rand::thread_rng;

const TOPOLOGIES: &[&[u64]] = &[
    &[4, 4, 4],
    &[8, 4, 2],
    &[8, 2, 4],
    &[4, 8, 2],
    &[4, 2, 8],
    &[2, 8, 4],
    &[2, 4, 8],
];

const KEYS: usize = 16384;

struct TestCase {
    name: String,
    forest: Khf<Sha3_256, SHA3_256_MD_SIZE>,
}

fn setup() -> Vec<TestCase> {
    TOPOLOGIES
        .iter()
        .map(|fanouts| {
            let mut forest = Khf::new(fanouts, thread_rng());

            forest.derive(KEYS as u64 - 1).unwrap();

            TestCase {
                name: format!("{fanouts:?}"),
                forest,
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!(
        "Fragmentation Rate With Heterogeneous Topologies ({KEYS} keys)"
    ));

    for test in setup().iter_mut() {
        group.bench_function(&test.name, |b| {
            b.iter(|| {
                let mut key = 0;
                while test.forest.fragmentation() != KEYS as u64 && key < KEYS {
                    test.forest.update(key as u64).unwrap();
                    key += 1;
                }

                test.forest.consolidate(Consolidation::Full, thread_rng());
                test.forest.derive(KEYS as u64 - 1).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
