//! This benchmark aims to compare the rate of fragmentation between `Khf`s with different widths.

use criterion::{criterion_group, Criterion};
use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use rand::thread_rng;

const WIDTHS: &[u64] = &[2, 4, 8, 16, 32];
const DEPTH: usize = 3;
const KEYS: usize = 32768;

struct TestCase {
    name: String,
    forest: Khf<Sha3_256, SHA3_256_MD_SIZE>,
}

fn setup() -> Vec<TestCase> {
    WIDTHS
        .iter()
        .map(|width| {
            let mut forest = Khf::new(&vec![*width; DEPTH], thread_rng());

            forest.derive(KEYS as u64 - 1).unwrap();

            TestCase {
                name: format!("{:?}", vec![width; DEPTH]),
                forest,
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!(
        "Fragmentation Rate With Variable Width ({KEYS} keys)"
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
