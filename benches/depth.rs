//! This benchmark aims to compare the rate of fragmentation between `Khf`s with different depths.

use criterion::{criterion_group, Criterion};
use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
use khf::{Consolidation, Khf};
use kms::KeyManagementScheme;
use rand::rngs::ThreadRng;

// Descendants per level:
//  L1: 16384
//  L2: 4096
//  L3: 256
//  L4: 64
//  L5: 16
//  L6: 4
const FANOUTS: &[u64] = &[4, 4, 4, 4, 4, 4, 4];

const KEYS: usize = 32768;

struct TestCase {
    name: String,
    forest: Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
}

fn setup() -> Vec<TestCase> {
    (1..FANOUTS.len())
        .map(|i| {
            let mut forest = Khf::new(&FANOUTS[..i], ThreadRng::default());

            forest.derive(KEYS as u64 - 1).unwrap();

            TestCase {
                name: format!("{:?}", &FANOUTS[..i]),
                forest,
            }
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("Fragmentation Rate ({KEYS} keys)"));

    for test in setup().iter_mut() {
        group.bench_function(&test.name, |b| {
            b.iter(|| {
                let mut key = 0;
                while test.forest.fragmentation() != KEYS as u64 && key < KEYS {
                    test.forest.update(key as u64).unwrap();
                    key += 1;
                }

                test.forest.consolidate(Consolidation::Full);
                test.forest.derive(KEYS as u64 - 1).unwrap();
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
