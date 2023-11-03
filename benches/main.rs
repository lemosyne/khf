use criterion::criterion_main;

mod benchmarks;

criterion_main! {
    benchmarks::depth::benches,
    benchmarks::derivation::benches,
    benchmarks::width::benches,
    benchmarks::heterogeneity::benches,
}
