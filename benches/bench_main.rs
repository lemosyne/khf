use criterion::criterion_main;

pub mod depth;
pub mod derivation;

criterion_main! {
    derivation::benches,
    depth::benches,
}
