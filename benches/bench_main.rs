use criterion::criterion_main;

pub mod depth;
pub mod derivation;
pub mod width;

criterion_main! {
    derivation::benches,
    depth::benches,
    width::benches,
}
