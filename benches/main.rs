use criterion::criterion_main;

pub mod depth;
pub mod derivation;
pub mod persist;
pub mod width;

criterion_main! {
    depth::benches,
    derivation::benches,
    persist::benches,
    width::benches,
}
