use std::io::Write;

pub trait KeyManagementScheme {
    type Error;
    type Init;
    type Key;
    type Id;

    fn setup(init: Self::Init) -> Self;

    /// Derive key corresponding to identifier `x`.
    /// You must not keep this key alive beyond any updates to identifier `x`.
    fn derive(&mut self, x: Self::Id) -> Self::Key;

    /// Ensure that after the next call to epoch, the key corresponding to `x` is underivable from
    /// `self`.
    fn update(&mut self, x: Self::Id) -> Self::Key;

    /// Ensure that every key which has been updated is underivable.
    fn epoch(&mut self);

    /// Persist to some writable location.
    fn persist<W: Write>(&mut self, loc: W) -> Result<(), Self::Error>;
}

pub mod aliases;
pub mod error;
pub mod khf;
pub mod kht;
pub mod node;
pub mod topology;
