use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io,

    #[error("unknown error")]
    Unknown,
}
