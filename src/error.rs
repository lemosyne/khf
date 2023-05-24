use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    Io,

    #[error(transparent)]
    Serde(#[from] bincode::Error),

    #[error("unknown error")]
    Unknown,
}
