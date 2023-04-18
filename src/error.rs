use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Serde(#[from] bincode::Error),

    #[error(transparent)]
    Crypter(#[from] crypter::Error),

    #[error("unknown error")]
    Unknown,
}
