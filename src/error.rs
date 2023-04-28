use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] io::Error),

    #[error(transparent)]
    Bincode(#[from] bincode::Error),

    #[error("unknown error")]
    Unknown,
}
