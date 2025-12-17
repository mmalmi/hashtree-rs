//! Error types for hashtree-git

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    #[error("Invalid object type: {0}")]
    InvalidObjectType(String),

    #[error("Invalid object format: {0}")]
    InvalidObjectFormat(String),

    #[error("Ref not found: {0}")]
    RefNotFound(String),

    #[error("Invalid ref name: {0}")]
    InvalidRefName(String),

    #[error("Pack error: {0}")]
    PackError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
