//! Git smart HTTP protocol implementation for hashtree
//!
//! Implements the git smart HTTP protocol allowing hashtree to serve as a git remote.
//! Supports both fetch (git-upload-pack) and push (git-receive-pack) operations.

pub mod error;
pub mod object;
pub mod refs;
pub mod storage;
pub mod protocol;
pub mod pack;
pub mod http;

pub use error::{Error, Result};
pub use storage::GitStorage;
