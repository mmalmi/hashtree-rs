//! Git references (branches, tags, HEAD)
//!
//! Refs are named pointers to commits. They live in the refs namespace:
//! - refs/heads/* - branches
//! - refs/tags/* - tags
//! - HEAD - symbolic ref or direct pointer

use crate::object::ObjectId;
use crate::Result;
use crate::Error;

/// A git reference
#[derive(Debug, Clone)]
pub enum Ref {
    /// Direct reference to an object
    Direct(ObjectId),
    /// Symbolic reference to another ref (e.g., HEAD -> refs/heads/main)
    Symbolic(String),
}

impl Ref {
    pub fn direct(oid: ObjectId) -> Self {
        Ref::Direct(oid)
    }

    pub fn symbolic(target: impl Into<String>) -> Self {
        Ref::Symbolic(target.into())
    }
}

/// Reference with its full name
#[derive(Debug, Clone)]
pub struct NamedRef {
    pub name: String,
    pub reference: Ref,
}

impl NamedRef {
    pub fn new(name: impl Into<String>, reference: Ref) -> Self {
        Self {
            name: name.into(),
            reference,
        }
    }
}

/// Validate a ref name according to git rules
pub fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidRefName("empty ref name".into()));
    }

    // Must not start with / or end with /
    if name.starts_with('/') || name.ends_with('/') {
        return Err(Error::InvalidRefName("cannot start or end with /".into()));
    }

    // No double slashes
    if name.contains("//") {
        return Err(Error::InvalidRefName("cannot contain //".into()));
    }

    // No .. (path traversal)
    if name.contains("..") {
        return Err(Error::InvalidRefName("cannot contain ..".into()));
    }

    // No control chars or special chars
    for c in name.chars() {
        if c.is_control() || c == ' ' || c == '~' || c == '^' || c == ':' || c == '?' || c == '*' || c == '[' {
            return Err(Error::InvalidRefName(format!("invalid character: {:?}", c)));
        }
    }

    // Cannot end with .lock
    if name.ends_with(".lock") {
        return Err(Error::InvalidRefName("cannot end with .lock".into()));
    }

    // Cannot contain @{
    if name.contains("@{") {
        return Err(Error::InvalidRefName("cannot contain @{".into()));
    }

    // Cannot be just @
    if name == "@" {
        return Err(Error::InvalidRefName("cannot be @".into()));
    }

    // Cannot end with .
    if name.ends_with('.') {
        return Err(Error::InvalidRefName("cannot end with .".into()));
    }

    Ok(())
}

/// Common ref constants
pub const HEAD: &str = "HEAD";
pub const REFS_HEADS: &str = "refs/heads/";
pub const REFS_TAGS: &str = "refs/tags/";

/// Create a branch ref name
pub fn branch_ref(name: &str) -> String {
    format!("{}{}", REFS_HEADS, name)
}

/// Create a tag ref name
pub fn tag_ref(name: &str) -> String {
    format!("{}{}", REFS_TAGS, name)
}

/// Extract branch name from full ref
pub fn branch_name(full_ref: &str) -> Option<&str> {
    full_ref.strip_prefix(REFS_HEADS)
}

/// Extract tag name from full ref
pub fn tag_name(full_ref: &str) -> Option<&str> {
    full_ref.strip_prefix(REFS_TAGS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ref_names() {
        assert!(validate_ref_name("refs/heads/main").is_ok());
        assert!(validate_ref_name("refs/heads/feature/test").is_ok());
        assert!(validate_ref_name("refs/tags/v1.0.0").is_ok());
        assert!(validate_ref_name("HEAD").is_ok());
    }

    #[test]
    fn test_invalid_ref_names() {
        assert!(validate_ref_name("").is_err());
        assert!(validate_ref_name("/refs/heads/main").is_err());
        assert!(validate_ref_name("refs/heads/main/").is_err());
        assert!(validate_ref_name("refs//heads").is_err());
        assert!(validate_ref_name("refs/heads/..").is_err());
        assert!(validate_ref_name("refs/heads/test.lock").is_err());
        assert!(validate_ref_name("refs/heads/te st").is_err());
    }

    #[test]
    fn test_branch_ref() {
        assert_eq!(branch_ref("main"), "refs/heads/main");
        assert_eq!(branch_name("refs/heads/main"), Some("main"));
    }
}
