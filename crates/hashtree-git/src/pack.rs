//! Git packfile generation and parsing
//!
//! Packfiles are git's binary format for efficiently transferring objects.
//! Format: PACK header, N objects, SHA-1 checksum

use sha1::{Sha1, Digest};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use std::io::{Read, Write};

use crate::object::{ObjectId, ObjectType, GitObject};
use crate::storage::GitStorage;
use crate::{Error, Result};

/// Pack object type encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PackObjectType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    // Delta types (6, 7) not implemented for simplicity
}

impl PackObjectType {
    pub fn from_object_type(t: ObjectType) -> Self {
        match t {
            ObjectType::Commit => PackObjectType::Commit,
            ObjectType::Tree => PackObjectType::Tree,
            ObjectType::Blob => PackObjectType::Blob,
            ObjectType::Tag => PackObjectType::Tag,
        }
    }

    pub fn to_object_type(self) -> ObjectType {
        match self {
            PackObjectType::Commit => ObjectType::Commit,
            PackObjectType::Tree => ObjectType::Tree,
            PackObjectType::Blob => ObjectType::Blob,
            PackObjectType::Tag => ObjectType::Tag,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(PackObjectType::Commit),
            2 => Some(PackObjectType::Tree),
            3 => Some(PackObjectType::Blob),
            4 => Some(PackObjectType::Tag),
            _ => None,
        }
    }
}

/// Generate a packfile containing the given objects
pub fn generate_packfile(storage: &GitStorage, oids: &[ObjectId]) -> Result<Vec<u8>> {
    let mut pack = Vec::new();

    // Header: "PACK" + version (2) + object count
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes()); // version 2
    pack.extend_from_slice(&(oids.len() as u32).to_be_bytes());

    // Objects
    for oid in oids {
        let obj = storage.read_object(oid)?;
        write_pack_object(&mut pack, &obj)?;
    }

    // Checksum: SHA-1 of everything before
    let mut hasher = Sha1::new();
    hasher.update(&pack);
    let checksum = hasher.finalize();
    pack.extend_from_slice(&checksum);

    Ok(pack)
}

/// Write a single object to the packfile
fn write_pack_object(pack: &mut Vec<u8>, obj: &GitObject) -> Result<()> {
    let pack_type = PackObjectType::from_object_type(obj.obj_type);
    let size = obj.content.len();

    // Encode type and size in variable-length format
    // First byte: 1-bit MSB continue flag, 3-bit type, 4-bit size LSB
    let mut c = ((pack_type as u8) << 4) | ((size & 0x0F) as u8);
    let mut remaining = size >> 4;

    if remaining > 0 {
        c |= 0x80; // More bytes follow
    }
    pack.push(c);

    // Remaining size bytes: 7 bits each with MSB continue flag
    while remaining > 0 {
        let mut byte = (remaining & 0x7F) as u8;
        remaining >>= 7;
        if remaining > 0 {
            byte |= 0x80;
        }
        pack.push(byte);
    }

    // Compress object content
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&obj.content)?;
    let compressed = encoder.finish()?;
    pack.extend_from_slice(&compressed);

    Ok(())
}

/// Parse a packfile, storing objects and returning their IDs
pub fn parse_packfile(storage: &GitStorage, data: &[u8]) -> Result<Vec<ObjectId>> {
    if data.len() < 20 {
        return Err(Error::PackError("packfile too small".into()));
    }

    // Verify header
    if &data[0..4] != b"PACK" {
        return Err(Error::PackError("invalid packfile magic".into()));
    }

    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(Error::PackError(format!("unsupported pack version: {}", version)));
    }

    let object_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // Verify checksum
    let checksum_start = data.len() - 20;
    let mut hasher = Sha1::new();
    hasher.update(&data[..checksum_start]);
    let computed = hasher.finalize();
    if &computed[..] != &data[checksum_start..] {
        return Err(Error::PackError("checksum mismatch".into()));
    }

    // Parse objects
    let mut pos = 12; // After header
    let mut oids = Vec::with_capacity(object_count as usize);

    for _ in 0..object_count {
        let (obj, bytes_consumed) = parse_pack_object(&data[pos..checksum_start])?;
        pos += bytes_consumed;

        let oid = storage.write_object(&obj)?;
        oids.push(oid);
    }

    Ok(oids)
}

/// Parse a single object from packfile data
fn parse_pack_object(data: &[u8]) -> Result<(GitObject, usize)> {
    let mut pos = 0;

    // Read type and size
    let first_byte = data[pos];
    pos += 1;

    let type_bits = (first_byte >> 4) & 0x07;
    let pack_type = PackObjectType::from_u8(type_bits)
        .ok_or_else(|| Error::PackError(format!("unsupported object type: {}", type_bits)))?;

    let mut size = (first_byte & 0x0F) as usize;
    let mut shift = 4;

    // Read remaining size bytes
    if first_byte & 0x80 != 0 {
        loop {
            if pos >= data.len() {
                return Err(Error::PackError("truncated size".into()));
            }
            let byte = data[pos];
            pos += 1;
            size |= ((byte & 0x7F) as usize) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    // Decompress content
    let mut decoder = ZlibDecoder::new(&data[pos..]);
    let mut content = vec![0u8; size];
    decoder.read_exact(&mut content)?;

    // Calculate how many bytes of compressed data we consumed
    let compressed_size = decoder.total_in() as usize;
    pos += compressed_size;

    let obj = GitObject::new(pack_type.to_object_type(), content);
    Ok((obj, pos))
}

/// Thin packfile generation for upload-pack
/// Generates a packfile with only the objects the client needs
pub struct PackBuilder<'a> {
    storage: &'a GitStorage,
    /// Objects to include
    want: Vec<ObjectId>,
    /// Objects the client already has
    have: Vec<ObjectId>,
}

impl<'a> PackBuilder<'a> {
    pub fn new(storage: &'a GitStorage) -> Self {
        Self {
            storage,
            want: Vec::new(),
            have: Vec::new(),
        }
    }

    pub fn want(&mut self, oid: ObjectId) {
        self.want.push(oid);
    }

    pub fn have(&mut self, oid: ObjectId) {
        self.have.push(oid);
    }

    /// Build the packfile, walking the object graph
    pub fn build(self) -> Result<Vec<u8>> {
        let mut needed = std::collections::HashSet::new();
        let have_set: std::collections::HashSet<_> = self.have.iter().copied().collect();

        // Walk from want commits to find all needed objects
        for oid in &self.want {
            Self::walk_object_static(self.storage, *oid, &have_set, &mut needed)?;
        }

        // Generate packfile
        let oids: Vec<_> = needed.into_iter().collect();
        generate_packfile(self.storage, &oids)
    }

    /// Recursively walk an object and its dependencies
    fn walk_object_static(
        storage: &GitStorage,
        oid: ObjectId,
        have: &std::collections::HashSet<ObjectId>,
        needed: &mut std::collections::HashSet<ObjectId>,
    ) -> Result<()> {
        if have.contains(&oid) || needed.contains(&oid) {
            return Ok(());
        }

        if !storage.has_object(&oid)? {
            return Ok(()); // Object doesn't exist, skip
        }

        needed.insert(oid);

        let obj = storage.read_object(&oid)?;

        match obj.obj_type {
            ObjectType::Commit => {
                // Parse commit to find tree and parents
                let content = String::from_utf8_lossy(&obj.content);
                for line in content.lines() {
                    if let Some(tree_hex) = line.strip_prefix("tree ") {
                        if let Some(tree_oid) = ObjectId::from_hex(tree_hex.trim()) {
                            Self::walk_object_static(storage, tree_oid, have, needed)?;
                        }
                    } else if let Some(parent_hex) = line.strip_prefix("parent ") {
                        if let Some(parent_oid) = ObjectId::from_hex(parent_hex.trim()) {
                            Self::walk_object_static(storage, parent_oid, have, needed)?;
                        }
                    } else if line.is_empty() {
                        break; // End of headers
                    }
                }
            }
            ObjectType::Tree => {
                // Parse tree entries
                let entries = crate::object::parse_tree(&obj.content)?;
                for entry in entries {
                    Self::walk_object_static(storage, entry.oid, have, needed)?;
                }
            }
            ObjectType::Tag => {
                // Parse tag to find object
                let content = String::from_utf8_lossy(&obj.content);
                for line in content.lines() {
                    if let Some(obj_hex) = line.strip_prefix("object ") {
                        if let Some(obj_oid) = ObjectId::from_hex(obj_hex.trim()) {
                            Self::walk_object_static(storage, obj_oid, have, needed)?;
                        }
                    }
                }
            }
            ObjectType::Blob => {
                // Blobs have no dependencies
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_packfile_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create some objects
        let blob1 = storage.write_blob(b"hello").unwrap();
        let blob2 = storage.write_blob(b"world").unwrap();

        // Generate packfile
        let pack = generate_packfile(&storage, &[blob1, blob2]).unwrap();

        // Verify header
        assert_eq!(&pack[0..4], b"PACK");

        // Parse in new storage
        let dir2 = tempdir().unwrap();
        let storage2 = GitStorage::open(dir2.path().join("git")).unwrap();
        let parsed_oids = parse_packfile(&storage2, &pack).unwrap();

        assert_eq!(parsed_oids.len(), 2);
        assert!(storage2.has_object(&blob1).unwrap());
        assert!(storage2.has_object(&blob2).unwrap());
    }
}
