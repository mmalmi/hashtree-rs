//! Git smart HTTP protocol handlers
//!
//! Implements:
//! - GET  /info/refs?service=git-upload-pack
//! - GET  /info/refs?service=git-receive-pack
//! - POST /git-upload-pack
//! - POST /git-receive-pack

use crate::object::ObjectId;
use crate::pack::{PackBuilder, parse_packfile};
use crate::protocol::*;
use crate::refs::Ref;
use crate::storage::GitStorage;
use crate::{Error, Result};

/// Service types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Service::UploadPack => "application/x-git-upload-pack-advertisement",
            Service::ReceivePack => "application/x-git-receive-pack-advertisement",
        }
    }

    pub fn result_content_type(&self) -> &'static str {
        match self {
            Service::UploadPack => "application/x-git-upload-pack-result",
            Service::ReceivePack => "application/x-git-receive-pack-result",
        }
    }
}

/// Handle GET /info/refs?service=git-upload-pack or git-receive-pack
pub fn handle_info_refs(storage: &GitStorage, service: Service) -> Result<(String, Vec<u8>)> {
    let mut writer = PktLineWriter::new();

    // Service announcement
    writer.write_str(&format!("# service={}", service.as_str()));
    writer.flush();

    // Get all refs
    let refs = storage.list_refs()?;

    // Capabilities string for first ref
    let caps = match service {
        Service::UploadPack => format_capabilities(UPLOAD_PACK_CAPABILITIES),
        Service::ReceivePack => format_capabilities(RECEIVE_PACK_CAPABILITIES),
    };

    if refs.is_empty() {
        // Empty repo - advertise capabilities with zero-id
        let zero = ObjectId::ZERO;
        writer.write_str(&format!("{} capabilities^{{}}\0{}", zero, caps));
    } else {
        let mut first = true;
        // HEAD first if it exists
        if let Ok(head_oid) = storage.resolve_ref("HEAD") {
            if first {
                writer.write_str(&format!("{} HEAD\0{}", head_oid, caps));
                first = false;
            } else {
                writer.write_str(&format!("{} HEAD", head_oid));
            }
        }

        // All other refs
        for named_ref in &refs {
            if named_ref.name == "HEAD" {
                continue;
            }
            if let Ok(oid) = storage.resolve_ref(&named_ref.name) {
                if first {
                    writer.write_str(&format!("{} {}\0{}", oid, named_ref.name, caps));
                    first = false;
                } else {
                    writer.write_str(&format!("{} {}", oid, named_ref.name));
                }
            }
        }
    }

    writer.flush();
    Ok((service.content_type().to_string(), writer.into_bytes()))
}

/// Handle POST /git-upload-pack (client wants to fetch)
pub fn handle_upload_pack(storage: &GitStorage, body: &[u8]) -> Result<Vec<u8>> {
    let mut reader = PktLineReader::new(body);
    let mut wants = Vec::new();
    let mut haves = Vec::new();
    let mut done = false;

    // Parse want/have lines
    while let Some(pkt) = reader.read()? {
        match pkt {
            PktLine::Flush => break,
            PktLine::Data(data) => {
                let line = std::str::from_utf8(data)
                    .map_err(|_| Error::ProtocolError("invalid utf8".into()))?
                    .trim();

                if let Some(rest) = line.strip_prefix("want ") {
                    let oid_hex = rest.split(' ').next().unwrap_or(rest);
                    if let Some(oid) = ObjectId::from_hex(oid_hex) {
                        wants.push(oid);
                    }
                } else if let Some(oid_hex) = line.strip_prefix("have ") {
                    if let Some(oid) = ObjectId::from_hex(oid_hex.trim()) {
                        haves.push(oid);
                    }
                } else if line == "done" {
                    done = true;
                }
            }
            _ => {}
        }
    }

    // Check for "done" in remaining data after flush
    let remaining = reader.remaining();
    if !remaining.is_empty() {
        let mut reader2 = PktLineReader::new(remaining);
        while let Some(pkt) = reader2.read()? {
            if let PktLine::Data(data) = pkt {
                let line = std::str::from_utf8(data).unwrap_or("").trim();
                if line == "done" {
                    done = true;
                } else if let Some(oid_hex) = line.strip_prefix("have ") {
                    if let Some(oid) = ObjectId::from_hex(oid_hex.trim()) {
                        haves.push(oid);
                    }
                }
            }
        }
    }

    let mut response = PktLineWriter::new();

    if wants.is_empty() {
        // Nothing to send
        response.write_str("NAK");
        response.flush();
        return Ok(response.into_bytes());
    }

    // For multi_ack_detailed, we need to ACK common commits
    // and send "ready" when we have enough in common
    let mut common_commits = Vec::new();
    for have in &haves {
        if storage.has_object(have)? {
            common_commits.push(*have);
        }
    }

    // ACK phase for multi_ack_detailed
    if !common_commits.is_empty() {
        for oid in &common_commits {
            response.write_str(&format!("ACK {} common", oid));
        }
        // Send ready to indicate we're done negotiating
        if let Some(last) = common_commits.last() {
            response.write_str(&format!("ACK {} ready", last));
        }
    }

    // Final NAK to signal end of ACK phase
    response.write_str("NAK");

    // Build and send packfile
    let mut builder = PackBuilder::new(storage);
    for oid in wants {
        builder.want(oid);
    }
    for oid in common_commits {
        builder.have(oid);
    }

    let pack = builder.build()?;

    // Send packfile with sideband-64k
    const CHUNK_SIZE: usize = 65515; // Leave room for sideband byte

    for chunk in pack.chunks(CHUNK_SIZE) {
        response.write_raw(&sideband_pkt(sideband::DATA, chunk));
    }

    // Send flush to signal end of packfile
    response.flush();

    Ok(response.into_bytes())
}

/// Handle POST /git-receive-pack (client wants to push)
pub fn handle_receive_pack(storage: &GitStorage, body: &[u8]) -> Result<Vec<u8>> {
    let mut reader = PktLineReader::new(body);
    let mut commands = Vec::new();
    let mut use_sideband = false;

    // Parse ref update commands
    while let Some(pkt) = reader.read()? {
        match pkt {
            PktLine::Flush => break,
            PktLine::Data(data) => {
                let line = std::str::from_utf8(data)
                    .map_err(|_| Error::ProtocolError("invalid utf8".into()))?
                    .trim();

                // Format: <old-oid> <new-oid> <ref-name>\0<caps>
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 3 {
                    let old_oid = if parts[0] == ObjectId::ZERO.to_hex() {
                        None
                    } else {
                        ObjectId::from_hex(parts[0])
                    };
                    let new_oid = if parts[1] == ObjectId::ZERO.to_hex() {
                        None
                    } else {
                        ObjectId::from_hex(parts[1])
                    };
                    // Strip capabilities from ref name
                    let ref_and_caps = parts[2];
                    let (ref_name, caps) = ref_and_caps.split_once('\0')
                        .map(|(r, c)| (r.to_string(), Some(c)))
                        .unwrap_or_else(|| (ref_and_caps.to_string(), None));

                    // Check for sideband capability
                    if let Some(caps_str) = caps {
                        if caps_str.contains("side-band-64k") || caps_str.contains("side-band") {
                            use_sideband = true;
                        }
                    }

                    commands.push(RefCommand { old_oid, new_oid, ref_name });
                }
            }
            _ => {}
        }
    }

    // Parse packfile from remaining data
    let pack_data = reader.remaining();
    if !pack_data.is_empty() {
        // Store objects from packfile
        parse_packfile(storage, pack_data)?;
    }

    // Apply ref updates and build report
    let mut report = Vec::new();
    report.push("unpack ok\n".to_string());

    for cmd in &commands {
        let result = apply_ref_command(storage, cmd);
        match result {
            Ok(()) => {
                report.push(format!("ok {}\n", cmd.ref_name));
            }
            Err(e) => {
                report.push(format!("ng {} {}\n", cmd.ref_name, e));
            }
        }
    }

    let mut response = PktLineWriter::new();

    if use_sideband {
        // When sideband is negotiated, send status via sideband channel 1
        // Build the report as pkt-lines first
        let mut report_pkt = PktLineWriter::new();
        for line in &report {
            report_pkt.write_str(line.trim());
        }
        report_pkt.flush();

        // Send the whole report via sideband
        let report_bytes = report_pkt.into_bytes();
        response.write_raw(&sideband_pkt(sideband::DATA, &report_bytes));
    } else {
        // Plain pkt-lines
        for line in &report {
            response.write_str(line.trim());
        }
    }

    response.flush();
    Ok(response.into_bytes())
}

/// A ref update command
#[derive(Debug)]
struct RefCommand {
    old_oid: Option<ObjectId>,
    new_oid: Option<ObjectId>,
    ref_name: String,
}

/// Apply a ref update command
fn apply_ref_command(storage: &GitStorage, cmd: &RefCommand) -> Result<()> {
    match (&cmd.old_oid, &cmd.new_oid) {
        (None, Some(new)) => {
            // Create new ref
            storage.write_ref(&cmd.ref_name, &Ref::Direct(*new))?;
        }
        (Some(_old), Some(new)) => {
            // Update ref (we skip CAS check for simplicity)
            storage.write_ref(&cmd.ref_name, &Ref::Direct(*new))?;
        }
        (Some(_old), None) => {
            // Delete ref
            storage.delete_ref(&cmd.ref_name)?;
        }
        (None, None) => {
            // No-op
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_info_refs_empty_repo() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        let (content_type, body) = handle_info_refs(&storage, Service::UploadPack).unwrap();
        assert_eq!(content_type, "application/x-git-upload-pack-advertisement");

        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("# service=git-upload-pack"));
        assert!(body_str.contains("capabilities^{}"));
    }

    #[test]
    fn test_info_refs_with_ref() {
        let dir = tempdir().unwrap();
        let storage = GitStorage::open(dir.path().join("git")).unwrap();

        // Create a commit
        let tree_content = b"";
        let tree_oid = storage.write_tree(tree_content).unwrap();

        let commit_content = format!(
            "tree {}\nauthor Test <test@test.com> 1234567890 +0000\ncommitter Test <test@test.com> 1234567890 +0000\n\nInitial commit\n",
            tree_oid
        );
        let commit_oid = storage.write_commit(commit_content.as_bytes()).unwrap();

        // Create ref
        storage.write_ref("refs/heads/main", &Ref::Direct(commit_oid)).unwrap();
        storage.write_ref("HEAD", &Ref::Symbolic("refs/heads/main".into())).unwrap();

        let (_, body) = handle_info_refs(&storage, Service::UploadPack).unwrap();
        let body_str = String::from_utf8_lossy(&body);

        assert!(body_str.contains(&commit_oid.to_hex()));
        assert!(body_str.contains("refs/heads/main"));
    }
}
