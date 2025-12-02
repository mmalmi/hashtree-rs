//! Git protocol implementation (pkt-line format)
//!
//! Git uses "pkt-line" framing: 4 hex digits length prefix followed by data.
//! Special values: "0000" (flush), "0001" (delimiter), "0002" (response-end)

use crate::{Error, Result};

/// Flush packet (marks end of message)
pub const FLUSH_PKT: &[u8] = b"0000";
/// Delimiter packet (separates sections)
pub const DELIM_PKT: &[u8] = b"0001";
/// Response end packet
pub const RESPONSE_END_PKT: &[u8] = b"0002";

/// Maximum pkt-line data size (65516 bytes payload + 4 length + 1 newline)
pub const MAX_PKT_LINE: usize = 65520;

/// Write a pkt-line
pub fn pkt_line(data: &[u8]) -> Vec<u8> {
    let len = data.len() + 4; // Include the 4-byte length prefix
    let mut pkt = format!("{:04x}", len).into_bytes();
    pkt.extend_from_slice(data);
    pkt
}

/// Write a pkt-line with newline suffix
pub fn pkt_line_with_newline(data: &str) -> Vec<u8> {
    let line = format!("{}\n", data);
    pkt_line(line.as_bytes())
}

/// Parse pkt-lines from a buffer
pub struct PktLineReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PktLineReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read the next pkt-line
    pub fn read(&mut self) -> Result<Option<PktLine<'a>>> {
        if self.pos + 4 > self.data.len() {
            return Ok(None);
        }

        let len_hex = std::str::from_utf8(&self.data[self.pos..self.pos + 4])
            .map_err(|_| Error::ProtocolError("invalid pkt-line length".into()))?;

        // Special packets
        match len_hex {
            "0000" => {
                self.pos += 4;
                return Ok(Some(PktLine::Flush));
            }
            "0001" => {
                self.pos += 4;
                return Ok(Some(PktLine::Delimiter));
            }
            "0002" => {
                self.pos += 4;
                return Ok(Some(PktLine::ResponseEnd));
            }
            _ => {}
        }

        let len = usize::from_str_radix(len_hex, 16)
            .map_err(|_| Error::ProtocolError("invalid pkt-line length".into()))?;

        if len < 4 {
            return Err(Error::ProtocolError("pkt-line length too small".into()));
        }

        if len > MAX_PKT_LINE {
            return Err(Error::ProtocolError("pkt-line too large".into()));
        }

        if self.pos + len > self.data.len() {
            return Err(Error::ProtocolError("pkt-line truncated".into()));
        }

        let payload = &self.data[self.pos + 4..self.pos + len];
        self.pos += len;

        Ok(Some(PktLine::Data(payload)))
    }

    /// Read all remaining pkt-lines until flush
    pub fn read_until_flush(&mut self) -> Result<Vec<&'a [u8]>> {
        let mut lines = Vec::new();
        loop {
            match self.read()? {
                Some(PktLine::Flush) | None => break,
                Some(PktLine::Data(data)) => lines.push(data),
                Some(PktLine::Delimiter) => continue,
                Some(PktLine::ResponseEnd) => break,
            }
        }
        Ok(lines)
    }

    /// Remaining bytes
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

/// A pkt-line entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine<'a> {
    Flush,
    Delimiter,
    ResponseEnd,
    Data(&'a [u8]),
}

/// Build pkt-line responses
pub struct PktLineWriter {
    buffer: Vec<u8>,
}

impl PktLineWriter {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(&pkt_line(data));
    }

    pub fn write_str(&mut self, s: &str) {
        self.buffer.extend_from_slice(&pkt_line_with_newline(s));
    }

    pub fn flush(&mut self) {
        self.buffer.extend_from_slice(FLUSH_PKT);
    }

    pub fn delimiter(&mut self) {
        self.buffer.extend_from_slice(DELIM_PKT);
    }

    pub fn response_end(&mut self) {
        self.buffer.extend_from_slice(RESPONSE_END_PKT);
    }

    pub fn write_raw(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }
}

impl Default for PktLineWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse capability string from ref advertisement
pub fn parse_capabilities(caps_str: &str) -> Vec<String> {
    caps_str.split(' ')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Server capabilities for upload-pack
pub const UPLOAD_PACK_CAPABILITIES: &[&str] = &[
    "multi_ack",
    "multi_ack_detailed",
    "side-band-64k",
    "thin-pack",
    "ofs-delta",
    "shallow",
    "no-progress",
    "include-tag",
    "allow-tip-sha1-in-want",
    "allow-reachable-sha1-in-want",
    "no-done",
];

/// Server capabilities for receive-pack
pub const RECEIVE_PACK_CAPABILITIES: &[&str] = &[
    "report-status",
    "delete-refs",
    "side-band-64k",
    "ofs-delta",
    "atomic",
];

/// Format capabilities as string
pub fn format_capabilities(caps: &[&str]) -> String {
    caps.join(" ")
}

/// Side-band channel IDs
pub mod sideband {
    pub const DATA: u8 = 1;
    pub const PROGRESS: u8 = 2;
    pub const ERROR: u8 = 3;
}

/// Write data to a side-band channel
pub fn sideband_pkt(channel: u8, data: &[u8]) -> Vec<u8> {
    let mut payload = vec![channel];
    payload.extend_from_slice(data);
    pkt_line(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkt_line() {
        let pkt = pkt_line(b"hello");
        assert_eq!(pkt, b"0009hello");
    }

    #[test]
    fn test_pkt_line_with_newline() {
        let pkt = pkt_line_with_newline("hello");
        assert_eq!(pkt, b"000ahello\n");
    }

    #[test]
    fn test_reader() {
        let data = b"0009hello0006ab0000";
        let mut reader = PktLineReader::new(data);

        assert_eq!(reader.read().unwrap(), Some(PktLine::Data(b"hello")));
        assert_eq!(reader.read().unwrap(), Some(PktLine::Data(b"ab")));
        assert_eq!(reader.read().unwrap(), Some(PktLine::Flush));
        assert_eq!(reader.read().unwrap(), None);
    }

    #[test]
    fn test_writer() {
        let mut writer = PktLineWriter::new();
        writer.write_str("hello");
        writer.flush();

        assert_eq!(writer.as_bytes(), b"000ahello\n0000");
    }
}
