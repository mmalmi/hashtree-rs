//! Configuration loading for git-remote-htree
//!
//! Reads from ~/.hashtree/config.toml, using same format as hashtree-cli

use serde::Deserialize;
use std::path::PathBuf;

/// Default read-only file servers
pub const DEFAULT_READ_SERVERS: &[&str] = &["https://files.iris.to"];

/// Default write-enabled file servers
pub const DEFAULT_WRITE_SERVERS: &[&str] = &["https://hashtree.iris.to"];

/// Default nostr relays
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://temp.iris.to",
];

/// Top-level config structure (subset of hashtree-cli config)
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub blossom: BlossomConfig,
    #[serde(default)]
    pub nostr: NostrConfig,
}

/// File server (blossom) configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BlossomConfig {
    /// Legacy servers field (both read and write)
    #[serde(default)]
    pub servers: Vec<String>,
    /// Read-only file servers
    #[serde(default = "default_read_servers")]
    pub read_servers: Vec<String>,
    /// Write-enabled file servers
    #[serde(default = "default_write_servers")]
    pub write_servers: Vec<String>,
}

impl Default for BlossomConfig {
    fn default() -> Self {
        Self {
            servers: vec![],
            read_servers: default_read_servers(),
            write_servers: default_write_servers(),
        }
    }
}

fn default_read_servers() -> Vec<String> {
    DEFAULT_READ_SERVERS.iter().map(|s| s.to_string()).collect()
}

fn default_write_servers() -> Vec<String> {
    DEFAULT_WRITE_SERVERS.iter().map(|s| s.to_string()).collect()
}

/// Nostr relay configuration
#[derive(Debug, Clone, Deserialize)]
pub struct NostrConfig {
    #[serde(default = "default_relays")]
    pub relays: Vec<String>,
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            relays: default_relays(),
        }
    }
}

fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

impl BlossomConfig {
    /// Get all read servers (legacy + read_servers)
    pub fn all_read_servers(&self) -> Vec<String> {
        let mut servers = self.servers.clone();
        servers.extend(self.read_servers.clone());
        // Deduplicate
        servers.sort();
        servers.dedup();
        servers
    }

    /// Get all write servers (legacy + write_servers)
    #[allow(dead_code)]
    pub fn all_write_servers(&self) -> Vec<String> {
        let mut servers = self.servers.clone();
        servers.extend(self.write_servers.clone());
        // Deduplicate
        servers.sort();
        servers.dedup();
        servers
    }
}

/// Load config from ~/.hashtree/config.toml
pub fn load_config() -> Config {
    let config_path = get_config_path();

    if let Ok(content) = std::fs::read_to_string(&config_path) {
        match toml::from_str(&content) {
            Ok(config) => return config,
            Err(e) => {
                eprintln!("[git-remote-htree] Warning: Failed to parse config: {}", e);
            }
        }
    }

    Config::default()
}

fn get_config_path() -> PathBuf {
    if let Ok(dir) = std::env::var("HTREE_CONFIG_DIR") {
        return PathBuf::from(dir).join("config.toml");
    }

    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".hashtree")
        .join("config.toml")
}

mod dirs {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.blossom.read_servers.is_empty());
        assert!(!config.blossom.write_servers.is_empty());
        assert!(!config.nostr.relays.is_empty());
    }

    #[test]
    fn test_parse_empty_config() {
        let config: Config = toml::from_str("").unwrap();
        assert!(!config.blossom.read_servers.is_empty());
    }

    #[test]
    fn test_parse_partial_config() {
        let toml = r#"
[blossom]
write_servers = ["https://custom.server"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.blossom.write_servers, vec!["https://custom.server"]);
        // read_servers should still have defaults
        assert!(!config.blossom.read_servers.is_empty());
    }
}
