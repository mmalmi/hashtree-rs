use anyhow::{Context, Result};
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::{Keys, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub nostr: NostrConfig,
    #[serde(default)]
    pub blossom: BlossomConfig,
    #[serde(default)]
    pub sync: SyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_enable_auth")]
    pub enable_auth: bool,
    /// Port for the built-in STUN server (0 = disabled)
    #[serde(default = "default_stun_port")]
    pub stun_port: u16,
    /// Enable WebRTC P2P connections
    #[serde(default = "default_enable_webrtc")]
    pub enable_webrtc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_max_size_gb")]
    pub max_size_gb: u64,
    /// Optional S3/R2 backend for blob storage
    #[serde(default)]
    pub s3: Option<S3Config>,
}

/// S3-compatible storage configuration (works with AWS S3, Cloudflare R2, MinIO, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 endpoint URL (e.g., "https://<account_id>.r2.cloudflarestorage.com" for R2)
    pub endpoint: String,
    /// S3 bucket name
    pub bucket: String,
    /// Optional key prefix for all blobs (e.g., "blobs/")
    #[serde(default)]
    pub prefix: Option<String>,
    /// AWS region (use "auto" for R2)
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// Access key ID (can also be set via AWS_ACCESS_KEY_ID env var)
    #[serde(default)]
    pub access_key: Option<String>,
    /// Secret access key (can also be set via AWS_SECRET_ACCESS_KEY env var)
    #[serde(default)]
    pub secret_key: Option<String>,
    /// Public URL for serving blobs (optional, for generating public URLs)
    #[serde(default)]
    pub public_url: Option<String>,
}

fn default_s3_region() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    #[serde(default = "default_relays")]
    pub relays: Vec<String>,
    /// Social graph root npub (for crawling follows). If not set, uses the local nsec's pubkey.
    #[serde(default)]
    pub socialgraph_root: Option<String>,
    /// Crawl depth for social graph (0 = disabled, 1 = direct follows, 2 = friends of friends, etc)
    #[serde(default = "default_crawl_depth")]
    pub crawl_depth: u32,
    /// Maximum follow distance for write access to relay (None = no restriction)
    /// 0 = only root user, 1 = root + direct follows, 2 = friends of friends, etc.
    #[serde(default)]
    pub max_write_distance: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlossomConfig {
    /// File servers for push/pull (legacy, both read and write)
    #[serde(default)]
    pub servers: Vec<String>,
    /// Read-only file servers (fallback for fetching content)
    #[serde(default = "default_read_servers")]
    pub read_servers: Vec<String>,
    /// Write-enabled file servers (for uploading)
    #[serde(default = "default_write_servers")]
    pub write_servers: Vec<String>,
    /// Maximum upload size in MB (default: 5)
    #[serde(default = "default_max_upload_mb")]
    pub max_upload_mb: u64,
}

fn default_read_servers() -> Vec<String> {
    vec!["https://files.iris.to".to_string()]
}

fn default_write_servers() -> Vec<String> {
    vec!["https://hashtree.iris.to".to_string()]
}

fn default_max_upload_mb() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Enable background sync (auto-pull trees)
    #[serde(default = "default_sync_enabled")]
    pub enabled: bool,
    /// Sync own trees (subscribed via Nostr)
    #[serde(default = "default_sync_own")]
    pub sync_own: bool,
    /// Sync followed users' public trees
    #[serde(default = "default_sync_followed")]
    pub sync_followed: bool,
    /// Max concurrent sync tasks
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// WebRTC request timeout in milliseconds
    #[serde(default = "default_webrtc_timeout_ms")]
    pub webrtc_timeout_ms: u64,
    /// Blossom request timeout in milliseconds
    #[serde(default = "default_blossom_timeout_ms")]
    pub blossom_timeout_ms: u64,
}


fn default_sync_enabled() -> bool {
    true
}

fn default_sync_own() -> bool {
    true
}

fn default_sync_followed() -> bool {
    true
}

fn default_max_concurrent() -> usize {
    3
}

fn default_webrtc_timeout_ms() -> u64 {
    2000
}

fn default_blossom_timeout_ms() -> u64 {
    10000
}

fn default_crawl_depth() -> u32 {
    3
}

fn default_relays() -> Vec<String> {
    vec![
        "wss://relay.damus.io".to_string(),
        "wss://relay.snort.social".to_string(),
        "wss://nos.lol".to_string(),
        "wss://temp.iris.to".to_string(),
    ]
}

fn default_bind_address() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_enable_auth() -> bool {
    true
}

fn default_stun_port() -> u16 {
    3478 // Standard STUN port (RFC 5389)
}

fn default_enable_webrtc() -> bool {
    true
}

fn default_data_dir() -> String {
    get_hashtree_dir()
        .join("data")
        .to_string_lossy()
        .to_string()
}

fn default_max_size_gb() -> u64 {
    10
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            enable_auth: default_enable_auth(),
            stun_port: default_stun_port(),
            enable_webrtc: default_enable_webrtc(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            max_size_gb: default_max_size_gb(),
            s3: None,
        }
    }
}

impl Default for NostrConfig {
    fn default() -> Self {
        Self {
            relays: default_relays(),
            socialgraph_root: None,
            crawl_depth: default_crawl_depth(),
            max_write_distance: None,
        }
    }
}

impl Default for BlossomConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            read_servers: default_read_servers(),
            write_servers: default_write_servers(),
            max_upload_mb: default_max_upload_mb(),
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: default_sync_enabled(),
            sync_own: default_sync_own(),
            sync_followed: default_sync_followed(),
            max_concurrent: default_max_concurrent(),
            webrtc_timeout_ms: default_webrtc_timeout_ms(),
            blossom_timeout_ms: default_blossom_timeout_ms(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            nostr: NostrConfig::default(),
            blossom: BlossomConfig::default(),
            sync: SyncConfig::default(),
        }
    }
}

impl Config {
    /// Load config from file, or create default if doesn't exist
    pub fn load() -> Result<Self> {
        let config_path = get_config_path();

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .context("Failed to read config file")?;
            toml::from_str(&content).context("Failed to parse config file")
        } else {
            let config = Config::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save config to file
    pub fn save(&self) -> Result<()> {
        let config_path = get_config_path();

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content)?;

        Ok(())
    }
}

/// Get the hashtree directory (~/.hashtree)
pub fn get_hashtree_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".hashtree")
}

/// Get the config file path (~/.hashtree/config.toml)
pub fn get_config_path() -> PathBuf {
    get_hashtree_dir().join("config.toml")
}

/// Get the auth cookie path (~/.hashtree/auth.cookie)
pub fn get_auth_cookie_path() -> PathBuf {
    get_hashtree_dir().join("auth.cookie")
}

/// Get the nostrdb directory (~/.hashtree/nostrdb)
pub fn get_nostrdb_dir() -> PathBuf {
    get_hashtree_dir().join("nostrdb")
}

/// Get the nsec file path (~/.hashtree/nsec)
pub fn get_nsec_path() -> PathBuf {
    get_hashtree_dir().join("nsec")
}

/// Initialize nostrdb with reasonable defaults (similar to notedeck)
pub fn init_nostrdb() -> Result<nostrdb::Ndb> {
    init_nostrdb_at(get_nostrdb_dir())
}

/// Initialize nostrdb at a specific path
pub fn init_nostrdb_at<P: AsRef<std::path::Path>>(path: P) -> Result<nostrdb::Ndb> {
    let db_path = path.as_ref();

    // Create directory if needed
    fs::create_dir_all(db_path)?;

    // Map size: 1 TiB on unix (virtual), 16 GiB on windows (actual file)
    let map_size = if cfg!(target_os = "windows") {
        1024 * 1024 * 1024 * 16 // 16 GiB
    } else {
        1024 * 1024 * 1024 * 1024 // 1 TiB
    };

    let config = nostrdb::Config::new()
        .set_ingester_threads(2)
        .set_mapsize(map_size);

    let db_path_str = db_path.to_string_lossy();
    nostrdb::Ndb::new(&db_path_str, &config)
        .context("Failed to initialize nostrdb")
}

/// Generate and save auth cookie if it doesn't exist
pub fn ensure_auth_cookie() -> Result<(String, String)> {
    let cookie_path = get_auth_cookie_path();

    if cookie_path.exists() {
        read_auth_cookie()
    } else {
        generate_auth_cookie()
    }
}

/// Read existing auth cookie
pub fn read_auth_cookie() -> Result<(String, String)> {
    let cookie_path = get_auth_cookie_path();
    let content = fs::read_to_string(&cookie_path)
        .context("Failed to read auth cookie")?;

    let parts: Vec<&str> = content.trim().split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid auth cookie format");
    }

    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Ensure nsec exists, generating one if not present
/// Returns (Keys, was_generated)
pub fn ensure_nsec() -> Result<(Keys, bool)> {
    let nsec_path = get_nsec_path();

    if nsec_path.exists() {
        let nsec_str = fs::read_to_string(&nsec_path)
            .context("Failed to read nsec file")?;
        let nsec_str = nsec_str.trim();
        let secret_key = SecretKey::from_bech32(nsec_str)
            .context("Invalid nsec format")?;
        let keys = Keys::new(secret_key);
        Ok((keys, false))
    } else {
        let keys = generate_nsec()?;
        Ok((keys, true))
    }
}

/// Read existing nsec
pub fn read_nsec() -> Result<Keys> {
    let nsec_path = get_nsec_path();
    let nsec_str = fs::read_to_string(&nsec_path)
        .context("Failed to read nsec file")?;
    let nsec_str = nsec_str.trim();
    let secret_key = SecretKey::from_bech32(nsec_str)
        .context("Invalid nsec format")?;
    Ok(Keys::new(secret_key))
}

/// Get nsec string, ensuring it exists (generate if needed)
/// Returns (nsec_string, was_generated)
pub fn ensure_nsec_string() -> Result<(String, bool)> {
    let nsec_path = get_nsec_path();

    if nsec_path.exists() {
        let nsec_str = fs::read_to_string(&nsec_path)
            .context("Failed to read nsec file")?;
        Ok((nsec_str.trim().to_string(), false))
    } else {
        let keys = generate_nsec()?;
        let nsec = keys.secret_key().to_bech32()
            .context("Failed to encode nsec")?;
        Ok((nsec, true))
    }
}

/// Generate new nsec and save to file
pub fn generate_nsec() -> Result<Keys> {
    let nsec_path = get_nsec_path();

    // Ensure parent directory exists
    if let Some(parent) = nsec_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Generate new keys
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32()
        .context("Failed to encode nsec")?;

    // Save to file
    fs::write(&nsec_path, &nsec)?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&nsec_path, perms)?;
    }

    Ok(keys)
}

/// Get 32-byte pubkey bytes from Keys (for nostrdb)
pub fn pubkey_bytes(keys: &Keys) -> [u8; 32] {
    keys.public_key().to_bytes()
}

/// Parse npub to 32-byte pubkey
pub fn parse_npub(npub: &str) -> Result<[u8; 32]> {
    use nostr::PublicKey;
    let pk = PublicKey::from_bech32(npub)
        .context("Invalid npub format")?;
    Ok(pk.to_bytes())
}

/// Generate new random auth cookie
pub fn generate_auth_cookie() -> Result<(String, String)> {
    use rand::Rng;

    let cookie_path = get_auth_cookie_path();

    // Ensure parent directory exists
    if let Some(parent) = cookie_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Generate random credentials
    let mut rng = rand::thread_rng();
    let username = format!("htree_{}", rng.gen::<u32>());
    let password: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=25 => (b'a' + idx) as char,
                26..=51 => (b'A' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();

    // Save to file
    let content = format!("{}:{}", username, password);
    fs::write(&cookie_path, content)?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&cookie_path, perms)?;
    }

    Ok((username, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server.bind_address, "127.0.0.1:8080");
        assert_eq!(config.server.enable_auth, true);
        assert_eq!(config.storage.max_size_gb, 10);
    }

    #[test]
    fn test_auth_cookie_generation() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Mock the cookie path
        std::env::set_var("HOME", temp_dir.path());

        let (username, password) = generate_auth_cookie()?;

        assert!(username.starts_with("htree_"));
        assert_eq!(password.len(), 32);

        // Verify cookie file exists
        let cookie_path = get_auth_cookie_path();
        assert!(cookie_path.exists());

        // Verify reading works
        let (u2, p2) = read_auth_cookie()?;
        assert_eq!(username, u2);
        assert_eq!(password, p2);

        Ok(())
    }
}
