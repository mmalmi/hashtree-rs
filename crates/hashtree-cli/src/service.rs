use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub enum ServiceScope {
    User,
    System,
}

#[derive(Debug, Clone)]
pub struct ServiceInstallOptions {
    pub scope: ServiceScope,
    pub name: String,
    pub addr: Option<String>,
    pub relays: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub rust_log: Option<String>,
    pub start_now: bool,
}

#[derive(Debug, Clone)]
pub struct ServiceUninstallOptions {
    pub scope: ServiceScope,
    pub name: String,
}

#[cfg(not(target_os = "linux"))]
pub fn install_systemd(_opts: ServiceInstallOptions) -> Result<PathBuf> {
    bail!("systemd is only supported on Linux");
}

#[cfg(not(target_os = "linux"))]
pub fn uninstall_systemd(_opts: ServiceUninstallOptions) -> Result<()> {
    bail!("systemd is only supported on Linux");
}

#[cfg(target_os = "linux")]
pub fn install_systemd(opts: ServiceInstallOptions) -> Result<PathBuf> {
    let bin_path = std::env::current_exe().context("Failed to resolve htree binary path")?;
    let unit_dir = systemd_unit_dir(opts.scope)?;
    std::fs::create_dir_all(&unit_dir)
        .with_context(|| format!("Failed to create systemd unit dir {}", unit_dir.display()))?;

    let service_name = systemd_unit_name(&opts.name);
    let unit_path = unit_dir.join(&service_name);
    let contents = systemd_unit_contents(&bin_path, &opts);
    std::fs::write(&unit_path, contents)
        .with_context(|| format!("Failed to write unit file {}", unit_path.display()))?;

    run_systemctl(opts.scope, &["daemon-reload"])?;
    if opts.start_now {
        run_systemctl(opts.scope, &["enable", "--now", &service_name])?;
    } else {
        run_systemctl(opts.scope, &["enable", &service_name])?;
    }

    Ok(unit_path)
}

#[cfg(target_os = "linux")]
pub fn uninstall_systemd(opts: ServiceUninstallOptions) -> Result<()> {
    let unit_dir = systemd_unit_dir(opts.scope)?;
    let service_name = systemd_unit_name(&opts.name);
    let unit_path = unit_dir.join(&service_name);

    run_systemctl(opts.scope, &["disable", "--now", &service_name])?;
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("Failed to remove unit file {}", unit_path.display()))?;
    }
    run_systemctl(opts.scope, &["daemon-reload"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn systemd_unit_contents(bin_path: &Path, opts: &ServiceInstallOptions) -> String {
    let mut exec_start = format!("{} start", bin_path.display());
    if let Some(addr) = &opts.addr {
        exec_start.push_str(" --addr ");
        exec_start.push_str(addr);
    }
    if let Some(relays) = &opts.relays {
        exec_start.push_str(" --relays ");
        exec_start.push_str(relays);
    }

    let mut lines = Vec::new();
    lines.push("[Unit]".to_string());
    lines.push("Description=hashtree daemon".to_string());
    lines.push("After=network-online.target".to_string());
    lines.push("Wants=network-online.target".to_string());
    lines.push(String::new());
    lines.push("[Service]".to_string());
    lines.push(format!("ExecStart={}", exec_start));
    if let Some(data_dir) = &opts.data_dir {
        lines.push(format!("Environment=HTREE_DATA_DIR={}", data_dir.display()));
    }
    if let Some(rust_log) = &opts.rust_log {
        lines.push(format!("Environment=RUST_LOG={}", rust_log));
    }
    lines.push("Restart=on-failure".to_string());
    lines.push("RestartSec=2".to_string());
    lines.push(String::new());
    lines.push("[Install]".to_string());
    lines.push(format!("WantedBy={}", systemd_wanted_by(opts.scope)));
    lines.push(String::new());
    lines.join("\n")
}

#[cfg(target_os = "linux")]
pub(crate) fn systemd_unit_dir(scope: ServiceScope) -> Result<PathBuf> {
    match scope {
        ServiceScope::User => {
            if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
                Ok(PathBuf::from(dir).join("systemd/user"))
            } else if let Ok(home) = std::env::var("HOME") {
                Ok(PathBuf::from(home).join(".config/systemd/user"))
            } else {
                bail!("XDG_CONFIG_HOME or HOME must be set for user services");
            }
        }
        ServiceScope::System => Ok(PathBuf::from("/etc/systemd/system")),
    }
}

#[cfg(target_os = "linux")]
fn systemd_wanted_by(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::User => "default.target",
        ServiceScope::System => "multi-user.target",
    }
}

#[cfg(target_os = "linux")]
fn systemd_unit_name(name: &str) -> String {
    let trimmed = name.strip_suffix(".service").unwrap_or(name);
    format!("{}.service", trimmed)
}

#[cfg(target_os = "linux")]
fn run_systemctl(scope: ServiceScope, args: &[&str]) -> Result<()> {
    use std::process::Command;

    let mut cmd = Command::new("systemctl");
    if matches!(scope, ServiceScope::User) {
        cmd.arg("--user");
    }
    cmd.args(args);
    let output = cmd.output().context("Failed to run systemctl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("systemctl {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn renders_systemd_unit_for_user_scope() {
        let _guard = env_lock();
        let opts = ServiceInstallOptions {
            scope: ServiceScope::User,
            name: "hashtree".to_string(),
            addr: Some("127.0.0.1:8081".to_string()),
            relays: Some("wss://relay.damus.io,wss://nos.lol".to_string()),
            data_dir: Some(PathBuf::from("/var/lib/hashtree")),
            rust_log: Some("info".to_string()),
            start_now: true,
        };
        let unit = systemd_unit_contents(Path::new("/usr/local/bin/htree"), &opts);
        assert!(unit.contains("ExecStart=/usr/local/bin/htree start --addr 127.0.0.1:8081 --relays wss://relay.damus.io,wss://nos.lol"));
        assert!(unit.contains("Environment=HTREE_DATA_DIR=/var/lib/hashtree"));
        assert!(unit.contains("Environment=RUST_LOG=info"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn resolves_user_unit_dir_from_xdg_config_home() {
        let _guard = env_lock();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/hashtree-xdg");
        std::env::set_var("HOME", "/tmp/hashtree-home");

        let dir = systemd_unit_dir(ServiceScope::User).expect("unit dir");
        assert_eq!(dir, PathBuf::from("/tmp/hashtree-xdg/systemd/user"));

        if let Some(value) = prev_xdg {
            std::env::set_var("XDG_CONFIG_HOME", value);
        } else {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Some(value) = prev_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }
}
