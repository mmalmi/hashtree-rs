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

#[derive(Debug, Clone)]
pub struct ServiceStatusOptions {
    pub scope: ServiceScope,
    pub name: String,
}

pub fn install_service(opts: ServiceInstallOptions) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        return install_systemd(opts);
    }
    #[cfg(target_os = "macos")]
    {
        return install_launchd(opts);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = opts;
        bail!("service install is only supported on Linux (systemd) or macOS (launchd)");
    }
}

pub fn uninstall_service(opts: ServiceUninstallOptions) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return uninstall_systemd(opts);
    }
    #[cfg(target_os = "macos")]
    {
        return uninstall_launchd(opts);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = opts;
        bail!("service uninstall is only supported on Linux (systemd) or macOS (launchd)");
    }
}

pub fn status_service(opts: ServiceStatusOptions) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        return status_systemd(opts);
    }
    #[cfg(target_os = "macos")]
    {
        return status_launchd(opts);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = opts;
        bail!("service status is only supported on Linux (systemd) or macOS (launchd)");
    }
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) fn launchd_plist_contents(bin_path: &Path, label: &str, opts: &ServiceInstallOptions) -> String {
    let mut args = Vec::new();
    args.push(bin_path.display().to_string());
    args.push("start".to_string());
    if let Some(addr) = &opts.addr {
        args.push("--addr".to_string());
        args.push(addr.clone());
    }
    if let Some(relays) = &opts.relays {
        args.push("--relays".to_string());
        args.push(relays.clone());
    }

    let mut lines = Vec::new();
    lines.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_string());
    lines.push(r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#.to_string());
    lines.push(r#"<plist version="1.0">"#.to_string());
    lines.push("<dict>".to_string());
    lines.push("  <key>Label</key>".to_string());
    lines.push(format!("  <string>{}</string>", xml_escape(label)));
    lines.push("  <key>ProgramArguments</key>".to_string());
    lines.push("  <array>".to_string());
    for arg in args {
        lines.push(format!("    <string>{}</string>", xml_escape(&arg)));
    }
    lines.push("  </array>".to_string());
    if opts.data_dir.is_some() || opts.rust_log.is_some() {
        lines.push("  <key>EnvironmentVariables</key>".to_string());
        lines.push("  <dict>".to_string());
        if let Some(data_dir) = &opts.data_dir {
            lines.push("    <key>HTREE_DATA_DIR</key>".to_string());
            lines.push(format!("    <string>{}</string>", xml_escape(&data_dir.display().to_string())));
        }
        if let Some(rust_log) = &opts.rust_log {
            lines.push("    <key>RUST_LOG</key>".to_string());
            lines.push(format!("    <string>{}</string>", xml_escape(rust_log)));
        }
        lines.push("  </dict>".to_string());
    }
    lines.push("  <key>RunAtLoad</key>".to_string());
    lines.push("  <true/>".to_string());
    lines.push("  <key>KeepAlive</key>".to_string());
    lines.push("  <true/>".to_string());
    lines.push("</dict>".to_string());
    lines.push("</plist>".to_string());
    lines.join("\n")
}

#[cfg(any(test, target_os = "macos"))]
pub(crate) fn launchd_plist_dir(scope: ServiceScope) -> Result<PathBuf> {
    match scope {
        ServiceScope::User => {
            if let Ok(home) = std::env::var("HOME") {
                Ok(PathBuf::from(home).join("Library/LaunchAgents"))
            } else {
                bail!("HOME must be set for user launchd services");
            }
        }
        ServiceScope::System => Ok(PathBuf::from("/Library/LaunchDaemons")),
    }
}

#[cfg(target_os = "macos")]
fn launchd_label(name: &str) -> String {
    let trimmed = name.strip_suffix(".plist").unwrap_or(name);
    let trimmed = trimmed.strip_suffix(".service").unwrap_or(trimmed);
    trimmed.to_string()
}

#[cfg(target_os = "macos")]
fn launchd_plist_name(name: &str) -> String {
    format!("{}.plist", launchd_label(name))
}

#[cfg(any(test, target_os = "macos"))]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(not(target_os = "linux"))]
pub fn install_systemd(_opts: ServiceInstallOptions) -> Result<PathBuf> {
    bail!("systemd is only supported on Linux");
}

#[cfg(not(target_os = "linux"))]
pub fn uninstall_systemd(_opts: ServiceUninstallOptions) -> Result<()> {
    bail!("systemd is only supported on Linux");
}

#[cfg(not(target_os = "macos"))]
pub fn install_launchd(_opts: ServiceInstallOptions) -> Result<PathBuf> {
    bail!("launchd is only supported on macOS");
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall_launchd(_opts: ServiceUninstallOptions) -> Result<()> {
    bail!("launchd is only supported on macOS");
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

    if let Err(err) = run_systemctl(opts.scope, &["daemon-reload"]) {
        if is_systemctl_bus_error(&err.to_string()) {
            eprintln!("{}", systemctl_unavailable_hint(opts.scope, &service_name, Some(&unit_path)));
            return Ok(unit_path);
        }
        return Err(err);
    }

    let enable_args = if opts.start_now {
        vec!["enable", "--now", &service_name]
    } else {
        vec!["enable", &service_name]
    };
    if let Err(err) = run_systemctl(opts.scope, &enable_args) {
        if is_systemctl_bus_error(&err.to_string()) {
            eprintln!("{}", systemctl_unavailable_hint(opts.scope, &service_name, Some(&unit_path)));
            return Ok(unit_path);
        }
        return Err(err);
    }

    Ok(unit_path)
}

#[cfg(target_os = "linux")]
pub fn uninstall_systemd(opts: ServiceUninstallOptions) -> Result<()> {
    let unit_dir = systemd_unit_dir(opts.scope)?;
    let service_name = systemd_unit_name(&opts.name);
    let unit_path = unit_dir.join(&service_name);

    if let Err(err) = run_systemctl(opts.scope, &["disable", "--now", &service_name]) {
        if !is_systemctl_bus_error(&err.to_string()) {
            return Err(err);
        }
    }
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("Failed to remove unit file {}", unit_path.display()))?;
    }
    if let Err(err) = run_systemctl(opts.scope, &["daemon-reload"]) {
        if !is_systemctl_bus_error(&err.to_string()) {
            return Err(err);
        }
    }
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

#[cfg(target_os = "linux")]
fn run_systemctl_capture(scope: ServiceScope, args: &[&str], allow_fail: bool) -> Result<String> {
    use std::process::Command;

    let mut cmd = Command::new("systemctl");
    if matches!(scope, ServiceScope::User) {
        cmd.arg("--user");
    }
    cmd.args(args);
    let output = cmd.output().context("Failed to run systemctl")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };
    if !output.status.success() && !allow_fail {
        bail!("systemctl {} failed: {}", args.join(" "), combined);
    }
    Ok(combined)
}

#[cfg(target_os = "linux")]
fn status_systemd(opts: ServiceStatusOptions) -> Result<String> {
    let service = systemd_unit_name(&opts.name);
    let active_output = run_systemctl_capture(opts.scope, &["is-active", &service], true)?;
    if is_systemctl_bus_error(&active_output) {
        return Ok(systemd_status_unavailable(&service, opts.scope, &active_output));
    }
    let enabled_output = run_systemctl_capture(opts.scope, &["is-enabled", &service], true)?;
    if is_systemctl_bus_error(&enabled_output) {
        return Ok(systemd_status_unavailable(&service, opts.scope, &enabled_output));
    }
    let status_output = run_systemctl_capture(opts.scope, &["status", &service, "--no-pager", "--full"], true)?;
    if is_systemctl_bus_error(&status_output) {
        return Ok(systemd_status_unavailable(&service, opts.scope, &status_output));
    }

    let active = normalize_status_value(active_output);
    let enabled = normalize_status_value(enabled_output);
    Ok(systemd_status_summary(&service, opts.scope, &enabled, &active, &status_output))
}

#[cfg(target_os = "linux")]
fn normalize_status_value(value: String) -> String {
    let trimmed = value.lines().next().unwrap_or("").trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(target_os = "linux")]
fn systemd_status_summary(service: &str, scope: ServiceScope, enabled: &str, active: &str, status: &str) -> String {
    let scope_label = match scope {
        ServiceScope::User => "user",
        ServiceScope::System => "system",
    };
    let status_text = if status.trim().is_empty() {
        "(no output)"
    } else {
        status.trim()
    };
    format!(
        "Service: {}\nScope: {}\nEnabled: {}\nActive: {}\nStatus:\n{}",
        service, scope_label, enabled, active, status_text
    )
}

#[cfg(target_os = "linux")]
fn systemd_status_unavailable(service: &str, scope: ServiceScope, message: &str) -> String {
    let scope_label = match scope {
        ServiceScope::User => "user",
        ServiceScope::System => "system",
    };
    format!(
        "Service: {}\nScope: {}\nStatus: systemd unavailable ({})",
        service,
        scope_label,
        message.lines().next().unwrap_or("unknown error")
    )
}

#[cfg(target_os = "linux")]
fn is_systemctl_bus_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("failed to connect to bus")
        || lower.contains("no medium found")
        || lower.contains("failed to connect to system bus")
        || lower.contains("failed to connect to user bus")
}

#[cfg(target_os = "linux")]
fn systemctl_scope_args(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::User => "--user ",
        ServiceScope::System => "",
    }
}

#[cfg(target_os = "linux")]
fn systemctl_unavailable_hint(scope: ServiceScope, service_name: &str, unit_path: Option<&Path>) -> String {
    let prefix = systemctl_scope_args(scope);
    let mut lines = Vec::new();
    if let Some(path) = unit_path {
        lines.push(format!("systemd unavailable; wrote unit file to {}", path.display()));
    } else {
        lines.push("systemd unavailable; unit file written".to_string());
    }
    lines.push(format!("Run when systemd is available:"));
    lines.push(format!("  systemctl {}daemon-reload", prefix));
    lines.push(format!("  systemctl {}enable --now {}", prefix, service_name));
    lines.join("\n")
}

#[cfg(target_os = "macos")]
pub fn install_launchd(opts: ServiceInstallOptions) -> Result<PathBuf> {
    let bin_path = std::env::current_exe().context("Failed to resolve htree binary path")?;
    let plist_dir = launchd_plist_dir(opts.scope)?;
    std::fs::create_dir_all(&plist_dir)
        .with_context(|| format!("Failed to create launchd directory {}", plist_dir.display()))?;

    let label = launchd_label(&opts.name);
    let plist_name = launchd_plist_name(&opts.name);
    let plist_path = plist_dir.join(&plist_name);
    let contents = launchd_plist_contents(&bin_path, &label, &opts);
    std::fs::write(&plist_path, contents)
        .with_context(|| format!("Failed to write plist {}", plist_path.display()))?;

    let domain = launchd_domain(opts.scope)?;
    let plist_path_str = plist_path.to_string_lossy().to_string();
    run_launchctl(&["bootstrap", &domain, &plist_path_str])?;

    let service_target = format!("{}/{}", domain, label);
    run_launchctl(&["enable", &service_target])?;
    if opts.start_now {
        run_launchctl(&["kickstart", "-k", &service_target])?;
    }

    Ok(plist_path)
}

#[cfg(target_os = "macos")]
pub fn uninstall_launchd(opts: ServiceUninstallOptions) -> Result<()> {
    let plist_dir = launchd_plist_dir(opts.scope)?;
    let label = launchd_label(&opts.name);
    let plist_name = launchd_plist_name(&opts.name);
    let plist_path = plist_dir.join(&plist_name);
    let domain = launchd_domain(opts.scope)?;

    let service_target = format!("{}/{}", domain, label);
    let plist_path_str = plist_path.to_string_lossy().to_string();
    if plist_path.exists() {
        run_launchctl(&["bootout", &domain, &plist_path_str])?;
    } else {
        run_launchctl(&["bootout", &domain, &label])?;
    }
    if plist_path.exists() {
        std::fs::remove_file(&plist_path)
            .with_context(|| format!("Failed to remove plist {}", plist_path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn status_launchd(opts: ServiceStatusOptions) -> Result<String> {
    let label = launchd_label(&opts.name);
    let domain = launchd_domain(opts.scope)?;
    let list_output = run_launchctl_capture(&["list", &label], true)?;
    let target = format!("{}/{}", domain, label);
    let print_output = run_launchctl_capture(&["print", &target], true)?;
    Ok(launchd_status_summary(&label, opts.scope, &list_output, &print_output))
}

#[cfg(target_os = "macos")]
fn launchd_status_summary(label: &str, scope: ServiceScope, list_output: &str, print_output: &str) -> String {
    let scope_label = match scope {
        ServiceScope::User => "user",
        ServiceScope::System => "system",
    };
    let list_text = if list_output.trim().is_empty() {
        "(no output)"
    } else {
        list_output.trim()
    };
    let print_text = if print_output.trim().is_empty() {
        "(no output)"
    } else {
        print_output.trim()
    };
    format!(
        "Service: {}\nScope: {}\nList:\n{}\nPrint:\n{}",
        label, scope_label, list_text, print_text
    )
}

#[cfg(target_os = "macos")]
fn launchd_domain(scope: ServiceScope) -> Result<String> {
    match scope {
        ServiceScope::User => {
            let output = std::process::Command::new("id")
                .arg("-u")
                .output()
                .context("Failed to run id -u")?;
            if !output.status.success() {
                bail!("id -u failed");
            }
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if uid.is_empty() {
                bail!("id -u returned empty uid");
            }
            Ok(format!("gui/{}", uid))
        }
        ServiceScope::System => Ok("system".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> Result<()> {
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(args)
        .output()
        .context("Failed to run launchctl")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("launchctl {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_launchctl_capture(args: &[&str], allow_fail: bool) -> Result<String> {
    use std::process::Command;

    let output = Command::new("launchctl")
        .args(args)
        .output()
        .context("Failed to run launchctl")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };
    if !output.status.success() && !allow_fail {
        bail!("launchctl {} failed: {}", args.join(" "), combined);
    }
    Ok(combined)
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    #[test]
    fn renders_launchd_plist_for_user_scope() {
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
        let plist = launchd_plist_contents(Path::new("/usr/local/bin/htree"), "hashtree", &opts);
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>hashtree</string>"));
        assert!(plist.contains("<string>/usr/local/bin/htree</string>"));
        assert!(plist.contains("<string>start</string>"));
        assert!(plist.contains("<string>--addr</string>"));
        assert!(plist.contains("<string>127.0.0.1:8081</string>"));
        assert!(plist.contains("<string>--relays</string>"));
        assert!(plist.contains("<string>wss://relay.damus.io,wss://nos.lol</string>"));
        assert!(plist.contains("<key>HTREE_DATA_DIR</key>"));
        assert!(plist.contains("<string>/var/lib/hashtree</string>"));
        assert!(plist.contains("<key>RUST_LOG</key>"));
        assert!(plist.contains("<string>info</string>"));
    }

    #[test]
    fn resolves_launchd_plist_dir_from_home() {
        let _guard = env_lock();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/tmp/hashtree-home");

        let dir = launchd_plist_dir(ServiceScope::User).expect("launchd dir");
        assert_eq!(dir, PathBuf::from("/tmp/hashtree-home/Library/LaunchAgents"));

        if let Some(value) = prev_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn formats_systemd_status_summary() {
        let summary = systemd_status_summary(
            "hashtree.service",
            ServiceScope::User,
            "enabled",
            "active",
            "status output",
        );
        assert!(summary.contains("Service: hashtree.service"));
        assert!(summary.contains("Scope: user"));
        assert!(summary.contains("Enabled: enabled"));
        assert!(summary.contains("Active: active"));
        assert!(summary.contains("Status:\nstatus output"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn formats_launchd_status_summary() {
        let summary = launchd_status_summary(
            "hashtree",
            ServiceScope::System,
            "list output",
            "print output",
        );
        assert!(summary.contains("Service: hashtree"));
        assert!(summary.contains("Scope: system"));
        assert!(summary.contains("List:\nlist output"));
        assert!(summary.contains("Print:\nprint output"));
    }
}
