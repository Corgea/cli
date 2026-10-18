//! Tell the user when a newer Corgea CLI release is out.
//!
//! Strictly best effort: nothing here may fail, slow down, or change the
//! output of the command the user actually ran.
//!   * The notice comes from a cached answer, so the command never waits on
//!     the network. A stale cache is refreshed on a detached background
//!     thread that the process does not join; if it is still running when
//!     the command finishes, it is simply dropped and retried next run.
//!   * Every failure (offline, firewalled, GitHub rate limit, repo private or
//!     renamed, malformed response, unwritable cache) is swallowed and only
//!     surfaces under `CORGEA_DEBUG=1`. A failed lookup still stamps the
//!     cache, so an unreachable GitHub costs one attempt per interval.
//!   * The notice goes to stderr and only when stderr is a terminal outside
//!     CI, so piped/JSON output and pipelines never see it.
//!   * The request uses its own client, not `utils::api`'s shared one, so the
//!     Corgea token and cookies never reach GitHub.

use crate::log::debug;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LATEST_RELEASE_API_URL: &str = "https://api.github.com/repos/Corgea/cli/releases/latest";
const LATEST_RELEASE_PAGE_URL: &str = "https://github.com/Corgea/cli/releases/latest";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_FILE_NAME: &str = "update-check.json";
const DISABLE_ENV_VAR: &str = "CORGEA_NO_UPDATE_CHECK";

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UpdateCache {
    /// Unix seconds of the last lookup attempt, successful or not.
    checked_at: u64,
    /// Latest release version from the last successful lookup.
    latest_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMethod {
    Npm,
    Pip,
    Unknown,
}

/// Print an upgrade notice if a newer release is known, and refresh the
/// cached answer in the background when it is due.
pub fn notify_if_update_available() {
    let disabled = std::env::var(DISABLE_ENV_VAR).ok();
    let in_ci = std::env::var_os("CI").is_some();
    if !should_check(disabled.as_deref(), in_ci, std::io::stderr().is_terminal()) {
        return;
    }
    let Some(cache_path) = cache_path() else {
        return;
    };

    let cache = read_cache(&cache_path);
    let known_latest = cache.as_ref().and_then(|c| c.latest_version.clone());
    if let Some(latest) = known_latest.as_deref() {
        if is_newer(CURRENT_VERSION, latest) {
            eprintln!("{}", notice(CURRENT_VERSION, latest, install_method()));
        }
    }

    if is_due(cache.as_ref(), unix_now()) {
        let spawned = std::thread::Builder::new()
            .name("corgea-update-check".to_string())
            .spawn(move || refresh_cache(&cache_path, LATEST_RELEASE_API_URL, known_latest));
        if let Err(e) = spawned {
            debug(&format!(
                "update check: could not start background thread: {e}"
            ));
        }
    }
}

fn should_check(disabled: Option<&str>, in_ci: bool, stderr_is_terminal: bool) -> bool {
    let opted_out = disabled.is_some_and(|v| {
        let v = v.trim();
        !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false")
    });
    !opted_out && !in_ci && stderr_is_terminal
}

fn cache_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".corgea").join(CACHE_FILE_NAME))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A missing cache, an expired one, or one stamped in the future (clock
/// moved backwards) is due for a refresh.
fn is_due(cache: Option<&UpdateCache>, now: u64) -> bool {
    match cache {
        None => true,
        Some(c) => c.checked_at > now || now - c.checked_at >= CHECK_INTERVAL.as_secs(),
    }
}

fn read_cache(path: &Path) -> Option<UpdateCache> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Write via a temp file and rename so a process killed mid-write (the
/// refresh thread is never joined) cannot leave a truncated cache behind.
fn write_cache(path: &Path, cache: &UpdateCache) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let body = serde_json::to_string(cache).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// A failed lookup keeps the last known version rather than forgetting it,
/// and still stamps `checked_at` so the next attempt waits a full interval.
fn refresh_cache(path: &Path, url: &str, previous_latest: Option<String>) {
    let latest_version = match fetch_latest_version(url) {
        Ok(version) => Some(version),
        Err(e) => {
            debug(&format!("update check: {e}"));
            previous_latest
        }
    };
    let cache = UpdateCache {
        checked_at: unix_now(),
        latest_version,
    };
    if let Err(e) = write_cache(path, &cache) {
        debug(&format!(
            "update check: could not write {}: {e}",
            path.display()
        ));
    }
}

#[derive(Deserialize)]
struct LatestRelease {
    tag_name: String,
}

fn fetch_latest_version(url: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("corgea-cli/{CURRENT_VERSION} (update-check)"))
        .build()
        .map_err(|e| format!("could not build http client: {e}"))?;
    let response = client
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| format!("release lookup failed: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("release lookup returned {status}"));
    }
    let release: LatestRelease = response
        .json()
        .map_err(|e| format!("unexpected release response: {e}"))?;
    parse_release_tag(&release.tag_name)
        .ok_or_else(|| format!("unrecognized release tag '{}'", release.tag_name))
}

fn parse_release_tag(tag: &str) -> Option<String> {
    let trimmed = tag.trim();
    let version = trimmed.strip_prefix('v').unwrap_or(trimmed);
    semver::Version::parse(version).ok().map(|v| v.to_string())
}

/// Only a strictly newer, non-prerelease version counts, so local or beta
/// builds ahead of the latest release are never told to "upgrade" backwards.
fn is_newer(current: &str, latest: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(latest),
    ) {
        (Ok(current), Ok(latest)) => latest.pre.is_empty() && latest > current,
        _ => false,
    }
}

fn install_method() -> InstallMethod {
    std::env::current_exe()
        .map(|exe| detect_install_method(&exe))
        .unwrap_or(InstallMethod::Unknown)
}

/// npm runs the vendored binary out of `node_modules/@corgea/cli/vendor/…`.
/// pip (maturin `bin` bindings) puts it in the environment's scripts dir with
/// a `corgea_cli-*.dist-info` in that environment's site-packages.
fn detect_install_method(exe: &Path) -> InstallMethod {
    if exe.components().any(|c| c.as_os_str() == "node_modules") {
        return InstallMethod::Npm;
    }
    let Some(prefix) = exe.parent().and_then(Path::parent) else {
        return InstallMethod::Unknown;
    };
    if site_packages_dirs(prefix)
        .iter()
        .any(|dir| has_corgea_dist_info(dir))
    {
        return InstallMethod::Pip;
    }
    InstallMethod::Unknown
}

fn site_packages_dirs(prefix: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![prefix.join("Lib").join("site-packages")];
    if let Ok(entries) = std::fs::read_dir(prefix.join("lib")) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("python") {
                dirs.push(entry.path().join("site-packages"));
                dirs.push(entry.path().join("dist-packages"));
            }
        }
    }
    dirs
}

fn has_corgea_dist_info(site_packages: &Path) -> bool {
    std::fs::read_dir(site_packages)
        .map(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy().to_ascii_lowercase();
                name.starts_with("corgea_cli-") && name.ends_with(".dist-info")
            })
        })
        .unwrap_or(false)
}

fn upgrade_hint(method: InstallMethod) -> String {
    match method {
        InstallMethod::Npm => "Update with: npm install -g @corgea/cli@latest".to_string(),
        InstallMethod::Pip => "Update with: pip install --upgrade corgea-cli".to_string(),
        InstallMethod::Unknown => format!(
            "Update with `pip install --upgrade corgea-cli`, `npm install -g @corgea/cli@latest`, or download it from {LATEST_RELEASE_PAGE_URL}"
        ),
    }
}

fn notice(current: &str, latest: &str, method: InstallMethod) -> String {
    let headline = crate::utils::terminal::set_text_color(
        &format!("A new version of the Corgea CLI is available: {current} -> {latest}"),
        crate::utils::terminal::TerminalColor::Yellow,
    );
    format!("{headline}\n{}\n", upgrade_hint(method))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serve one canned HTTP response on an ephemeral port and return its URL.
    fn serve_once(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("stub addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}/repos/Corgea/cli/releases/latest")
    }

    fn closed_port_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("stub addr").port();
        drop(listener);
        format!("http://127.0.0.1:{port}/")
    }

    #[test]
    fn check_runs_only_on_an_interactive_non_ci_terminal() {
        assert!(should_check(None, false, true));
        assert!(!should_check(None, false, false));
        assert!(!should_check(None, true, true));
        assert!(!should_check(Some("1"), false, true));
        assert!(!should_check(Some("true"), false, true));
        assert!(should_check(Some("0"), false, true));
        assert!(should_check(Some("false"), false, true));
        assert!(should_check(Some(""), false, true));
    }

    #[test]
    fn release_tags_parse_with_or_without_v_prefix() {
        assert_eq!(parse_release_tag("v1.17.0").as_deref(), Some("1.17.0"));
        assert_eq!(parse_release_tag("1.17.0").as_deref(), Some("1.17.0"));
        assert_eq!(parse_release_tag(" v2.0.0 ").as_deref(), Some("2.0.0"));
        assert_eq!(parse_release_tag("latest"), None);
        assert_eq!(parse_release_tag(""), None);
    }

    #[test]
    fn only_strictly_newer_stable_releases_count() {
        assert!(is_newer("1.16.2", "1.17.0"));
        assert!(is_newer("1.16.2", "1.16.10"));
        assert!(is_newer("1.17.0-beta.1", "1.17.0"));
        assert!(!is_newer("1.16.2", "1.16.2"));
        assert!(!is_newer("1.17.0", "1.16.2"));
        assert!(!is_newer("1.16.2", "1.17.0-beta.1"));
        assert!(!is_newer("1.16.2", "garbage"));
    }

    #[test]
    fn refresh_is_due_when_missing_expired_or_from_the_future() {
        let now = 1_000_000;
        let interval = CHECK_INTERVAL.as_secs();
        let at = |checked_at| UpdateCache {
            checked_at,
            latest_version: None,
        };
        assert!(is_due(None, now));
        assert!(!is_due(Some(&at(now)), now));
        assert!(!is_due(Some(&at(now - interval + 1)), now));
        assert!(is_due(Some(&at(now - interval)), now));
        assert!(is_due(Some(&at(now + 60)), now));
    }

    #[test]
    fn cache_round_trips_and_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(CACHE_FILE_NAME);
        assert_eq!(read_cache(&path), None);

        let cache = UpdateCache {
            checked_at: 42,
            latest_version: Some("1.17.0".to_string()),
        };
        write_cache(&path, &cache).unwrap();
        assert_eq!(read_cache(&path), Some(cache));

        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(read_cache(&path), None);
    }

    #[test]
    fn successful_lookup_records_the_latest_version() {
        let url = serve_once("200 OK", r#"{"tag_name":"v9.9.9","name":"v9.9.9"}"#);
        assert_eq!(fetch_latest_version(&url).as_deref(), Ok("9.9.9"));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CACHE_FILE_NAME);
        let url = serve_once("200 OK", r#"{"tag_name":"v9.9.9"}"#);
        refresh_cache(&path, &url, Some("1.0.0".to_string()));
        let cache = read_cache(&path).expect("cache written");
        assert_eq!(cache.latest_version.as_deref(), Some("9.9.9"));
        assert!(!is_due(Some(&cache), unix_now()));
    }

    /// Private, renamed, or rate-limited repos and unreachable hosts must all
    /// fail quietly: no panic, the previous answer kept, and the attempt
    /// stamped so the next run does not retry immediately.
    #[test]
    fn failed_lookups_are_silent_and_keep_the_previous_answer() {
        let failures = [
            serve_once("404 Not Found", r#"{"message":"Not Found"}"#),
            serve_once("403 Forbidden", r#"{"message":"API rate limit exceeded"}"#),
            serve_once("200 OK", "<html>captive portal</html>"),
            serve_once("200 OK", r#"{"tag_name":"nightly"}"#),
            closed_port_url(),
        ];
        for url in failures {
            assert!(fetch_latest_version(&url).is_err(), "{url}");

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(CACHE_FILE_NAME);
            refresh_cache(&path, &url, Some("1.17.0".to_string()));
            let cache = read_cache(&path).expect("attempt stamped");
            assert_eq!(cache.latest_version.as_deref(), Some("1.17.0"), "{url}");
            assert!(!is_due(Some(&cache), unix_now()), "{url}");

            let path = dir.path().join("fresh.json");
            refresh_cache(&path, &url, None);
            assert_eq!(read_cache(&path).unwrap().latest_version, None, "{url}");
        }
    }

    #[test]
    fn unresponsive_host_times_out_instead_of_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let port = listener.local_addr().expect("stub addr").port();
        std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener.accept() {
                std::thread::sleep(REQUEST_TIMEOUT * 3);
            }
        });
        let started = std::time::Instant::now();
        assert!(fetch_latest_version(&format!("http://127.0.0.1:{port}/")).is_err());
        assert!(started.elapsed() < REQUEST_TIMEOUT * 2);
    }

    #[test]
    fn install_method_follows_the_binary_location() {
        let npm = Path::new(
            "/usr/lib/node_modules/@corgea/cli/vendor/x86_64-unknown-linux-musl/corgea/corgea",
        );
        assert_eq!(detect_install_method(npm), InstallMethod::Npm);

        let venv = tempfile::tempdir().unwrap();
        let site = venv
            .path()
            .join("lib")
            .join("python3.12")
            .join("site-packages");
        std::fs::create_dir_all(site.join("corgea_cli-1.16.2.dist-info")).unwrap();
        let exe = venv.path().join("bin").join("corgea");
        assert_eq!(detect_install_method(&exe), InstallMethod::Pip);

        let win = tempfile::tempdir().unwrap();
        let site = win.path().join("Lib").join("site-packages");
        std::fs::create_dir_all(site.join("corgea_cli-1.16.2.dist-info")).unwrap();
        let exe = win.path().join("Scripts").join("corgea.exe");
        assert_eq!(detect_install_method(&exe), InstallMethod::Pip);

        let manual = tempfile::tempdir().unwrap();
        let exe = manual.path().join("bin").join("corgea");
        assert_eq!(detect_install_method(&exe), InstallMethod::Unknown);
    }

    #[test]
    fn notice_names_both_versions_and_an_upgrade_path() {
        let text = notice("1.16.2", "1.17.0", InstallMethod::Npm);
        assert!(text.contains("1.16.2 -> 1.17.0"));
        assert!(text.contains("npm install -g @corgea/cli@latest"));

        let text = notice("1.16.2", "1.17.0", InstallMethod::Unknown);
        assert!(text.contains("pip install --upgrade corgea-cli"));
        assert!(text.contains(LATEST_RELEASE_PAGE_URL));
    }
}
