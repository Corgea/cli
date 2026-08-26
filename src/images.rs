use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Corgea greps the uploaded bundle for archives named with this prefix. When it
/// finds any, it scans those images instead of resolving base images from the
/// source tree, so the name is part of the contract with the backend.
pub const IMAGE_ARCHIVE_PREFIX: &str = "corgea-image-scanning-";
const IMAGE_ARCHIVE_EXTENSION: &str = ".tar";
/// Stay well inside the 255 byte file name limit that common filesystems enforce.
const MAX_ARCHIVE_NAME_LEN: usize = 200;
/// Overrides the container CLI used to export images.
const ENGINE_ENV: &str = "CORGEA_CONTAINER_ENGINE";
const ENGINE_CANDIDATES: &[&str] = &["docker", "podman"];

/// An image exported to a tar archive that is ready to be bundled with the scan.
#[derive(Debug)]
pub struct SavedImage {
    pub image: String,
    pub archive_name: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

impl SavedImage {
    /// One line for the scan output: what was exported, and how big it is.
    pub fn description(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.image,
            self.archive_name,
            human_size(self.size_bytes)
        )
    }
}

/// Trim, validate and de-duplicate `--include-image` values.
pub fn normalize_image_refs(images: &[String]) -> Result<Vec<String>, String> {
    let mut normalized: Vec<String> = Vec::new();

    for raw in images {
        let image = raw.trim();

        if image.is_empty() {
            return Err("--include-image was given an empty image reference. Pass a full image name with a tag, e.g. --include-image myapp:1.2.3.".to_string());
        }
        if image.starts_with('-') {
            return Err(format!(
                "Invalid image reference '{}': an image name can't start with '-'.",
                image
            ));
        }
        if image.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!(
                "Invalid image reference '{}': an image name can't contain whitespace.",
                image
            ));
        }

        if !normalized.iter().any(|existing| existing == image) {
            normalized.push(image.to_string());
        }
    }

    Ok(normalized)
}

/// The archive name Corgea looks for, derived from the image reference.
pub fn archive_name(image: &str) -> String {
    let (repository, reference) = split_reference(image);
    let mut name = format!(
        "{}{}-{}",
        IMAGE_ARCHIVE_PREFIX,
        sanitize(repository),
        sanitize(&reference)
    );

    // sanitize() only emits ASCII, so truncating by bytes stays on a char boundary.
    let max_len = MAX_ARCHIVE_NAME_LEN - IMAGE_ARCHIVE_EXTENSION.len();
    if name.len() > max_len {
        name.truncate(max_len);
    }

    format!("{}{}", name.trim_end_matches('-'), IMAGE_ARCHIVE_EXTENSION)
}

/// Export every image to `out_dir`, pulling images that aren't available locally.
pub fn save_images(images: &[String], out_dir: &Path) -> Result<Vec<SavedImage>, String> {
    let engine = detect_engine()?;
    save_images_with_engine(&engine, images, out_dir)
}

fn save_images_with_engine(
    engine: &str,
    images: &[String],
    out_dir: &Path,
) -> Result<Vec<SavedImage>, String> {
    fs::create_dir_all(out_dir).map_err(|e| {
        format!(
            "Failed to create the image staging directory '{}': {}",
            out_dir.display(),
            e
        )
    })?;

    let mut saved: Vec<SavedImage> = Vec::with_capacity(images.len());

    for image in images {
        let archive_name = unique_archive_name(image, &saved);
        let path = out_dir.join(&archive_name);

        println!("Exporting container image {}...", image);
        ensure_image_present(engine, image)?;
        save_image(engine, image, &path)?;

        let size_bytes = fs::metadata(&path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);

        saved.push(SavedImage {
            image: image.clone(),
            archive_name,
            path,
            size_bytes,
        });
    }

    Ok(saved)
}

/// Split `repository[:tag][@digest]` into the repository and the reference that
/// identifies the version. Untagged references are exported as `latest`, which
/// is the tag the container CLI resolves them to.
fn split_reference(image: &str) -> (&str, String) {
    let (name, digest) = match image.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (image, None),
    };

    // A colon inside the registry host (`registry:5000/team/app`) is a port, not a tag.
    let tag_separator = name
        .rfind(':')
        .filter(|index| !name[*index + 1..].contains('/'));
    let repository = match tag_separator {
        Some(index) => &name[..index],
        None => name,
    };
    let tag = tag_separator.map(|index| &name[index + 1..]);

    let reference = match (tag, digest) {
        (Some(tag), Some(digest)) => format!("{}-{}", tag, digest),
        (Some(tag), None) => tag.to_string(),
        (None, Some(digest)) => digest.to_string(),
        (None, None) => "latest".to_string(),
    };

    (repository, reference)
}

fn sanitize(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());

    for c in value.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            sanitized.push(c);
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }

    sanitized.trim_matches('-').to_string()
}

/// Sanitizing and truncating can map two different references onto one name, so
/// suffix duplicates instead of overwriting an archive that was already written.
///
/// Names are compared case-insensitively: image tags may carry uppercase, and on
/// a case-insensitive filesystem `myapp:V1` and `myapp:v1` would otherwise be
/// exported over each other and scanned as the same image.
fn unique_archive_name(image: &str, saved: &[SavedImage]) -> String {
    let is_taken = |candidate: &str| {
        saved
            .iter()
            .any(|entry| entry.archive_name.eq_ignore_ascii_case(candidate))
    };

    let candidate = archive_name(image);
    if !is_taken(&candidate) {
        return candidate;
    }

    let stem = candidate
        .strip_suffix(IMAGE_ARCHIVE_EXTENSION)
        .unwrap_or(&candidate);
    for suffix in 2.. {
        let candidate = format!("{}-{}{}", stem, suffix, IMAGE_ARCHIVE_EXTENSION);
        if !is_taken(&candidate) {
            return candidate;
        }
    }

    unreachable!("suffixed archive names are unbounded")
}

fn detect_engine() -> Result<String, String> {
    if let Some(engine) = crate::utils::generic::get_env_var_if_exists(ENGINE_ENV) {
        return Ok(engine);
    }

    for engine in ENGINE_CANDIDATES {
        if which::which(engine).is_ok() {
            return Ok((*engine).to_string());
        }
    }

    Err(format!(
        "--include-image needs a container CLI to export images, but neither docker nor podman was found on your PATH.\nInstall one of them, or set {} to the CLI Corgea should use.",
        ENGINE_ENV
    ))
}

fn ensure_image_present(engine: &str, image: &str) -> Result<(), String> {
    let inspect = run_quiet(engine, &["image", "inspect", image])?;
    if inspect.status.success() {
        return Ok(());
    }

    println!("  {} isn't available locally, pulling it...", image);
    let status = Command::new(engine)
        .args(["pull", image])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("Failed to run `{} pull {}`: {}", engine, image, e))?;

    if !status.success() {
        return Err(format!(
            "Couldn't find or pull the container image '{}'.\nBuild or pull it before running the scan, and make sure you're logged in to its registry.",
            image
        ));
    }

    Ok(())
}

fn save_image(engine: &str, image: &str, path: &Path) -> Result<(), String> {
    let path_arg = path.to_string_lossy().to_string();
    let output = run_quiet(engine, &["save", "-o", &path_arg, image])?;

    let failure = if !output.status.success() {
        Some(failure_details(&output))
    } else if fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
        == 0
    {
        Some("the container CLI produced an empty archive".to_string())
    } else {
        None
    };

    if let Some(details) = failure {
        let _ = fs::remove_file(path);
        return Err(format!(
            "Failed to export the container image '{}'.\nError details:\n{}",
            image, details
        ));
    }

    Ok(())
}

fn run_quiet(engine: &str, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new(engine).args(args).output().map_err(|e| {
        format!(
            "Failed to run `{} {}`: {}. Is it installed and on your PATH?",
            engine,
            args.join(" "),
            e
        )
    })
}

fn failure_details(output: &std::process::Output) -> String {
    for stream in [&output.stderr, &output.stdout] {
        let details = String::from_utf8_lossy(stream).trim().to_string();
        if !details.is_empty() {
            return details;
        }
    }
    "the container CLI exited with an error".to_string()
}

fn human_size(size_bytes: u64) -> String {
    let megabytes = size_bytes as f64 / (1024.0 * 1024.0);
    if megabytes >= 1024.0 {
        format!("{:.2} GB", megabytes / 1024.0)
    } else {
        format!("{:.2} MB", megabytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn archive_name_uses_repository_and_tag() {
        assert_eq!(
            archive_name("alpine:3.19"),
            "corgea-image-scanning-alpine-3.19.tar"
        );
        assert_eq!(
            archive_name("ghcr.io/acme/api:1.2.3"),
            "corgea-image-scanning-ghcr.io-acme-api-1.2.3.tar"
        );
    }

    #[test]
    fn archive_name_defaults_untagged_images_to_latest() {
        assert_eq!(
            archive_name("myapp"),
            "corgea-image-scanning-myapp-latest.tar"
        );
    }

    #[test]
    fn archive_name_treats_registry_port_as_part_of_the_repository() {
        assert_eq!(
            archive_name("registry:5000/team/app"),
            "corgea-image-scanning-registry-5000-team-app-latest.tar"
        );
    }

    #[test]
    fn archive_name_keeps_digest_references() {
        assert_eq!(
            archive_name("alpine@sha256:abc123"),
            "corgea-image-scanning-alpine-sha256-abc123.tar"
        );
        assert_eq!(
            archive_name("alpine:3.19@sha256:abc123"),
            "corgea-image-scanning-alpine-3.19-sha256-abc123.tar"
        );
    }

    #[test]
    fn archive_name_stays_within_the_file_name_limit() {
        let name = archive_name(&format!("acme/{}:1.0", "a".repeat(500)));
        assert!(name.len() <= MAX_ARCHIVE_NAME_LEN);
        assert!(name.starts_with(IMAGE_ARCHIVE_PREFIX));
        assert!(name.ends_with(IMAGE_ARCHIVE_EXTENSION));
    }

    #[test]
    fn normalize_image_refs_trims_and_deduplicates() {
        let images = vec![
            " alpine:3.19 ".to_string(),
            "alpine:3.19".to_string(),
            "myapp:1.0".to_string(),
        ];
        assert_eq!(
            normalize_image_refs(&images).unwrap(),
            vec!["alpine:3.19".to_string(), "myapp:1.0".to_string()]
        );
    }

    #[test]
    fn normalize_image_refs_rejects_unusable_references() {
        assert!(normalize_image_refs(&["  ".to_string()]).is_err());
        assert!(normalize_image_refs(&["--output=/tmp/x".to_string()]).is_err());
        assert!(normalize_image_refs(&["alpine 3.19".to_string()]).is_err());
    }

    /// Stub container CLI: reports every image as present locally and writes the
    /// archive `save -o <path>` asks for. POSIX shell, so every test that runs it
    /// is Unix-only — Windows can't execute the script through `Command::new`.
    #[cfg(unix)]
    fn stub_engine(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("stub-engine.sh");
        // Write to a sibling, fsync, chmod, then rename. Creating the
        // executable in place and execing it immediately races overlayfs
        // (GitHub Actions + llvm-cov) with ETXTBSY / "Text file busy".
        let tmp = dir.join("stub-engine.sh.tmp");
        let mut file = fs::File::create(&tmp).unwrap();
        writeln!(
            file,
            r#"#!/bin/sh
if [ "$1" = "image" ]; then
  exit 0
fi
if [ "$1" = "save" ]; then
  printf 'archive of %s' "$4" > "$3"
  exit 0
fi
exit 1
"#
        )
        .unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut permissions = fs::metadata(&tmp).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&tmp, permissions).unwrap();
        fs::rename(&tmp, &path).unwrap();
        wait_until_executable(&path);

        path
    }

    /// Overlayfs can still return ETXTBSY on the first exec after rename.
    /// Spin briefly so the tests do not flake under cargo-llvm-cov.
    #[cfg(unix)]
    fn wait_until_executable(path: &Path) {
        for delay_ms in [0_u64, 2, 5, 10, 20, 50] {
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            if Command::new(path)
                .args(["image", "inspect", "warmup"])
                .output()
                .is_ok()
            {
                return;
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_images_writes_one_archive_per_image() {
        let temp_dir = env_temp_dir("save-images");
        let engine = stub_engine(&temp_dir);
        let out_dir = temp_dir.join("images");

        let saved = save_images_with_engine(
            engine.to_str().unwrap(),
            &["alpine:3.19".to_string(), "myapp:1.0".to_string()],
            &out_dir,
        )
        .unwrap();

        assert_eq!(saved.len(), 2);
        for entry in &saved {
            assert!(entry.path.exists());
            assert!(entry.size_bytes > 0);
            assert!(entry.archive_name.starts_with(IMAGE_ARCHIVE_PREFIX));
            assert!(entry.archive_name.ends_with(IMAGE_ARCHIVE_EXTENSION));
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_images_suffixes_colliding_archive_names() {
        let temp_dir = env_temp_dir("colliding-images");
        let engine = stub_engine(&temp_dir);
        let out_dir = temp_dir.join("images");

        // Both references sanitize to the same archive name.
        let saved = save_images_with_engine(
            engine.to_str().unwrap(),
            &["acme/app:1.0".to_string(), "acme:app-1.0".to_string()],
            &out_dir,
        )
        .unwrap();

        assert_eq!(
            saved[0].archive_name,
            "corgea-image-scanning-acme-app-1.0.tar"
        );
        assert_eq!(
            saved[1].archive_name,
            "corgea-image-scanning-acme-app-1.0-2.tar"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    /// Tags may carry uppercase, and a case-insensitive filesystem would export
    /// `myapp:V1` over `myapp:v1` — both images would then scan as one.
    #[cfg(unix)]
    #[test]
    fn save_images_separates_references_differing_only_in_case() {
        let temp_dir = env_temp_dir("case-collision");
        let engine = stub_engine(&temp_dir);
        let out_dir = temp_dir.join("images");

        let saved = save_images_with_engine(
            engine.to_str().unwrap(),
            &["myapp:v1".to_string(), "myapp:V1".to_string()],
            &out_dir,
        )
        .unwrap();

        assert_eq!(saved[0].archive_name, "corgea-image-scanning-myapp-v1.tar");
        assert_eq!(
            saved[1].archive_name,
            "corgea-image-scanning-myapp-V1-2.tar"
        );
        assert_ne!(saved[0].path, saved[1].path);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn save_images_reports_a_failing_container_cli() {
        let temp_dir = env_temp_dir("failing-engine");
        let out_dir = temp_dir.join("images");

        let error = save_images_with_engine(
            "corgea-nonexistent-container-cli",
            &["alpine:3.19".to_string()],
            &out_dir,
        )
        .unwrap_err();

        assert!(error.contains("corgea-nonexistent-container-cli"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    fn env_temp_dir(name: &str) -> PathBuf {
        tempfile::Builder::new()
            .prefix(&format!("corgea-images-test-{name}-"))
            .tempdir()
            .expect("temp dir")
            .keep()
    }
}
