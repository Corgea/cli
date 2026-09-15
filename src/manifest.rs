//! File manifest: what this upload contains, addressed by content.
//!
//! Incremental scans need a list of changed files, and `incremental.rs` gets
//! one by diffing two commits in this clone. That needs history the clone may
//! not have: a shallow checkout cannot reach the commit the last scan covered,
//! a detached HEAD names no branch, and a pipeline that unpacks a tarball has
//! no `.git` at all. Each of those falls back to analyzing every file, on every
//! run, forever.
//!
//! A manifest answers the same question from content. Every file that goes into
//! the archive is hashed on the way in, and the server subtracts this manifest
//! from the one the baseline scan uploaded. No commit has to be reachable, or
//! to exist.
//!
//! It also describes a different thing from a git diff: the archive, not the
//! repository. Ignored paths, excluded globs, untracked files and uncommitted
//! edits all make the two disagree, and the archive is what the scanner reads.
//! That is why the server prefers a manifest diff when it has one, and why this
//! is built from the same walk that writes the zip rather than from a second
//! pass over the worktree.
//!
//! The archive has to be the whole project. A `--target` or `--only-uncommitted`
//! run uploads a subset, and a manifest of a subset reads as every other file
//! having been deleted -- every one of their findings dropped without anything
//! having looked at them. Those runs build no manifest, which is the same
//! reason they already skip incremental.

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Write};

/// Serialization this manifest speaks. The server refuses a version it does not
/// read rather than guessing, so a newer client's scans analyze every file
/// until the deployment catches up.
pub const MANIFEST_VERSION: &str = "1";

/// First line of the canonical form, naming the format and the digest.
const MANIFEST_HEADER: &str = "corgea-file-manifest/1 sha256";

/// Ceiling on entries, matching the server's. A manifest above it is refused
/// there, so building and uploading one would only waste the transfer.
const MAX_ENTRIES: usize = 100_000;

/// Every archived path and the digest of its contents.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Sorted by path, which is what makes the root reproducible.
    entries: BTreeMap<String, String>,
}

/// A manifest packed for upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedManifest {
    /// Gzipped canonical bytes.
    pub body: Vec<u8>,
    /// SHA-256 over the canonical bytes before compression. The server
    /// recomputes it, so a truncated upload is refused rather than read as a
    /// tree that shrank.
    pub root: String,
}

/// Hashes file contents as they stream past, so the archive is read once.
pub struct FileHasher {
    hasher: Sha256,
}

impl FileHasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    pub fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}

impl Default for FileHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for FileHasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer that feeds everything written to it to two sinks.
///
/// Wrapped around the zip writer, this hashes a file's bytes during the copy
/// that compresses them, rather than opening and reading it a second time.
pub struct TeeWriter<'a, W: Write> {
    primary: &'a mut W,
    hasher: FileHasher,
}

impl<'a, W: Write> TeeWriter<'a, W> {
    pub fn new(primary: &'a mut W) -> Self {
        Self {
            primary,
            hasher: FileHasher::new(),
        }
    }

    pub fn finish(self) -> String {
        self.hasher.finish()
    }
}

impl<W: Write> Write for TeeWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // The zip writer decides how much it accepted; the hash has to cover
        // exactly that much or it describes bytes nobody archived.
        let written = self.primary.write(buf)?;
        self.hasher.write_all(&buf[..written])?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.primary.flush()
    }
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one archived file. `path` must be the zip entry name, byte for
    /// byte: the server matches manifest paths against the changed-file list
    /// and against stored findings, and a path spelled differently in either
    /// place is a file whose old findings are carried forward untouched.
    pub fn insert(&mut self, path: String, digest: String) {
        self.entries.insert(path, digest);
    }

    /// Canonical bytes: the header, then one `<digest> <path>` line per entry
    /// in path order. Two runs over the same file set produce the same bytes,
    /// which is what lets the server compare two scans on the root alone.
    fn canonical(&self) -> Vec<u8> {
        let mut out = String::with_capacity(self.entries.len() * 96 + MANIFEST_HEADER.len());
        out.push_str(MANIFEST_HEADER);
        out.push('\n');
        for (path, digest) in &self.entries {
            out.push_str(digest);
            out.push(' ');
            out.push_str(path);
            out.push('\n');
        }
        out.into_bytes()
    }

    /// Pack for upload, or `None` when this manifest cannot be one.
    ///
    /// Empty is not a manifest of nothing, it is the absence of one: an archive
    /// with no files is not a project state to carry findings forward from.
    /// Above the entry ceiling the server refuses it anyway.
    pub fn encode(&self) -> Option<EncodedManifest> {
        if self.entries.is_empty() || self.entries.len() > MAX_ENTRIES {
            return None;
        }
        let canonical = self.canonical();
        let root = format!("{:x}", Sha256::digest(&canonical));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&canonical).ok()?;
        let body = encoder.finish().ok()?;
        Some(EncodedManifest { body, root })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn manifest(entries: &[(&str, &str)]) -> Manifest {
        let mut manifest = Manifest::new();
        for (path, digest) in entries {
            manifest.insert((*path).to_string(), (*digest).to_string());
        }
        manifest
    }

    fn decoded(encoded: &EncodedManifest) -> String {
        let mut text = String::new();
        GzDecoder::new(encoded.body.as_slice())
            .read_to_string(&mut text)
            .expect("gunzip");
        text
    }

    #[test]
    fn hashing_a_stream_matches_hashing_the_whole_buffer() {
        let mut hasher = FileHasher::new();
        hasher.write_all(b"hello ").expect("write");
        hasher.write_all(b"world").expect("write");

        assert_eq!(
            hasher.finish(),
            format!("{:x}", Sha256::digest(b"hello world"))
        );
    }

    #[test]
    fn the_tee_writes_every_byte_through_and_hashes_the_same_ones() {
        let mut sink = Vec::new();
        let mut tee = TeeWriter::new(&mut sink);
        tee.write_all(b"contents").expect("write");
        let digest = tee.finish();

        assert_eq!(sink, b"contents");
        assert_eq!(digest, format!("{:x}", Sha256::digest(b"contents")));
    }

    #[test]
    fn the_encoded_form_holds_the_header_and_one_line_per_file() {
        let encoded = manifest(&[("b.py", "digest-b"), ("a.py", "digest-a")])
            .encode()
            .expect("encode");

        assert_eq!(
            decoded(&encoded),
            format!("{MANIFEST_HEADER}\ndigest-a a.py\ndigest-b b.py\n")
        );
    }

    #[test]
    fn the_root_does_not_depend_on_the_order_files_were_walked() {
        // Two runs over the same tree can visit it in different orders, and
        // the server compares whole trees on this value alone.
        let forward = manifest(&[("a.py", "one"), ("b.py", "two")])
            .encode()
            .expect("encode");
        let backward = manifest(&[("b.py", "two"), ("a.py", "one")])
            .encode()
            .expect("encode");

        assert_eq!(forward.root, backward.root);
        assert_eq!(forward.body, backward.body);
    }

    #[test]
    fn the_root_is_the_digest_of_the_uncompressed_form() {
        // The server recomputes it from what it decompressed, so a root over
        // anything else would refuse every upload.
        let entries = manifest(&[("a.py", "one")]);
        let encoded = entries.encode().expect("encode");

        assert_eq!(
            encoded.root,
            format!("{:x}", Sha256::digest(entries.canonical()))
        );
    }

    #[test]
    fn a_changed_digest_changes_the_root() {
        let before = manifest(&[("a.py", "one")]).encode().expect("encode");
        let after = manifest(&[("a.py", "two")]).encode().expect("encode");

        assert_ne!(before.root, after.root);
    }

    #[test]
    fn an_empty_manifest_encodes_to_nothing_rather_than_an_empty_tree() {
        // An archive with no files is not a project state to carry findings
        // forward from, and uploading one as a baseline would drop every
        // finding of the next scan that matched against it.
        assert!(Manifest::new().encode().is_none());
    }

    #[test]
    fn a_manifest_past_the_servers_ceiling_is_not_uploaded() {
        let mut manifest = Manifest::new();
        for i in 0..=MAX_ENTRIES {
            manifest.insert(format!("f{i}.py"), "digest".to_string());
        }

        assert!(manifest.encode().is_none());
    }

    #[test]
    fn a_path_recorded_twice_keeps_the_last_digest() {
        // The zip writer would have overwritten the entry too, so the manifest
        // has to describe the same thing the archive ended up holding.
        let encoded = manifest(&[("a.py", "first"), ("a.py", "second")])
            .encode()
            .expect("encode");

        assert!(decoded(&encoded).contains("second a.py"));
        assert!(!decoded(&encoded).contains("first a.py"));
    }
}
