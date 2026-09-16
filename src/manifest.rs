//! File manifest: what an upload contains, addressed by content.
//!
//! Incremental scans need a list of changed files, and `incremental.rs` works
//! one out by diffing this clone against the commit the last trunk scan
//! covered. That needs history the clone may not have: a shallow checkout
//! cannot reach that commit, a detached HEAD names no branch, and a pipeline
//! that unpacks a tarball has no `.git` at all. Each of those analyzes every
//! file, on every run, forever.
//!
//! A manifest answers the same question from content. Every file that goes
//! into the archive is hashed on the way in, and the result is uploaded beside
//! it. The next scan fetches the baseline's and subtracts one from the other.
//! No commit has to be reachable, or to exist.
//!
//! The server stores these and hands them back; it never reads one. Both ends
//! of the comparison are this code, which is why `encode` and `decode` are
//! sides of the same coin and why the root is checked on the way in -- a
//! manifest that arrives damaged has to read as "no baseline" rather than as a
//! tree that lost every file it could not parse.
//!
//! A manifest also describes something different from a git diff: the archive,
//! not the repository. Ignored paths, excluded globs, untracked files and
//! uncommitted edits all make the two disagree, and the archive is what the
//! scanner reads. Hence building it from the same walk that writes the zip
//! rather than from a second pass over the worktree.
//!
//! The archive has to be the whole project. A `--target` or `--only-uncommitted`
//! run uploads a subset, and a manifest of a subset reads as every other file
//! having been deleted -- every one of their findings dropped without anything
//! having looked at them. Those runs build no manifest, which is the same
//! reason they already skip incremental.

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};

/// Serialization this manifest speaks. A manifest tagged with anything else is
/// left alone rather than guessed at, so a client meeting a newer format
/// analyzes every file instead of misreading a tree.
pub const MANIFEST_VERSION: &str = "1";

/// First line of the canonical form, naming the format and the digest.
const MANIFEST_HEADER: &str = "corgea-file-manifest/1 sha256";

/// Ceiling on entries. A project with more files than this is one where the
/// diff is unlikely to be small enough to matter, and the cap keeps a
/// downloaded manifest from expanding without limit.
const MAX_ENTRIES: usize = 100_000;

/// Ceiling on the decompressed form, applied while decompressing. The bytes
/// arrive gzipped over the network, and a small body can unpack into an
/// arbitrarily large one.
const MAX_DECODED_BYTES: u64 = 64 * 1024 * 1024;

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
    /// with no files is not a project state to carry findings forward from, and
    /// the next scan would read it as a project where everything was deleted.
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

    /// Read back a manifest packed by `encode`, or say why it cannot be read.
    ///
    /// `expected_root` is what the server recorded when the manifest was
    /// uploaded, and it is checked against the bytes that actually arrived.
    /// Without that check a truncated download parses as a smaller tree, and
    /// every file missing from it reads as deleted -- findings dropped for
    /// files nobody touched.
    ///
    /// Every failure is a refusal, never a partial answer, for the same
    /// reason: a manifest that is half understood describes a project that
    /// never existed. The caller falls back to a full scan.
    pub fn decode(body: &[u8], expected_root: &str) -> Result<Self, String> {
        let mut canonical = Vec::new();
        // Capped during the read, not after: this is compressed input, so the
        // size that matters is not knowable until it has been expanded.
        GzDecoder::new(body)
            .take(MAX_DECODED_BYTES + 1)
            .read_to_end(&mut canonical)
            .map_err(|e| format!("it could not be decompressed ({e})"))?;
        if canonical.len() as u64 > MAX_DECODED_BYTES {
            return Err(format!("it unpacks to more than {MAX_DECODED_BYTES} bytes"));
        }

        let root = format!("{:x}", Sha256::digest(&canonical));
        if !root.eq_ignore_ascii_case(expected_root) {
            return Err(
                "its contents do not match the digest recorded for it, so it arrived \
                 damaged or truncated"
                    .to_string(),
            );
        }

        let text = String::from_utf8(canonical).map_err(|_| "it is not valid UTF-8".to_string())?;
        let mut lines = text.lines();
        match lines.next() {
            Some(MANIFEST_HEADER) => {}
            Some(other) => {
                return Err(format!(
                    "it is in a format this version does not read ({})",
                    other.chars().take(40).collect::<String>()
                ))
            }
            None => return Err("it is empty".to_string()),
        }

        let mut entries = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            // One space, and paths may contain more, so split once from the
            // left and treat everything after as the path.
            let Some((digest, path)) = line.split_once(' ') else {
                return Err("one of its lines is not a digest and a path".to_string());
            };
            if digest.is_empty() || path.is_empty() {
                return Err("one of its lines names an empty digest or path".to_string());
            }
            entries.insert(path.to_string(), digest.to_string());
            if entries.len() > MAX_ENTRIES {
                return Err(format!("it describes more than {MAX_ENTRIES} files"));
            }
        }
        if entries.is_empty() {
            return Err("it describes no files".to_string());
        }
        Ok(Self { entries })
    }

    /// Paths that differ between this manifest and `newer`: added, removed, and
    /// same-path-different-contents.
    ///
    /// Both sides, including removals, because the list decides which findings
    /// are *not* carried forward. A deleted file left off keeps its findings in
    /// a tree that no longer holds it.
    ///
    /// Sorted, and each path named once, matching what the git diff produces so
    /// the two are interchangeable to everything downstream.
    pub fn changed_paths(&self, newer: &Manifest) -> Vec<String> {
        let mut changed: Vec<String> = self
            .entries
            .iter()
            .filter(|(path, digest)| newer.entries.get(*path) != Some(digest))
            .map(|(path, _)| path.clone())
            .collect();
        changed.extend(
            newer
                .entries
                .keys()
                .filter(|path| !self.entries.contains_key(*path))
                .cloned(),
        );
        changed.sort();
        changed
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
    fn a_manifest_survives_the_round_trip_through_the_server() {
        let original = manifest(&[("a.py", "one"), ("dir/b with space.py", "two")]);
        let encoded = original.encode().expect("encode");

        let read_back = Manifest::decode(&encoded.body, &encoded.root).expect("decode");

        assert_eq!(read_back, original);
    }

    #[test]
    fn a_manifest_that_does_not_match_its_digest_is_refused() {
        // A truncated download parses as a smaller tree, and every file missing
        // from it would read as deleted.
        let encoded = manifest(&[("a.py", "one")]).encode().expect("encode");

        let err = Manifest::decode(&encoded.body, &"0".repeat(64)).expect_err("must refuse");

        assert!(err.contains("damaged or truncated"), "{err}");
    }

    #[test]
    fn a_body_that_is_not_a_manifest_is_refused_rather_than_read_as_an_empty_tree() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"corgea-file-manifest/9 blake3\n").ok();
        let body = encoder.finish().expect("gzip");
        let root = format!("{:x}", Sha256::digest(b"corgea-file-manifest/9 blake3\n"));

        let err = Manifest::decode(&body, &root).expect_err("must refuse");

        assert!(err.contains("format this version does not read"), "{err}");
    }

    #[test]
    fn bytes_that_are_not_gzip_are_refused() {
        let err = Manifest::decode(b"not gzip at all", "irrelevant").expect_err("must refuse");
        assert!(err.contains("decompressed"), "{err}");
    }

    #[test]
    fn the_diff_names_added_edited_and_deleted_files_but_not_untouched_ones() {
        let baseline = manifest(&[("keep.py", "same"), ("edit.py", "before"), ("gone.py", "x")]);
        let current = manifest(&[("keep.py", "same"), ("edit.py", "after"), ("added.py", "y")]);

        assert_eq!(
            baseline.changed_paths(&current),
            vec!["added.py", "edit.py", "gone.py"]
        );
    }

    #[test]
    fn two_identical_trees_report_nothing_changed() {
        let tree = manifest(&[("a.py", "one"), ("b.py", "two")]);
        assert!(tree.changed_paths(&tree).is_empty());
    }

    #[test]
    fn a_file_that_moved_is_named_on_both_sides() {
        // The old path has to be there, or its findings are carried into a tree
        // that no longer holds it.
        let baseline = manifest(&[("old/a.py", "same")]);
        let current = manifest(&[("new/a.py", "same")]);

        assert_eq!(
            baseline.changed_paths(&current),
            vec!["new/a.py", "old/a.py"]
        );
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
