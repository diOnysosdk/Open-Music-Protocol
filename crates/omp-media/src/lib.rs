//! Deterministic, offline media binding for authenticated OMP v0.2 manifests.
//!
//! This crate never establishes identity authorization or playback entitlement.
//! It authenticates a manifest with W3, validates it with W2, and binds local
//! bytes while retaining the exact verified open file handle.

#![deny(missing_docs)]

use ed25519_dalek::VerifyingKey;
use omp_core::v02::{self, Asset, Manifest};
use omp_crypto::{verify_v02, V02Profile};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// W5 validation or media-binding failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The manifest failed W2 validation.
    #[error("OMP_SCHEMA_INVALID: {0}")]
    Schema(String),
    /// W3 signature verification failed.
    #[error("OMP_SIGNATURE_INVALID")]
    SignatureInvalid,
    /// A portable path or package root is unsafe.
    #[error("OMP_ASSET_PATH_INVALID: {0}")]
    PathInvalid(String),
    /// Multiple paths are ambiguous under Unicode case folding.
    #[error("OMP_ASSET_PATH_CONFLICT")]
    PathConflict,
    /// The local bytes do not match the signed binding.
    #[error("OMP_ASSET_BINDING_INVALID: {0}")]
    BindingInvalid(String),
    /// No supported, non-preview asset bound successfully.
    #[error("OMP_ASSET_UNAVAILABLE")]
    AssetUnavailable,
    /// The bytes do not match the signed supported media type.
    #[error("OMP_MEDIA_TYPE_INVALID")]
    MediaTypeInvalid,
    /// A local resource policy rejected the asset size.
    #[error("OMP_RESOURCE_LIMIT")]
    ResourceLimit,
    /// Local filesystem operation failed closed.
    #[error("OMP_ASSET_IO: {0}")]
    Io(#[from] std::io::Error),
}

/// A W2-valid manifest whose exact v0.2 W3 signature has been verified.
pub struct AuthenticatedManifest {
    manifest: Manifest,
}

impl AuthenticatedManifest {
    /// Parse with duplicate-key rejection, validate v0.2 semantics, and verify
    /// the exact manifest signing profile. This does not establish W4 signer
    /// authorization or legal ownership.
    pub fn parse_and_verify(bytes: &[u8], key: &VerifyingKey) -> Result<Self, Error> {
        let manifest = v02::parse::<Manifest>(bytes).map_err(|e| Error::Schema(e.to_string()))?;
        let value = serde_json::to_value(&manifest).map_err(|e| Error::Schema(e.to_string()))?;
        verify_v02(V02Profile::Manifest, &value, &manifest.signature.value, key)
            .map_err(|_| Error::SignatureInvalid)?;
        validate_asset_set(&manifest.assets)?;
        Ok(Self { manifest })
    }

    /// Access authenticated, byte-preserved descriptive metadata.
    pub fn metadata(&self) -> &v02::Metadata {
        &self.manifest.metadata
    }

    /// Access the authenticated manifest ID.
    pub fn manifest_id(&self) -> &str {
        &self.manifest.manifest_id
    }

    /// Recording identifier bound by this manifest.
    pub fn recording_id(&self) -> &str {
        &self.manifest.recording_id
    }

    /// License identifier bound by this manifest.
    pub fn license_id(&self) -> &str {
        &self.manifest.license_id
    }
}

/// Explicit validated package root used for every asset resolution.
#[derive(Debug)]
pub struct PackageRoot {
    canonical: PathBuf,
    root_handle: File,
}

impl PackageRoot {
    /// Open and canonicalize an existing directory, rejecting a symlink or
    /// Windows reparse point at the selected root itself.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        reject_link(path)?;
        let canonical = fs::canonicalize(path)?;
        let metadata = fs::metadata(&canonical)?;
        if !metadata.is_dir() {
            return Err(Error::PathInvalid("package root is not a directory".into()));
        }
        reject_link(&canonical)?;
        let root_handle = open_root_handle(&canonical)?;
        Ok(Self {
            canonical,
            root_handle,
        })
    }

    /// Canonical package-root path, for diagnostics only.
    pub fn path(&self) -> &Path {
        &self.canonical
    }
}

/// Local resource policy, separate from protocol validity.
#[derive(Clone, Copy, Debug)]
pub struct MediaPolicy {
    /// Maximum asset bytes this caller is willing to stream and verify.
    pub max_asset_bytes: u64,
}

impl Default for MediaPolicy {
    fn default() -> Self {
        Self {
            max_asset_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

/// An integrity-verified asset and the exact open handle that was hashed.
pub struct VerifiedMedia {
    file: File,
    asset_id: String,
    relative_path: String,
    media_type: String,
    size_bytes: u64,
    sha256: String,
}

impl VerifiedMedia {
    /// Authenticated manifest-local asset ID.
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    /// Authenticated portable relative path.
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Sniffed and signed media type.
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Verified byte length.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Verified lowercase SHA-256.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Transfer the already-open, rewound verified handle to a decoder.
    pub fn into_file(self) -> File {
        self.file
    }
}

/// Deterministically select the lowest-ranked supported non-preview asset
/// whose local bytes bind. JSON array and directory enumeration order have no
/// effect. Failed candidates do not become protocol-valid media objects.
pub fn select_and_verify(
    manifest: &AuthenticatedManifest,
    root: &PackageRoot,
    policy: MediaPolicy,
) -> Result<VerifiedMedia, Error> {
    let mut candidates: Vec<_> = manifest
        .manifest
        .assets
        .iter()
        .filter(|asset| asset.role != "preview" && supported(&asset.media_type))
        .collect();
    candidates.sort_by_key(|asset| asset.selection_rank);
    let mut first_error = None;
    for asset in candidates {
        match verify_asset(asset, root, policy) {
            Ok(verified) => return Ok(verified),
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    Err(first_error.unwrap_or(Error::AssetUnavailable))
}

fn verify_asset(
    asset: &Asset,
    root: &PackageRoot,
    policy: MediaPolicy,
) -> Result<VerifiedMedia, Error> {
    if !supported(&asset.media_type) {
        return Err(Error::MediaTypeInvalid);
    }
    if asset.size_bytes > policy.max_asset_bytes {
        return Err(Error::ResourceLimit);
    }
    let mut source = open_source(root, &asset.relative_path)?;
    let file = &mut source.file;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != asset.size_bytes {
        return Err(Error::BindingInvalid("size mismatch".into()));
    }
    let mut header = [0_u8; 12];
    let header_len = file.read(&mut header)?;
    if !magic_matches(&asset.media_type, &header[..header_len]) {
        return Err(Error::MediaTypeInvalid);
    }
    file.seek(SeekFrom::Start(0))?;
    // Hash into a private, unnamed snapshot. The decoder receives this exact
    // verified handle, so later replacement or in-place mutation of the
    // package pathname cannot change decoded bytes.
    let mut snapshot = tempfile::tempfile()?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = asset.size_bytes.saturating_sub(total);
        if remaining == 0 {
            break;
        }
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap();
        let count = file.read(&mut buffer[..wanted])?;
        if count == 0 {
            return Err(Error::BindingInvalid("unexpected EOF".into()));
        }
        total += count as u64;
        digest.update(&buffer[..count]);
        snapshot.write_all(&buffer[..count])?;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(Error::BindingInvalid("size changed while reading".into()));
    }
    let actual = format!("{:x}", digest.finalize());
    if actual != asset.sha256 {
        return Err(Error::BindingInvalid("SHA-256 mismatch".into()));
    }
    snapshot.flush()?;
    if snapshot.metadata()?.len() != total {
        return Err(Error::BindingInvalid("snapshot size mismatch".into()));
    }
    validate_container_structure(&mut snapshot, &asset.media_type, total)?;
    snapshot.seek(SeekFrom::Start(0))?;
    Ok(VerifiedMedia {
        file: snapshot,
        asset_id: asset.asset_id.clone(),
        relative_path: asset.relative_path.clone(),
        media_type: asset.media_type.clone(),
        size_bytes: total,
        sha256: actual,
    })
}

/// Validate allocation-sensitive container declarations before decoding.
pub fn validate_container_structure<R: Read + Seek>(
    reader: &mut R,
    media_type: &str,
    size: u64,
) -> Result<(), Error> {
    reader.seek(SeekFrom::Start(0))?;
    if media_type == "audio/wav" {
        let mut header = [0_u8; 12];
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::MediaTypeInvalid)?;
        if &header[..4] != b"RIFF" || &header[8..] != b"WAVE" {
            return Err(Error::MediaTypeInvalid);
        }
        let declared = u64::from(u32::from_le_bytes(header[4..8].try_into().unwrap())) + 8;
        if declared > size {
            return Err(Error::ResourceLimit);
        }
        return Ok(());
    }
    if media_type != "audio/flac" {
        return Ok(());
    }
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"fLaC" {
        return Err(Error::MediaTypeInvalid);
    }
    let mut position = 4_u64;
    let mut first = true;
    loop {
        let mut header = [0_u8; 4];
        reader
            .read_exact(&mut header)
            .map_err(|_| Error::MediaTypeInvalid)?;
        position += 4;
        let block_type = header[0] & 0x7f;
        let length = u64::from_be_bytes([0, 0, 0, 0, 0, header[1], header[2], header[3]]);
        let end = position.checked_add(length).ok_or(Error::ResourceLimit)?;
        if end > size {
            return Err(Error::ResourceLimit);
        }
        if block_type == 127 || (first && (block_type != 0 || length != 34)) {
            return Err(Error::MediaTypeInvalid);
        }
        reader.seek(SeekFrom::Start(end))?;
        position = end;
        first = false;
        if header[0] & 0x80 != 0 {
            return Ok(());
        }
    }
}

fn validate_asset_set(assets: &[Asset]) -> Result<(), Error> {
    let mut folded = BTreeMap::<String, &str>::new();
    for asset in assets {
        v02::validate_portable_path(&asset.relative_path)
            .map_err(|e| Error::PathInvalid(e.to_string()))?;
        reject_reserved_segments(&asset.relative_path)?;
        let key = asset.relative_path.to_lowercase();
        if folded.insert(key, &asset.relative_path).is_some() {
            return Err(Error::PathConflict);
        }
    }
    Ok(())
}

fn reject_reserved_segments(path: &str) -> Result<(), Error> {
    for segment in path.split('/') {
        let stem = segment
            .split('.')
            .next()
            .unwrap_or(segment)
            .to_ascii_uppercase();
        let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || stem
                .strip_prefix("COM")
                .or_else(|| stem.strip_prefix("LPT"))
                .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"));
        if device {
            return Err(Error::PathInvalid("reserved device segment".into()));
        }
    }
    Ok(())
}

fn validate_resolution_input(relative: &str) -> Result<Vec<&str>, Error> {
    v02::validate_portable_path(relative).map_err(|e| Error::PathInvalid(e.to_string()))?;
    reject_reserved_segments(relative)?;
    Ok(relative.split('/').collect())
}

#[cfg(windows)]
fn open_root_handle(path: &Path) -> Result<File, Error> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001 | 0x0000_0002)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(path)?;
    if is_windows_reparse(&file.metadata()?) {
        return Err(Error::PathInvalid("reparse-point package root".into()));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_root_handle(path: &Path) -> Result<File, Error> {
    use rustix::fs::{open, Mode, OFlags};
    let handle = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(handle.into())
}

struct SourceHandle {
    file: File,
    #[cfg(windows)]
    _directory_guards: Vec<File>,
}

#[cfg(windows)]
fn open_source(root: &PackageRoot, relative: &str) -> Result<SourceHandle, Error> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let _root_guard = &root.root_handle;
    let segments = validate_resolution_input(relative)?;
    let mut current = root.canonical.clone();
    let mut guards = Vec::new();
    for segment in &segments[..segments.len() - 1] {
        current.push(segment);
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&current)?;
        if is_windows_reparse(&guard.metadata()?) || !guard.metadata()?.is_dir() {
            return Err(Error::PathInvalid(
                "reparse point or nondirectory component".into(),
            ));
        }
        guards.push(guard);
    }
    current.push(segments.last().expect("portable path is nonempty"));
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)?;
    if is_windows_reparse(&file.metadata()?) {
        return Err(Error::PathInvalid("reparse-point asset".into()));
    }
    Ok(SourceHandle {
        file,
        _directory_guards: guards,
    })
}

#[cfg(unix)]
fn open_source(root: &PackageRoot, relative: &str) -> Result<SourceHandle, Error> {
    use rustix::fs::{openat, Mode, OFlags};
    let segments = validate_resolution_input(relative)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = root.root_handle.try_clone()?;
    for segment in &segments[..segments.len() - 1] {
        directory = openat(&directory, *segment, directory_flags, Mode::empty())
            .map_err(map_unix_open_error)?
            .into();
    }
    let asset = openat(
        &directory,
        *segments.last().expect("portable path is nonempty"),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_unix_open_error)?;
    Ok(SourceHandle { file: asset.into() })
}

#[cfg(unix)]
fn map_unix_open_error(error: rustix::io::Errno) -> Error {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        Error::PathInvalid("symlink or non-directory path component".into())
    } else {
        Error::Io(std::io::Error::from(error))
    }
}

fn supported(media_type: &str) -> bool {
    matches!(media_type, "audio/wav" | "audio/flac")
}

fn magic_matches(media_type: &str, bytes: &[u8]) -> bool {
    match media_type {
        "audio/flac" => bytes.starts_with(b"fLaC"),
        "audio/wav" => bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        _ => false,
    }
}

fn reject_link(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_windows_reparse(&metadata) {
        return Err(Error::PathInvalid("symlink or reparse point".into()));
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_windows_reparse(_: &fs::Metadata) -> bool {
    false
}
