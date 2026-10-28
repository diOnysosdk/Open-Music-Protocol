//! Persistent local library index containing authenticated display facts.

use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

/// Security axes shown separately in the details panel.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityStatus {
    /// Manifest signature result.
    pub authenticity: String,
    /// Required signer-role result.
    pub key_authorization: String,
    /// Local identity bootstrap/freshness result.
    pub trust: String,
    /// Exact local asset binding result.
    pub package_integrity: String,
    /// Offline entitlement result.
    pub license: String,
    /// Final playback preparation result.
    pub playback: String,
    /// Stable non-normative diagnostic category when rejected.
    pub diagnostic: Option<String>,
}

/// One locally indexed package. Display metadata is stored only after authentication.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Track {
    /// Authenticated recording identifier.
    pub recording_id: String,
    /// Canonical package directory.
    pub package_path: String,
    /// Authenticated title.
    pub title: String,
    /// Authenticated joined artist credit.
    pub artist: String,
    /// Authenticated release title, if declared.
    pub album: String,
    /// Duration label; v0.2 does not currently authenticate duration metadata.
    pub duration: String,
    /// Artwork status; v0.2 does not currently define a verified artwork asset.
    pub artwork: Option<String>,
    /// Latest verification state.
    pub security: SecurityStatus,
    /// Whether the package directory was present during the last refresh.
    pub present: bool,
}

/// Versioned local library index.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Library {
    /// Index format version.
    pub format: u32,
    /// Indexed tracks.
    pub tracks: Vec<Track>,
}

impl Library {
    /// Load an index or return a new empty index when it does not exist.
    pub fn load(path: &Path) -> Result<Self, io::Error> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self {
                format: 1,
                tracks: Vec::new(),
            }),
            Err(error) => Err(error),
        }
    }

    /// Atomically save the index without embedding protocol documents or keys.
    pub fn save(&self, path: &Path) -> Result<(), io::Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)
    }

    /// Insert or replace by recording identifier and keep deterministic ordering.
    pub fn upsert(&mut self, track: Track) {
        self.tracks
            .retain(|item| item.recording_id != track.recording_id);
        self.tracks.push(track);
        self.tracks.sort_by(|left, right| {
            left.artist
                .cmp(&right.artist)
                .then(left.album.cmp(&right.album))
                .then(left.title.cmp(&right.title))
        });
    }

    /// Refresh missing-file indicators without trusting new package contents.
    pub fn refresh_presence(&mut self) {
        for track in &mut self.tracks {
            track.present = Path::new(&track.package_path).is_dir();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_round_trip_and_upsert_are_deterministic() {
        let root = std::env::temp_dir().join(format!("omp-library-{}", std::process::id()));
        let path = root.join("library.json");
        let mut library = Library {
            format: 1,
            tracks: Vec::new(),
        };
        let track = Track {
            recording_id: "recording".into(),
            package_path: root.display().to_string(),
            title: "Title".into(),
            artist: "Artist".into(),
            album: "Album".into(),
            duration: "Not declared".into(),
            artwork: None,
            security: SecurityStatus::default(),
            present: false,
        };
        library.upsert(track.clone());
        library.upsert(track);
        library.save(&path).unwrap();
        assert_eq!(Library::load(&path).unwrap().tracks.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
