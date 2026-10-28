//! Testable GUI state transitions independent of rendering and audio hardware.

use crate::library::Library;

/// Primary collection view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum View {
    /// All tracks.
    #[default]
    Library,
    /// Album groups.
    Albums,
    /// Artist groups.
    Artists,
    /// Playback queue.
    Queue,
}

/// Playback state reflected by transport controls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// No active session.
    #[default]
    Stopped,
    /// Audio is running.
    Playing,
    /// Session is authorized but paused.
    Paused,
}

/// Serializable-independent application state.
#[derive(Default)]
pub struct AppState {
    /// Persistent collection.
    pub library: Library,
    /// Current navigation view.
    pub view: View,
    /// Case-insensitive search text.
    pub search: String,
    /// Selected track index.
    pub selected: Option<usize>,
    /// Queue of track indices.
    pub queue: Vec<usize>,
    /// Transport state.
    pub transport: Transport,
    /// Linear volume.
    pub volume: f32,
    /// Last user-facing error.
    pub error: Option<String>,
}

impl AppState {
    /// Indices matching title, artist, or album.
    pub fn filtered(&self) -> Vec<usize> {
        let query = self.search.to_lowercase();
        self.library
            .tracks
            .iter()
            .enumerate()
            .filter(|(_, track)| {
                query.is_empty()
                    || track.title.to_lowercase().contains(&query)
                    || track.artist.to_lowercase().contains(&query)
                    || track.album.to_lowercase().contains(&query)
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Select the next available track, wrapping at the end.
    pub fn next(&mut self) {
        if self.library.tracks.is_empty() {
            self.selected = None;
            return;
        }
        self.selected = Some((self.selected.unwrap_or(0) + 1) % self.library.tracks.len());
    }

    /// Select the previous available track, wrapping at the beginning.
    pub fn previous(&mut self) {
        if self.library.tracks.is_empty() {
            self.selected = None;
            return;
        }
        let current = self.selected.unwrap_or(0);
        self.selected = Some(if current == 0 {
            self.library.tracks.len() - 1
        } else {
            current - 1
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::{SecurityStatus, Track};

    fn track(title: &str, artist: &str, album: &str) -> Track {
        Track {
            recording_id: title.into(),
            package_path: ".".into(),
            title: title.into(),
            artist: artist.into(),
            album: album.into(),
            duration: "n/a".into(),
            artwork: None,
            security: SecurityStatus::default(),
            present: true,
        }
    }

    #[test]
    fn search_and_transport_navigation_are_deterministic() {
        let mut state = AppState::default();
        state.library.tracks = vec![track("First", "Ada", "One"), track("Second", "Bob", "Two")];
        state.search = "ada".into();
        assert_eq!(state.filtered(), vec![0]);
        state.selected = Some(0);
        state.next();
        assert_eq!(state.selected, Some(1));
        state.previous();
        assert_eq!(state.selected, Some(0));
    }
}
