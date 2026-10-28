//! Native egui presentation layer; protocol decisions remain in `service`.

use crate::{
    library::Library,
    service,
    state::{AppState, Transport, View},
};
use eframe::egui;
use omp_identity::IdentityTrust;
use omp_player::LocalPlayback;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// Desktop application with local-only persistence and playback.
pub struct DesktopApp {
    /// Testable application state.
    pub state: AppState,
    index_path: PathBuf,
    import_path: String,
    trust_confirmed: bool,
    playback: Option<LocalPlayback>,
}

impl DesktopApp {
    /// Load a desktop application from the chosen local index.
    pub fn load(index_path: PathBuf) -> Self {
        let mut state = AppState {
            library: Library::load(&index_path).unwrap_or_else(|error| {
                let mut library = Library {
                    format: 1,
                    tracks: Vec::new(),
                };
                library.tracks.clear();
                eprintln!("OMP-DIAG-OPERATIONAL: cannot load library index: {error}");
                library
            }),
            volume: 0.8,
            ..AppState::default()
        };
        state.library.refresh_presence();
        Self {
            state,
            index_path,
            import_path: String::new(),
            trust_confirmed: false,
            playback: None,
        }
    }

    fn import(&mut self) {
        let trust = if self.trust_confirmed {
            IdentityTrust::Verified
        } else {
            IdentityTrust::Unknown
        };
        match service::inspect_package(Path::new(self.import_path.trim()), trust) {
            Ok(track) => {
                self.state.library.upsert(track);
                if let Err(error) = self.state.library.save(&self.index_path) {
                    self.state.error =
                        Some(format!("OMP-DIAG-OPERATIONAL — cannot save index: {error}"));
                } else {
                    self.state.error = None;
                }
            }
            Err(error) => {
                self.state.error = Some(format!("{}: {error}", service::diagnostic(&error)))
            }
        }
    }

    fn play_selected(&mut self) {
        let Some(index) = self.state.selected else {
            return;
        };
        let Some(track) = self.state.library.tracks.get(index) else {
            return;
        };
        let trust = if self.trust_confirmed {
            IdentityTrust::Verified
        } else {
            IdentityTrust::Unknown
        };
        match service::start_playback(Path::new(&track.package_path), trust) {
            Ok(playback) => {
                playback.set_volume(self.state.volume);
                self.playback = Some(playback);
                self.state.transport = Transport::Playing;
                self.state.error = None;
            }
            Err(error) => {
                self.state.transport = Transport::Stopped;
                self.state.error = Some(format!("{}: {error}", service::diagnostic(&error)));
            }
        }
    }

    fn toggle_pause(&mut self) {
        match (&self.playback, self.state.transport) {
            (Some(playback), Transport::Playing) => {
                playback.pause();
                self.state.transport = Transport::Paused;
            }
            (Some(playback), Transport::Paused) => {
                playback.resume();
                self.state.transport = Transport::Playing;
            }
            _ => self.play_selected(),
        }
    }

    fn stop(&mut self) {
        if let Some(playback) = self.playback.take() {
            playback.stop();
        }
        self.state.transport = Transport::Stopped;
    }

    fn keyboard(&mut self, context: &egui::Context) {
        if context.input(|input| input.key_pressed(egui::Key::Space)) {
            self.toggle_pause();
        }
        if context
            .input(|input| input.key_pressed(egui::Key::ArrowRight) && input.modifiers.command)
        {
            self.stop();
            self.state.next();
            self.play_selected();
        }
        if context.input(|input| input.key_pressed(egui::Key::ArrowLeft) && input.modifiers.command)
        {
            self.stop();
            self.state.previous();
            self.play_selected();
        }
        if context.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.stop();
        }
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, context: &egui::Context, _: &mut eframe::Frame) {
        context.set_visuals(egui::Visuals::dark());
        self.keyboard(context);
        if self
            .playback
            .as_ref()
            .is_some_and(LocalPlayback::is_finished)
        {
            self.playback = None;
            self.state.transport = Transport::Stopped;
            if !self.state.library.tracks.is_empty() {
                self.state.next();
            }
        }

        egui::SidePanel::left("navigation")
            .resizable(false)
            .default_width(140.0)
            .show(context, |ui| {
                ui.heading("OMP");
                ui.label("Reference Player");
                ui.separator();
                for (view, label) in [
                    (View::Library, "Library"),
                    (View::Albums, "Albums"),
                    (View::Artists, "Artists"),
                    (View::Queue, "Queue"),
                ] {
                    if ui
                        .selectable_label(self.state.view == view, label)
                        .clicked()
                    {
                        self.state.view = view;
                    }
                }
                ui.separator();
                ui.small("Offline • W8-11 OPEN/HIGH");
            });

        egui::SidePanel::right("details").resizable(true).default_width(290.0).show(context, |ui| {
            ui.heading("Verification details");
            if let Some(track) = self.state.selected.and_then(|index| self.state.library.tracks.get(index)) {
                ui.strong(&track.title); ui.label(&track.artist); ui.separator();
                egui::Grid::new("security").num_columns(2).striped(true).show(ui, |ui| {
                    for (label, value) in [
                        ("Signature", &track.security.authenticity), ("Key authorization", &track.security.key_authorization),
                        ("Trust", &track.security.trust), ("Package integrity", &track.security.package_integrity),
                        ("License", &track.security.license), ("Playback", &track.security.playback),
                    ] { ui.label(label); ui.label(value); ui.end_row(); }
                });
                ui.separator();
                ui.small("A valid signature authenticates bytes only. It is not proof of ownership or legal rights.");
            } else { ui.label("Select a verified track to inspect its independent security axes."); }
        });

        egui::TopBottomPanel::bottom("transport")
            .min_height(92.0)
            .show(context, |ui| {
                ui.horizontal_centered(|ui| {
                    if ui
                        .button("⏮")
                        .on_hover_text("Previous (Ctrl+Left)")
                        .clicked()
                    {
                        self.stop();
                        self.state.previous();
                    }
                    if ui
                        .button(if self.state.transport == Transport::Playing {
                            "⏸"
                        } else {
                            "▶"
                        })
                        .on_hover_text("Play/Pause (Space)")
                        .clicked()
                    {
                        self.toggle_pause();
                    }
                    if ui.button("⏹").on_hover_text("Stop (Esc)").clicked() {
                        self.stop();
                    }
                    if ui.button("⏭").on_hover_text("Next (Ctrl+Right)").clicked() {
                        self.stop();
                        self.state.next();
                    }
                    let mut seconds = self
                        .playback
                        .as_ref()
                        .map_or(0.0, |playback| playback.position().as_secs_f64());
                    if ui
                        .add(egui::Slider::new(&mut seconds, 0.0..=14_400.0).text("progress"))
                        .changed()
                    {
                        if let Some(playback) = &self.playback {
                            if let Err(error) = playback.seek(Duration::from_secs_f64(seconds)) {
                                self.state.error = Some(error.to_string());
                            }
                        }
                    }
                    if ui
                        .add(egui::Slider::new(&mut self.state.volume, 0.0..=1.0).text("volume"))
                        .changed()
                    {
                        if let Some(playback) = &self.playback {
                            playback.set_volume(self.state.volume);
                        }
                    }
                });
                if let Some(track) = self
                    .state
                    .selected
                    .and_then(|index| self.state.library.tracks.get(index))
                {
                    ui.horizontal_centered(|ui| {
                        ui.strong(&track.title);
                        ui.label(format!("— {}", track.artist));
                    });
                }
            });

        egui::CentralPanel::default().show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading(match self.state.view {
                    View::Library => "Music library",
                    View::Albums => "Albums",
                    View::Artists => "Artists",
                    View::Queue => "Queue",
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.state.search)
                            .hint_text("Search title, artist, album"),
                    );
                });
            });
            ui.horizontal(|ui| {
                ui.label("Package directory:");
                ui.add(egui::TextEdit::singleline(&mut self.import_path).desired_width(360.0));
                if ui.button("Import and verify").clicked() {
                    self.import();
                }
            });
            ui.checkbox(
                &mut self.trust_confirmed,
                "I established this signer identity through an independent trusted channel",
            );
            if let Some(error) = &self.state.error {
                ui.colored_label(egui::Color32::LIGHT_RED, error);
            }
            ui.separator();
            if self.state.library.tracks.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.heading("Your local library is empty");
                    ui.label("Enter an OMP package directory to verify and import it.");
                });
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                for index in self.state.filtered() {
                    let track = &self.state.library.tracks[index];
                    let label = match self.state.view {
                        View::Albums => {
                            format!("{}  ·  {}  —  {}", track.album, track.title, track.artist)
                        }
                        View::Artists => {
                            format!("{}  ·  {}  —  {}", track.artist, track.title, track.album)
                        }
                        View::Queue => {
                            if self.state.queue.contains(&index) {
                                format!("{} — {}", track.title, track.artist)
                            } else {
                                continue;
                            }
                        }
                        View::Library => {
                            format!("{} — {}  ·  {}", track.title, track.artist, track.album)
                        }
                    };
                    ui.horizontal(|ui| {
                        let status = if track.present { "✓" } else { "Missing" };
                        if ui
                            .selectable_label(self.state.selected == Some(index), label)
                            .clicked()
                        {
                            self.state.selected = Some(index);
                        }
                        ui.label(&track.duration);
                        ui.label(status);
                        if ui.small_button("+").on_hover_text("Add to queue").clicked()
                            && !self.state.queue.contains(&index)
                        {
                            self.state.queue.push(index);
                        }
                    });
                }
            });
        });
        context.request_repaint_after(Duration::from_millis(250));
    }
}
