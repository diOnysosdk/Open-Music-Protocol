# ADR-015: Desktop GUI framework

**Status:** Accepted for the experimental W10 reference player, 2026-10-27.

## Decision

Use `eframe/egui` 0.33 with its OpenGL (`glow`) native backend and Windows,
X11, and Wayland support. Keep persistence, GUI state, OMP application
services, protocol verification, and playback in separate modules/crates.

## Rationale

`eframe` is Rust-native, cross-platform, immediate-mode, easy to exercise at
the state layer without a display server, and does not require Electron or a
network service. The locked desktop dependency graph requires Rust 1.88 or
newer. Iced was not selected because its official documentation describes it
as experimental. Slint is technically capable and lightweight, including on
embedded targets, but its multi-license/application-attribution choices add an
unnecessary policy decision for this Apache-2.0/MIT reference workspace.

## Boundaries

The GUI may render only metadata returned after `AuthenticatedManifest`
verification. Play creates audio only from `omp_player::PreparedPlayback`.
GUI state cannot construct a playback permit or independently evaluate a
license. The existing Symphonia/Rodio path remains the decoder/audio backend.
