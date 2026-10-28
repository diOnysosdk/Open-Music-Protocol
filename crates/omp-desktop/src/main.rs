use omp_desktop::ui::DesktopApp;
use std::path::PathBuf;

fn default_index() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("XDG_DATA_HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("omp-reference-player/library.json")
}

fn main() -> eframe::Result<()> {
    let index = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_index);
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("OMP Reference Player")
            .with_inner_size([1280.0, 760.0])
            .with_min_inner_size([800.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "OMP Reference Player",
        options,
        Box::new(move |_| Box::new(DesktopApp::load(index))),
    )
}
