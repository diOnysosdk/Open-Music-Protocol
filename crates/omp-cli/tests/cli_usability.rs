use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn omp(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omp"))
        .args(args)
        .output()
        .expect("OMP CLI must start")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn global_and_command_help_are_available_without_side_effects() {
    let global = omp(&["--help"]);
    assert!(global.status.success());
    assert!(stdout(&global).contains("Commands:"));

    for command in ["keygen", "pack", "inspect", "verify"] {
        let output = omp(&[command, "--help"]);
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(stdout(&output).contains("USAGE:"));
    }
}

#[test]
fn version_is_machine_readable() {
    let output = omp(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        format!("omp {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn missing_duplicate_and_unknown_options_fail_clearly() {
    let missing = omp(&["verify", "audio.wav", "manifest.json", "--public-key"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("--public-key requires a value"));
    assert!(stderr(&missing).contains("OMP-DIAG-USAGE"));

    let duplicate = omp(&["inspect", "a.json", "--x=one", "--x=two"]);
    assert!(!duplicate.status.success());
    assert!(stderr(&duplicate).contains("duplicate --x"));

    let unknown = omp(&["inspect", "a.json", "--unknown=value"]);
    assert!(!unknown.status.success());
    assert!(stderr(&unknown).contains("unknown option --unknown"));
}

#[test]
fn malformed_content_has_a_stable_actionable_category() {
    let root = std::env::temp_dir().join(format!("omp-cli-malformed-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("bad.json");
    std::fs::write(&path, b"{not-json").unwrap();
    let output = omp(&["inspect", path.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("OMP-DIAG-MALFORMED-CONTENT"));
    assert!(stderr(&output).contains("action:"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn short_options_are_not_misreported_as_file_paths() {
    let output = omp(&["inspect", "-x"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unsupported short option `-x`"));
}

#[test]
fn missing_input_names_the_file_that_could_not_be_read() {
    let output = omp(&["inspect", "definitely-missing-manifest.json"]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cannot read definitely-missing-manifest.json"));
}

#[test]
fn offline_package_inspect_and_verify_workflow_succeeds() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("omp-cli-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let audio = root.join("sample.wav");
    let private = root.join("test.private.json");
    let public = root.join("test.public.json");
    let manifest = root.join("sample.omc.json");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../omp-spec-v0.2-draft/fixtures/audio/omp-triangle-250ms.wav"),
        &audio,
    )
    .unwrap();

    let run = |args: &[String]| {
        Command::new(env!("CARGO_BIN_EXE_omp"))
            .args(args)
            .output()
            .expect("OMP CLI must start")
    };
    let keygen = run(&[
        "keygen".into(),
        "--key-id=test-key-01".into(),
        "--private".into(),
        private.display().to_string(),
        "--public".into(),
        public.display().to_string(),
    ]);
    assert!(keygen.status.success(), "{}", stderr(&keygen));

    let pack = run(&[
        "pack".into(),
        audio.display().to_string(),
        "--manifest-id=omp:manifest:test-001".into(),
        "--recording-id=omp:recording:test-001".into(),
        "--work-id=omp:work:test-001".into(),
        "--issuer-id=omp:party:test-001".into(),
        "--agreement-id=omp:agreement:test-001".into(),
        "--license-id=omp:license:test-001".into(),
        "--created-at=2026-01-01T00:00:00Z".into(),
        "--private-key".into(),
        private.display().to_string(),
        "--output".into(),
        manifest.display().to_string(),
    ]);
    assert!(pack.status.success(), "{}", stderr(&pack));
    let manifest_text = std::fs::read_to_string(&manifest).unwrap();
    assert!(!manifest_text.contains("private_key"));

    let inspect = run(&["inspect".into(), manifest.display().to_string()]);
    assert!(inspect.status.success(), "{}", stderr(&inspect));
    assert!(stdout(&inspect).contains("signature:    present (not verified by inspect)"));

    let verify = run(&[
        "verify".into(),
        audio.display().to_string(),
        manifest.display().to_string(),
        "--public-key".into(),
        public.display().to_string(),
    ]);
    assert!(verify.status.success(), "{}", stderr(&verify));
    assert!(stdout(&verify).contains("signature and audio bytes are valid"));

    std::fs::remove_dir_all(root).unwrap();
}
