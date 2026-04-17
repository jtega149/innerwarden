use std::path::Path;
use std::process::Command;

#[test]
fn replay_subcommand_passes_with_bundled_testdata() {
    let bin = env!("CARGO_BIN_EXE_innerwarden-ctl");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let output = Command::new(bin)
        .args([
            "replay",
            "--fixture",
            root.join("testdata/fixtures").to_str().unwrap(),
            "--expected",
            root.join("testdata/expected.json").to_str().unwrap(),
        ])
        .output()
        .expect("failed to spawn innerwarden-ctl");

    assert!(
        output.status.success(),
        "replay should pass with bundled testdata\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
