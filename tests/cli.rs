use std::process::Command;

fn certferry() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certferry"))
}

#[test]
fn no_args_prints_usage_and_exits_1() {
    let out = certferry().output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message, got: {stderr}"
    );
}

#[test]
fn force_alone_prints_usage() {
    let out = certferry().arg("--force").output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message, got: {stderr}"
    );
}

#[test]
fn nonexistent_domain_exits_with_error() {
    let out = certferry().arg("nonexistent.invalid").output().unwrap();
    assert!(!out.status.success());
}
