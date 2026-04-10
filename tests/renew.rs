use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const LIVE_DIR: &str = "/etc/letsencrypt/live";

fn certferry() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certferry"))
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn make_cert_pem(days_until_expiry: i64) -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let ts = now_ts() + days_until_expiry * 86400;
    let dt = time::OffsetDateTime::from_unix_timestamp(ts).unwrap();
    params.not_after = rcgen::date_time_ymd(dt.year(), dt.month() as u8, dt.day());
    params.self_signed(&key).unwrap().pem()
}

fn setup_domain(domain: &str, cert_pem: &str) {
    let dir = Path::new(LIVE_DIR).join(domain);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), cert_pem).unwrap();
}

fn cleanup(domain: &str) {
    let _ = fs::remove_dir_all(Path::new(LIVE_DIR).join(domain));
}

fn setup() {
    fs::create_dir_all(LIVE_DIR).unwrap();
}

// Use a real domain so --renew can fetch from it
const TEST_DOMAIN: &str = "google.com";

#[test]
fn renew_updates_expiring_cert() {
    setup();
    cleanup(TEST_DOMAIN);

    // Plant a cert that expires in 5 days
    let expiring_pem = make_cert_pem(5);
    setup_domain(TEST_DOMAIN, &expiring_pem);

    let before =
        fs::read_to_string(Path::new(LIVE_DIR).join(format!("{TEST_DOMAIN}/cert.pem"))).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after =
        fs::read_to_string(Path::new(LIVE_DIR).join(format!("{TEST_DOMAIN}/cert.pem"))).unwrap();

    // Cert should have been replaced with the real one from the server
    assert_ne!(before, after, "cert.pem should have been updated");

    // The new cert should be valid PEM
    let parsed = pem::parse(after.as_bytes()).unwrap();
    assert_eq!(parsed.tag(), "CERTIFICATE");

    cleanup(TEST_DOMAIN);
}

#[test]
fn renew_skips_valid_cert() {
    setup();
    // Use a different domain that resolves to avoid conflicts
    let domain = "cloudflare.com";
    cleanup(domain);

    // Plant a cert that expires in 365 days
    let valid_pem = make_cert_pem(365);
    setup_domain(domain, &valid_pem);

    let before =
        fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    // Cert should NOT have been replaced
    assert_eq!(before, after, "valid cert should not be updated");

    cleanup(domain);
}

#[test]
fn renew_force_updates_valid_cert() {
    setup();
    let domain = "google.com";
    cleanup(domain);

    // Plant a cert that expires in 365 days (would normally be skipped)
    let valid_pem = make_cert_pem(365);
    setup_domain(domain, &valid_pem);

    let before =
        fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    assert_ne!(before, after, "--force should update even valid certs");

    cleanup(domain);
}

#[test]
fn force_renew_order_independent() {
    setup();
    let domain = "google.com";
    cleanup(domain);

    let valid_pem = make_cert_pem(365);
    setup_domain(domain, &valid_pem);

    let before =
        fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    // --force before --renew
    let out = certferry().args(["--force", "--renew"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = fs::read_to_string(Path::new(LIVE_DIR).join(format!("{domain}/cert.pem"))).unwrap();

    assert_ne!(before, after, "--force --renew should work in any order");

    cleanup(domain);
}

#[test]
fn renew_empty_live_dir() {
    setup();
    // Make sure no domain dirs exist (clean slate)
    for entry in fs::read_dir(LIVE_DIR).unwrap() {
        let entry = entry.unwrap();
        if entry.path().is_dir() {
            fs::remove_dir_all(entry.path()).ok();
        }
    }

    let out = certferry().arg("--renew").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output = String::from_utf8_lossy(&out.stdout);
    assert!(
        output.contains("0 updated") && output.contains("0 skipped"),
        "expected 0 updated/skipped, got: {output}"
    );
}

#[test]
fn renew_domain_without_cert_pem_skipped() {
    setup();
    let domain = "nocert.test";
    cleanup(domain);

    // Create domain dir but NO cert.pem
    fs::create_dir_all(Path::new(LIVE_DIR).join(domain)).unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    // Should succeed overall, just skip this domain
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    cleanup(domain);
}

#[test]
fn renew_with_invalid_cert_pem_skipped() {
    setup();
    let domain = "badcert.test";
    cleanup(domain);

    let dir = Path::new(LIVE_DIR).join(domain);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), "this is not a certificate").unwrap();

    let out = certferry().arg("--renew").output().unwrap();
    // Should succeed overall — invalid cert is logged and skipped
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    cleanup(domain);
}

#[test]
fn renew_unchanged_cert_not_counted_as_updated() {
    setup();
    let domain = "google.com";
    cleanup(domain);

    // First: fetch the real cert
    let out = certferry().arg(domain).output().unwrap();
    assert!(
        out.status.success(),
        "initial fetch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Now --renew --force: should fetch same cert, detect unchanged, skip
    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let output = String::from_utf8_lossy(&out.stdout);
    assert!(
        output.contains("0 updated"),
        "unchanged cert should not count as updated, got: {output}"
    );

    cleanup(domain);
}

#[test]
fn renew_unchanged_cert_no_deploy_hooks() {
    setup();
    let domain = "google.com";
    cleanup(domain);

    let hooks_dir = Path::new("/etc/letsencrypt/renewal-hooks/deploy");
    fs::create_dir_all(hooks_dir).unwrap();

    let marker = Path::new("/tmp/certferry-hook-test-marker");
    let _ = fs::remove_file(marker);

    let hook = hooks_dir.join("certferry-test-hook.sh");
    fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Fetch real cert
    certferry().arg(domain).output().unwrap();

    // Ensure marker doesn't exist from previous run
    let _ = fs::remove_file(marker);

    // Force renew — cert unchanged, hooks should NOT run
    let out = certferry().args(["--renew", "--force"]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !marker.exists(),
        "deploy hook should not run when cert is unchanged"
    );

    // Cleanup
    let _ = fs::remove_file(&hook);
    let _ = fs::remove_file(marker);
    cleanup(domain);
}
