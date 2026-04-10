use std::fs;
use std::path::Path;
use std::process::Command;

const LIVE_DIR: &str = "/etc/letsencrypt/live";

fn certferry() -> Command {
    Command::new(env!("CARGO_BIN_EXE_certferry"))
}

fn setup() {
    fs::create_dir_all(LIVE_DIR).unwrap();
}

fn cleanup(domain: &str) {
    let _ = fs::remove_dir_all(Path::new(LIVE_DIR).join(domain));
}

#[test]
fn fetch_google_com() {
    setup();
    cleanup("google.com");

    let out = certferry().arg("google.com").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dir = Path::new(LIVE_DIR).join("google.com");
    assert!(dir.join("cert.pem").exists());
    assert!(dir.join("chain.pem").exists());
    assert!(dir.join("fullchain.pem").exists());

    cleanup("google.com");
}

#[test]
fn fetch_with_https_prefix() {
    setup();
    cleanup("one.one.one.one");

    let out = certferry().arg("https://one.one.one.one").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        Path::new(LIVE_DIR)
            .join("one.one.one.one/cert.pem")
            .exists()
    );

    cleanup("one.one.one.one");
}

#[test]
fn cert_pem_is_valid_pem() {
    setup();
    cleanup("cloudflare.com");

    let out = certferry().arg("cloudflare.com").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let data = fs::read(Path::new(LIVE_DIR).join("cloudflare.com/cert.pem")).unwrap();
    let parsed = pem::parse(&data).unwrap();
    assert_eq!(parsed.tag(), "CERTIFICATE");

    cleanup("cloudflare.com");
}

#[test]
fn chain_pem_is_non_empty() {
    setup();
    cleanup("google.com");

    certferry().arg("google.com").output().unwrap();

    let chain = fs::read_to_string(Path::new(LIVE_DIR).join("google.com/chain.pem")).unwrap();
    assert!(
        !chain.is_empty(),
        "chain.pem should contain intermediate certs"
    );
    let certs = pem::parse_many(chain.as_bytes()).unwrap();
    assert!(
        !certs.is_empty(),
        "chain.pem should contain at least one cert"
    );

    cleanup("google.com");
}

#[test]
fn fullchain_equals_cert_plus_chain() {
    setup();
    cleanup("google.com");

    certferry().arg("google.com").output().unwrap();

    let dir = Path::new(LIVE_DIR).join("google.com");
    let cert = fs::read_to_string(dir.join("cert.pem")).unwrap();
    let chain = fs::read_to_string(dir.join("chain.pem")).unwrap();
    let fullchain = fs::read_to_string(dir.join("fullchain.pem")).unwrap();

    assert_eq!(fullchain, format!("{cert}{chain}"));

    cleanup("google.com");
}

#[test]
fn fullchain_has_multiple_certs() {
    setup();
    cleanup("google.com");

    certferry().arg("google.com").output().unwrap();

    let data = fs::read(Path::new(LIVE_DIR).join("google.com/fullchain.pem")).unwrap();
    let certs = pem::parse_many(&data).unwrap();
    assert!(
        certs.len() >= 2,
        "fullchain should have leaf + at least one intermediate, got {}",
        certs.len()
    );

    cleanup("google.com");
}

#[test]
fn creates_domain_directory() {
    setup();
    cleanup("example.google.com");
    let dir = Path::new(LIVE_DIR).join("example.google.com");
    assert!(!dir.exists());

    // This will fail on the domain (no such host) but directory should be attempted
    // Actually, it won't create the dir if fetch fails. Let's use a real domain.
    cleanup("github.com");
    let dir = Path::new(LIVE_DIR).join("github.com");
    assert!(!dir.exists());

    let out = certferry().arg("github.com").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.is_dir());

    cleanup("github.com");
}

#[test]
fn overwrites_existing_cert_files() {
    setup();
    cleanup("google.com");

    // First fetch
    certferry().arg("google.com").output().unwrap();
    let first = fs::read_to_string(Path::new(LIVE_DIR).join("google.com/cert.pem")).unwrap();

    // Second fetch — should overwrite (content will be same since it's the same server)
    certferry().arg("google.com").output().unwrap();
    let second = fs::read_to_string(Path::new(LIVE_DIR).join("google.com/cert.pem")).unwrap();

    // Same server = same cert (barring a rotation mid-test)
    assert_eq!(first, second);

    cleanup("google.com");
}

#[test]
fn fetch_with_explicit_port() {
    setup();
    cleanup("google.com");

    let out = certferry().arg("google.com:443").output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(Path::new(LIVE_DIR).join("google.com/cert.pem").exists());

    cleanup("google.com");
}
