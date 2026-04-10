mod fetcher;

use std::env;
use std::fs;
use std::path::Path;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use log::{error, info, warn};

use fetcher::{der_to_pem, fetch_cert_chain};

const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";
const RENEW_THRESHOLD_DAYS: i64 = 29;
const DEFAULT_PORT: u16 = 443;

fn parse_host_port(arg: &str) -> (&str, u16) {
    let s = arg.strip_prefix("https://").unwrap_or(arg);
    let s = s.trim_end_matches('/');
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host, port);
        }
    }
    (s, DEFAULT_PORT)
}

fn write_cert_files(domain: &str, certs: &[Vec<u8>]) -> Result<()> {
    ensure!(!certs.is_empty(), "no certificates received");

    let dir = Path::new(LETSENCRYPT_LIVE).join(domain);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }

    // cert.pem = leaf certificate
    fs::write(dir.join("cert.pem"), der_to_pem(&certs[0]))?;
    info!("{}/cert.pem written", dir.display());

    // chain.pem = intermediate certificates
    let chain: String = certs[1..].iter().map(|c| der_to_pem(c)).collect();
    fs::write(dir.join("chain.pem"), &chain)?;
    info!("{}/chain.pem written", dir.display());

    // fullchain.pem = leaf + intermediates
    let fullchain: String = certs.iter().map(|c| der_to_pem(c)).collect();
    fs::write(dir.join("fullchain.pem"), &fullchain)?;
    info!("{}/fullchain.pem written", dir.display());

    Ok(())
}

fn cert_not_after(path: &Path) -> Result<i64> {
    let data = fs::read(path)?;
    let p = pem::parse(&data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(p.contents())?;
    Ok(cert.validity().not_after.timestamp())
}

fn cmd_fetch(host: &str, port: u16) -> Result<()> {
    info!("connecting to {}:{}", host, port);
    let certs = fetch_cert_chain(host, port)?;
    info!("received {} certificate(s)", certs.len());
    write_cert_files(host, &certs)
}

fn cmd_renew() -> Result<()> {
    let live = Path::new(LETSENCRYPT_LIVE);
    ensure!(live.exists(), "{LETSENCRYPT_LIVE} does not exist");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let threshold = now + RENEW_THRESHOLD_DAYS * 86400;
    let mut updated = 0u32;
    let mut skipped = 0u32;

    for entry in fs::read_dir(live)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }

        let domain = entry.file_name().to_string_lossy().into_owned();
        let cert_path = entry.path().join("cert.pem");

        if !cert_path.exists() {
            warn!("{}: no cert.pem, skipping", domain);
            skipped += 1;
            continue;
        }

        let not_after = match cert_not_after(&cert_path) {
            Ok(t) => t,
            Err(e) => {
                error!("{}: {}", domain, e);
                skipped += 1;
                continue;
            }
        };

        if not_after >= threshold {
            let days = (not_after - now) / 86400;
            info!("{}: {} days remaining, skipping", domain, days);
            skipped += 1;
            continue;
        }

        info!("{}: expiring soon, fetching new certificate", domain);
        match fetch_cert_chain(&domain, DEFAULT_PORT) {
            Ok(certs) => {
                write_cert_files(&domain, &certs)?;
                updated += 1;
            }
            Err(e) => {
                error!("{}: {}", domain, e);
                skipped += 1;
            }
        }
    }

    info!("done: {} updated, {} skipped", updated, skipped);
    Ok(())
}

fn cmd_install() -> Result<()> {
    let exe = env::current_exe()?;

    let service =
        include_str!("certferry-renew.service").replace("%CERTFERRY_EXE%", &exe.display().to_string());
    let timer = include_str!("certferry-renew.timer");

    let svc_path = "/etc/systemd/system/certferry-renew.service";
    let tmr_path = "/etc/systemd/system/certferry-renew.timer";

    fs::write(svc_path, &service)?;
    info!("wrote {}", svc_path);

    fs::write(tmr_path, timer)?;
    info!("wrote {}", tmr_path);

    let ok = Command::new("systemctl")
        .arg("daemon-reload")
        .status()?
        .success()
        && Command::new("systemctl")
            .args(["enable", "--now", "certferry-renew.timer"])
            .status()?
            .success();

    if ok {
        info!("certferry-renew.timer enabled and started");
    } else {
        error!("failed to enable timer — run manually: systemctl daemon-reload && systemctl enable --now certferry-renew.timer");
    }

    Ok(())
}

fn main() {
    logsy::set_echo(true);

    let args: Vec<String> = env::args().collect();

    let result = match args.get(1).map(String::as_str) {
        Some("--renew") => cmd_renew(),
        Some("--install") => cmd_install(),
        Some(arg) => {
            let (host, port) = parse_host_port(arg);
            cmd_fetch(host, port)
        }
        None => {
            eprintln!("Usage:");
            eprintln!("  certferry <domain>      Fetch certificate from remote host");
            eprintln!("  certferry --renew       Renew expiring local certificates");
            eprintln!("  certferry --install     Install systemd timer for periodic renewal");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        error!("{:#}", e);
        process::exit(1);
    }
}
