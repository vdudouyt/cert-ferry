use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Result};
use log::{error, info, warn};

use crate::config::{DEFAULT_PORT, DEPLOY_HOOKS, LETSENCRYPT_LIVE, RENEW_THRESHOLD_DAYS};
use crate::fetcher::fetch_cert_chain;
use crate::write_cert_files;

fn cert_not_after(path: &Path) -> Result<i64> {
    let data = fs::read(path)?;
    let p = pem::parse(&data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(p.contents())?;
    Ok(cert.validity().not_after.timestamp())
}

/// Try to renew a single domain. Returns Ok(true) if renewed, Ok(false) if skipped.
fn try_renew(domain: &str, now: i64, threshold: i64, force: bool) -> Result<bool> {
    let cert_path = Path::new(LETSENCRYPT_LIVE).join(domain).join("cert.pem");
    if !cert_path.exists() {
        warn!("{}: no cert.pem, skipping", domain);
        return Ok(false);
    }

    if !force {
        let not_after = cert_not_after(&cert_path)?;
        if not_after >= threshold {
            let days = (not_after - now) / 86400;
            info!("{}: {} days remaining, skipping", domain, days);
            return Ok(false);
        }
    }

    info!("{}: fetching certificate", domain);
    let certs = fetch_cert_chain(domain, DEFAULT_PORT)?;
    write_cert_files(domain, &certs)?;
    Ok(true)
}

fn run_deploy_hooks(domain: &str) {
    let hooks_dir = Path::new(DEPLOY_HOOKS);
    if !hooks_dir.is_dir() {
        return;
    }

    let lineage = Path::new(LETSENCRYPT_LIVE).join(domain);
    let entries = match fs::read_dir(hooks_dir) {
        Ok(e) => e,
        Err(e) => { warn!("could not read {}: {}", DEPLOY_HOOKS, e); return; }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        info!("running deploy hook: {}", path.display());
        let result = Command::new(&path)
            .env("RENEWED_LINEAGE", &lineage)
            .env("RENEWED_DOMAINS", domain)
            .status();
        if let Err(e) = result {
            warn!("hook {} failed: {}", path.display(), e);
        }
    }
}

pub fn cmd_renew(force: bool) -> Result<()> {
    let live = Path::new(LETSENCRYPT_LIVE);
    ensure!(live.exists(), "{LETSENCRYPT_LIVE} does not exist");

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let threshold = now + RENEW_THRESHOLD_DAYS * 86400;
    let mut updated = 0u32;
    let mut skipped = 0u32;
    let mut renewed_domains = Vec::new();

    for entry in fs::read_dir(live)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }

        let domain = entry.file_name().to_string_lossy().into_owned();
        let renewed = try_renew(&domain, now, threshold, force).unwrap_or_else(|e| {
            error!("{}: {:#}", domain, e);
            false
        });
        if renewed {
            updated += 1;
            renewed_domains.push(domain);
        } else {
            skipped += 1;
        }
    }

    for domain in &renewed_domains {
        run_deploy_hooks(domain);
    }

    info!("done: {} updated, {} skipped", updated, skipped);
    Ok(())
}
