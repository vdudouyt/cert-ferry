mod cmd_fetch;
mod cmd_install;
mod cmd_renew;
mod fetcher;

use std::path::Path;
use std::process;

use anyhow::{ensure, Result};
use log::error;

use fetcher::der_to_pem;

pub(crate) const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";
pub(crate) const DEPLOY_HOOKS: &str = "/etc/letsencrypt/renewal-hooks/deploy";
pub(crate) const RENEW_THRESHOLD_DAYS: i64 = 29;
pub(crate) const DEFAULT_PORT: u16 = 443;

fn parse_host_port(arg: &str) -> (&str, u16) {
    let s = arg.strip_prefix("https://").unwrap_or(arg).trim_end_matches('/');
    s.rsplit_once(':').and_then(|(h, p)| p.parse().ok().map(|p| (h, p))).unwrap_or((s, DEFAULT_PORT))
}

pub(crate) fn write_cert_files(domain: &str, certs: &[Vec<u8>]) -> Result<()> {
    ensure!(!certs.is_empty(), "no certificates received");

    let dir = Path::new(LETSENCRYPT_LIVE).join(domain);
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }

    std::fs::write(dir.join("cert.pem"), der_to_pem(&certs[0]))?;
    log::info!("{}/cert.pem written", dir.display());

    let chain: String = certs[1..].iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("chain.pem"), &chain)?;
    log::info!("{}/chain.pem written", dir.display());

    let fullchain: String = certs.iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("fullchain.pem"), &fullchain)?;
    log::info!("{}/fullchain.pem written", dir.display());

    Ok(())
}

fn main() {
    logsy::set_echo(true);

    let args: Vec<String> = std::env::args().collect();

    let result = match args.get(1).map(String::as_str) {
        Some("--renew") => cmd_renew::cmd_renew(),
        Some("--install") => cmd_install::cmd_install(),
        Some(arg) => {
            let (host, port) = parse_host_port(arg);
            cmd_fetch::cmd_fetch(host, port)
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
