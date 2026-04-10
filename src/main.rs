mod cmd_fetch;
mod cmd_install;
mod cmd_renew;
mod config;
mod fetcher;

use std::path::Path;
use std::process;

use anyhow::{ensure, Result};
use log::{error, info};

use config::{DEFAULT_PORT, LETSENCRYPT_LIVE};
use fetcher::der_to_pem;

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
    info!("{}/cert.pem written", dir.display());

    let chain: String = certs[1..].iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("chain.pem"), &chain)?;
    info!("{}/chain.pem written", dir.display());

    let fullchain: String = certs.iter().map(|c| der_to_pem(c)).collect();
    std::fs::write(dir.join("fullchain.pem"), &fullchain)?;
    info!("{}/fullchain.pem written", dir.display());

    Ok(())
}

fn main() {
    logsy::set_echo(true);

    let args: Vec<String> = std::env::args().collect();

    let force = args.iter().any(|a| a == "--force");

    let result = match args.get(1).map(String::as_str) {
        Some("--renew") => cmd_renew::cmd_renew(force),
        Some("--install") => cmd_install::cmd_install(),
        Some(arg) if arg != "--force" => {
            let (host, port) = parse_host_port(arg);
            cmd_fetch::cmd_fetch(host, port)
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  certferry <domain>        Fetch certificate from remote host");
            eprintln!("  certferry --renew         Renew expiring local certificates");
            eprintln!("  certferry --renew --force  Renew all certificates unconditionally");
            eprintln!("  certferry --install       Install systemd timer for periodic renewal");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        error!("{:#}", e);
        process::exit(1);
    }
}
