use std::path::Path;

use anyhow::Result;
use log::info;

use crate::config::LETSENCRYPT_LIVE;
use crate::fetcher::fetch_cert_chain;
use crate::write_cert_files;

pub fn cmd_fetch(host: &str, port: u16) -> Result<()> {
    info!("connecting to {}:{}", host, port);
    let certs = fetch_cert_chain(host, port)?;
    info!("received {} certificate(s)", certs.len());
    write_cert_files(Path::new(LETSENCRYPT_LIVE), host, &certs)
}
