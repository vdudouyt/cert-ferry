use std::path::Path;

use anyhow::Result;
use log::info;

use crate::config::{DEFAULT_PORT, LETSENCRYPT_LIVE};
use crate::fetcher::{
    fetch_cert_chain, verify_cert_matches_domain, verify_cert_matches_private_key,
};
use crate::write_cert_files;

pub fn cmd_fetch(host: &str) -> Result<()> {
    info!("connecting to {}:{}", host, DEFAULT_PORT);
    let certs = fetch_cert_chain(host, DEFAULT_PORT)?;
    info!("received {} certificate(s)", certs.len());
    verify_cert_matches_domain(&certs[0], host)?;

    let base = Path::new(LETSENCRYPT_LIVE);
    verify_cert_matches_private_key(&certs[0], &base.join(host).join("privkey.pem"))?;

    write_cert_files(base, host, &certs)
}
