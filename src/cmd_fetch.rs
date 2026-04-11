use std::path::Path;

use anyhow::Result;
use log::info;

use crate::config::LETSENCRYPT_LIVE;
use crate::fetcher::{
    fetch_cert_chain, verify_cert_matches_domain, verify_cert_matches_private_key,
};
use crate::write_cert_files;

pub fn cmd_fetch(host: &str, port: u16) -> Result<()> {
    info!("connecting to {}:{}", host, port);
    let certs = fetch_cert_chain(host, port)?;
    info!("received {} certificate(s)", certs.len());
    verify_cert_matches_domain(&certs[0], host)?;

    let base = Path::new(LETSENCRYPT_LIVE);
    verify_cert_matches_private_key(&certs[0], &base.join(host).join("privkey.pem"))?;

    write_cert_files(base, host, &certs)
}
