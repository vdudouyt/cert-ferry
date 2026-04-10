use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{self, Command};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};

const LETSENCRYPT_LIVE: &str = "/etc/letsencrypt/live";
const RENEW_THRESHOLD_DAYS: i64 = 29;
const DEFAULT_PORT: u16 = 443;

// Accept any certificate — we only want the public cert chain, not authentication.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

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

fn fetch_cert_chain(host: &str, port: u16) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| "invalid server name")?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect((host, port))?;

    conn.complete_io(&mut sock)?;

    let certs = conn
        .peer_certificates()
        .ok_or("no peer certificates received")?
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();

    Ok(certs)
}

fn der_to_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}

fn write_cert_files(domain: &str, certs: &[Vec<u8>]) -> Result<(), Box<dyn std::error::Error>> {
    if certs.is_empty() {
        return Err("no certificates received".into());
    }

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

fn cert_not_after(path: &Path) -> Result<i64, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let p = pem::parse(&data)?;
    let (_, cert) = x509_parser::parse_x509_certificate(p.contents())?;
    Ok(cert.validity().not_after.timestamp())
}

fn cmd_fetch(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    info!("connecting to {}:{}", host, port);
    let certs = fetch_cert_chain(host, port)?;
    info!("received {} certificate(s)", certs.len());
    write_cert_files(host, &certs)
}

fn cmd_renew() -> Result<(), Box<dyn std::error::Error>> {
    let live = Path::new(LETSENCRYPT_LIVE);
    if !live.exists() {
        return Err(format!("{LETSENCRYPT_LIVE} does not exist").into());
    }

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

        match cert_not_after(&cert_path) {
            Ok(not_after) if not_after < threshold => {
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
            Ok(not_after) => {
                let days = (not_after - now) / 86400;
                info!("{}: {} days remaining, skipping", domain, days);
                skipped += 1;
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

fn cmd_install() -> Result<(), Box<dyn std::error::Error>> {
    let exe = env::current_exe()?;

    let service = format!(
        "\
[Unit]
Description=cert-ferry certificate renewal

[Service]
Type=oneshot
ExecStart={} --renew
",
        exe.display()
    );

    let timer = "\
[Unit]
Description=cert-ferry renewal timer

[Timer]
OnCalendar=*-*-* 00/12:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
";

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
        error!("{}", e);
        process::exit(1);
    }
}
