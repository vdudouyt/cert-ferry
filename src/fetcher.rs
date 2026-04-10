use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};

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

pub fn fetch_cert_chain(host: &str, port: u16) -> Result<Vec<Vec<u8>>> {
    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let server_name = ServerName::try_from(host.to_string()).context("invalid server name")?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect((host, port))
        .with_context(|| format!("failed to connect to {}:{}", host, port))?;

    conn.complete_io(&mut sock)?;

    let certs = conn
        .peer_certificates()
        .context("no peer certificates received")?;
    ensure!(!certs.is_empty(), "empty certificate chain");

    Ok(certs.iter().map(|c| c.as_ref().to_vec()).collect())
}

pub fn der_to_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}

/// Check that the leaf certificate covers the given domain (exact or wildcard match).
pub fn verify_cert_matches_domain(der: &[u8], domain: &str) -> Result<()> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("failed to parse certificate: {}", e))?;

    // Collect SANs (DNS names)
    let sans: Vec<&str> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some(*dns),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Fall back to CN if no SANs
    let cn: Option<String> = if sans.is_empty() {
        cert.subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()))
    } else {
        None
    };

    let names: Vec<&str> = if sans.is_empty() {
        cn.as_deref().into_iter().collect()
    } else {
        sans
    };

    let domain_lower = domain.to_lowercase();
    for name in &names {
        let name_lower = name.to_lowercase();
        if name_lower == domain_lower {
            return Ok(());
        }
        // Wildcard: *.example.com matches example.com and sub.example.com
        if let Some(wildcard_base) = name_lower.strip_prefix("*.") {
            if domain_lower == wildcard_base || domain_lower.ends_with(&format!(".{wildcard_base}"))
            {
                return Ok(());
            }
        }
    }

    anyhow::bail!(
        "certificate does not match domain '{}' (cert covers: {})",
        domain,
        names.join(", ")
    );
}
