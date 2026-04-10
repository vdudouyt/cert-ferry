use std::net::TcpStream;
use std::sync::Arc;

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

pub fn fetch_cert_chain(host: &str, port: u16) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
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

pub fn der_to_pem(der: &[u8]) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der))
}
