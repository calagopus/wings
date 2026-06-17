use compact_str::CompactString;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const FINGERPRINT_ERROR: &str =
    "fingerprint must be a SHA-256 hash (64 hex characters, colons optional)";

pub fn normalize_fingerprint(fingerprint: &str) -> Result<[u8; 32], CompactString> {
    let mut out = [0; 32];
    let mut count = 0;
    let mut high = None;

    for ch in fingerprint.chars() {
        if ch.is_whitespace() || ch == ':' {
            continue;
        }

        let nibble = match ch.to_digit(16) {
            Some(value) => value as u8,
            None => return Err(FINGERPRINT_ERROR.into()),
        };

        match high.take() {
            None => high = Some(nibble),
            Some(hi) => {
                match out.get_mut(count) {
                    Some(slot) => *slot = (hi << 4) | nibble,
                    None => return Err(FINGERPRINT_ERROR.into()),
                }
                count += 1;
            }
        }
    }

    if count != 32 || high.is_some() {
        return Err(FINGERPRINT_ERROR.into());
    }

    Ok(out)
}

pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der);
    let mut out = [0; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn fingerprint_hex(bytes: &[u8]) -> CompactString {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out.into()
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = cert_sha256(end_entity.as_ref());
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "certificate fingerprint mismatch: expected {}, server presented {}",
                fingerprint_hex(&self.expected),
                fingerprint_hex(&actual),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn build_client_config(fingerprint: &str) -> Result<ClientConfig, CompactString> {
    let expected = normalize_fingerprint(fingerprint)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|err| CompactString::from(err.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier { expected, provider }))
        .with_no_client_auth();

    Ok(config)
}
