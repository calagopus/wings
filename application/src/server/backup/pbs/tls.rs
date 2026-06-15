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

/// Normalizes a SHA-256 TLS fingerprint into its 32 raw bytes.
///
/// Accepts the fingerprint with or without colon separators and in any case,
/// e.g. `AB:CD:...` or `abcd...`. Returns an error if it is not exactly 64 hex
/// characters.
pub fn normalize_fingerprint(fingerprint: &str) -> Result<[u8; 32], CompactString> {
    let mut out = [0u8; 32];
    let mut count = 0usize;
    let mut high: Option<u8> = None;

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

/// SHA-256 digest of a certificate's DER encoding, the value PBS pins on.
pub fn cert_sha256(der: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(der);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Lowercase, colon-less hex rendering of raw fingerprint bytes (for messages).
pub fn fingerprint_hex(bytes: &[u8]) -> CompactString {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out.into()
}

/// A rustls certificate verifier that pins the server's end-entity certificate
/// to a specific SHA-256 fingerprint.
///
/// PBS instances commonly use self-signed certificates, so chain/hostname
/// validation is intentionally replaced by exact fingerprint matching. Crucially
/// this does **not** disable TLS: handshake signature verification is delegated
/// to the configured crypto provider, so a forged handshake is still rejected.
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

/// Builds a rustls [`ClientConfig`] that pins the PBS certificate to the given
/// SHA-256 fingerprint.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_colons_and_any_case() {
        let plain = "ab".repeat(32);
        let upper = "AB".repeat(32);
        let colons = std::iter::repeat_n("ab", 32).collect::<Vec<_>>().join(":");

        let a = normalize_fingerprint(&plain).expect("plain hex is valid");
        let b = normalize_fingerprint(&upper).expect("upper hex is valid");
        let c = normalize_fingerprint(&colons).expect("colon hex is valid");

        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, [0xabu8; 32]);
    }

    #[test]
    fn normalize_rejects_bad_input() {
        assert!(normalize_fingerprint("abcd").is_err()); // too short
        assert!(normalize_fingerprint(&"zz".repeat(32)).is_err()); // non-hex
        assert!(normalize_fingerprint(&"ab".repeat(33)).is_err()); // too long
    }

    #[test]
    fn pinning_detects_mismatch() {
        // A pinned fingerprint matches only the exact certificate bytes.
        let cert_a = b"-----fake der cert A-----";
        let cert_b = b"-----fake der cert B-----";

        let expected = cert_sha256(cert_a);
        assert_eq!(
            cert_sha256(cert_a),
            expected,
            "same cert must match the pin"
        );
        assert_ne!(
            cert_sha256(cert_b),
            expected,
            "a different cert must fail the pin"
        );
    }
}
