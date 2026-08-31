use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SanType, SerialNumber, string::Ia5String,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};
use tundra_common::hash::{Hash32, sha256};

const CA_VALIDITY_DAYS: i64 = 3650;
const NODE_CERT_VALIDITY_DAYS: i64 = 90;

#[inline]
fn node_dns_name(node: &uuid::Uuid) -> String {
    format!("n{}.nodes.calagopus.internal", node.simple())
}

pub struct LocalCa {
    cert_pem: String,
    key: KeyPair,
}

pub struct SignedCert {
    pub pem: String,
    pub sha256: Hash32,
}

impl LocalCa {
    pub fn load_or_create(dir: &Path) -> Result<Self, anyhow::Error> {
        std::fs::create_dir_all(dir).context(format!("failed to create {}", dir.display()))?;

        let key_path = dir.join("ca.key.pem");
        let cert_path = dir.join("ca.crt.pem");

        if key_path.exists() && cert_path.exists() {
            let key = KeyPair::from_pkcs8_pem_and_sign_algo(
                &std::fs::read_to_string(&key_path)?,
                &PKCS_ECDSA_P256_SHA256,
            )
            .context("failed to load the tundra ca key")?;

            return Ok(Self {
                cert_pem: std::fs::read_to_string(&cert_path)?,
                key,
            });
        }

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "calagopus wings tundra ca");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(CA_VALIDITY_DAYS);

        let cert = params.self_signed(&key)?;
        super::write_private(&key_path, key.serialize_pem().as_bytes())?;
        std::fs::write(&cert_path, cert.pem())?;

        Ok(Self {
            cert_pem: cert.pem(),
            key,
        })
    }

    #[inline]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn sign_csr(&self, csr_pem: &str, node: &uuid::Uuid) -> Result<SignedCert, anyhow::Error> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("failed to parse the certificate signing request")?;

        if csr.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(anyhow::anyhow!("node keys must be ECDSA P-256"));
        }

        let dns = node_dns_name(node);
        let now = OffsetDateTime::now_utc();
        csr.params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from(dns.clone())?)];
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params.distinguished_name.push(DnType::CommonName, dns);
        csr.params.not_before = now - Duration::hours(1);
        csr.params.not_after = now + Duration::days(NODE_CERT_VALIDITY_DAYS);
        csr.params.is_ca = IsCa::ExplicitNoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        csr.params.serial_number = Some(SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
        csr.params.use_authority_key_identifier_extension = true;

        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, &self.key)
            .context("failed to load the signing ca")?;
        let cert = csr.signed_by(&issuer)?;

        Ok(SignedCert {
            sha256: sha256(cert.der()),
            pem: cert.pem(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_is_generated_once_and_reloaded_verbatim() {
        let dir = tempfile::tempdir().unwrap();

        let a = LocalCa::load_or_create(dir.path()).unwrap();
        let b = LocalCa::load_or_create(dir.path()).unwrap();

        assert_eq!(a.cert_pem(), b.cert_pem());
    }

    #[test]
    fn a_signed_csr_carries_the_uuid_the_shim_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_create(dir.path()).unwrap();

        let node = uuid::Uuid::new_v4();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "whatever the node claims");
        let csr = params.serialize_request(&key).unwrap();

        let signed = ca.sign_csr(&csr.pem().unwrap(), &node).unwrap();
        assert!(signed.pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(signed.sha256 != Hash32([0; 32]));

        assert!(ca.sign_csr("not a csr", &node).is_err());
    }
}
