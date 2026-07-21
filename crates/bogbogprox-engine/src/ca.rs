//! Certificate-authority generation for TLS interception (§28).
//!
//! Each install gets a **unique** CA — we never ship a shared one.

use anyhow::Result;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

/// A generated CA in PEM form.
pub struct GeneratedCa {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a fresh self-signed CA suitable for on-the-fly leaf issuance.
pub fn generate_ca() -> Result<GeneratedCa> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "BogBogProx Proxy CA");
    dn.push(DnType::OrganizationName, "BogBogProx");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}
