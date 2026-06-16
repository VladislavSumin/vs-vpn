use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::io;
use std::net::IpAddr;

/// Генерирует self-signed сертификат и закрытый ключ.
pub fn generate_self_signed() -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "vs-vpn");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().map_err(io_err)?),
        SanType::IpAddress(IpAddr::from(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let key = KeyPair::generate().map_err(|e| io_err(&e))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| io_err(format!("cert generation failed: {e}")))?;

    Ok((cert.into(), PrivateKeyDer::from(key)))
}

/// SHA-256 fingerprint сертификата в hex.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    hex::encode(hasher.finalize())
}

/// Загружает сертификат и ключ из PEM-файлов.
pub fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| io_err(&e))?;
    let key_pem = std::fs::read(key_path).map_err(|e| io_err(&e))?;

    let mut cert_reader = std::io::BufReader::new(&cert_pem[..]);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| io_err(&e))?;
    let cert = certs
        .into_iter()
        .next()
        .ok_or_else(|| io_err("no certificate found in PEM file"))?;

    let mut key_reader = std::io::BufReader::new(&key_pem[..]);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| io_err(&e))?
        .ok_or_else(|| io_err("no private key found in PEM file"))?;

    Ok((cert, key))
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
