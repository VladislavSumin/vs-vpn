use clap::{Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;
use tracing::info;
use vs_vpn::{client, crypto, server};
use vs_vpn_tunnel_quic::{QuicAcceptor, QuicConnector, cert};

#[derive(Parser)]
#[command(name = "vs-vpn", about = "Custom VPN with SOCKS5 proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, ValueEnum)]
enum Transport {
    /// TCP-туннель (по умолчанию)
    Tcp,
    /// QUIC-туннель (UDP)
    Quic,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Run the VPN client (SOCKS5 proxy)")]
    Client {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        #[arg(long)]
        server: String,
        #[arg(
            long,
            help = "PSK hex-ключ для шифрования туннеля (64 hex-символа = 32 байта)"
        )]
        secret: Option<String>,
        #[arg(long, default_value = "tcp")]
        transport: Transport,
        /// Принимать любой сертификат сервера (только для разработки)
        #[arg(long)]
        quic_insecure: bool,
        /// SHA-256 fingerprint сертификата сервера (64 hex-символа)
        #[arg(long)]
        quic_fingerprint: Option<String>,
    },
    #[command(about = "Run the VPN server")]
    Server {
        #[arg(long, default_value = "0.0.0.0:9090")]
        listen: String,
        #[arg(
            long,
            help = "PSK hex-ключ для шифрования туннеля (64 hex-символа = 32 байта)"
        )]
        secret: Option<String>,
        #[arg(long, default_value = "tcp")]
        transport: Transport,
        /// UDP-адрес для QUIC (напр. 0.0.0.0:9091)
        #[arg(long)]
        quic_listen: Option<String>,
        /// Путь к PEM-файлу сертификата
        #[arg(long)]
        quic_cert: Option<String>,
        /// Путь к PEM-файлу закрытого ключа
        #[arg(long)]
        quic_key: Option<String>,
    },
    #[command(about = "Generate a random PSK key (hex string)")]
    Keygen,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    init_rustls();
    info!("Starting vs-vpn");

    let cli = Cli::parse();

    match cli.command {
        Command::Client {
            listen,
            server,
            secret,
            transport,
            quic_insecure,
            quic_fingerprint,
        } => match transport {
            Transport::Tcp => {
                let key = secret.as_deref().map(parse_secret).transpose()?;
                client::run(&listen, &server, key, None, CancellationToken::new()).await?;
            }
            Transport::Quic => {
                let tls = build_quic_client_tls(quic_insecure, quic_fingerprint.as_deref())?;
                let connector = QuicConnector::new(server, tls);
                client::run_connector(&listen, connector, None, CancellationToken::new()).await?;
            }
        },
        Command::Server {
            listen,
            secret,
            transport,
            quic_listen,
            quic_cert,
            quic_key,
        } => match transport {
            Transport::Tcp => {
                let key = secret.as_deref().map(parse_secret).transpose()?;
                server::run(&listen, key, None).await?;
            }
            Transport::Quic => {
                let listen_addr = quic_listen.unwrap_or_else(|| "0.0.0.0:9091".to_string());
                let (cert_der, key_der) = match (quic_cert.as_deref(), quic_key.as_deref()) {
                    (Some(cert_path), Some(key_path)) => {
                        cert::load_cert_and_key(cert_path, key_path)?
                    }
                    _ => {
                        let (c, k) = cert::generate_self_signed()?;
                        info!(
                            "Generated self-signed certificate, fingerprint: {}",
                            cert::fingerprint(&c)
                        );
                        (c, k)
                    }
                };
                let acceptor = QuicAcceptor::bind(&listen_addr, cert_der, key_der).await?;
                info!("QUIC server listening on {listen_addr}");
                server::run_acceptor(acceptor).await?;
            }
        },
        Command::Keygen => {
            let psk = crypto::generate_psk();
            println!("{}", hex::encode(psk));
        }
    }

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .init();
}

fn init_rustls() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring crypto provider");
}

fn parse_secret(s: &str) -> Result<[u8; crypto::KEY_LEN], Box<dyn std::error::Error>> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex key: {e}"))?;
    if bytes.len() != crypto::KEY_LEN {
        return Err(format!(
            "key must be {} hex chars ({} bytes), got {} bytes",
            crypto::KEY_LEN * 2,
            crypto::KEY_LEN,
            bytes.len()
        )
        .into());
    }
    let mut key = [0u8; crypto::KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn build_quic_client_tls(
    insecure: bool,
    fingerprint: Option<&str>,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    if insecure {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(SkipCertVerification))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"vs-vpn".to_vec()];
        return Ok(config);
    }
    if let Some(_fp) = fingerprint {
        return Err(
            "fingerprint verification not yet implemented; use --quic-insecure for testing".into(),
        );
    }
    Err(
        "QUIC requires --quic-insecure or --quic-fingerprint for server certificate verification"
            .into(),
    )
}

/// Пропускает любую проверку сертификата (только для разработки).
#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
