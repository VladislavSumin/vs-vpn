use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::info;
use vs_vpn::{client, crypto, server};

#[derive(Parser)]
#[command(name = "vs-vpn", about = "Custom VPN with SOCKS5 proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    },
    #[command(about = "Generate a random PSK key (hex string)")]
    Keygen,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    info!("Starting vs-vpn");

    let cli = Cli::parse();

    match cli.command {
        Command::Client {
            listen,
            server,
            secret,
        } => {
            let key = secret.as_deref().map(parse_secret).transpose()?;
            client::run(&listen, &server, key, None, CancellationToken::new()).await?;
        }
        Command::Server { listen, secret } => {
            let key = secret.as_deref().map(parse_secret).transpose()?;
            server::run(&listen, key, None).await?;
        }
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
