mod client;
mod protocol;
mod server;

use clap::{Parser, Subcommand};
use tracing::info;

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
    },
    #[command(about = "Run the VPN server")]
    Server {
        #[arg(long, default_value = "0.0.0.0:9090")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("trace")),
        )
        .init();
    info!("Starting vs-vpn");

    let cli = Cli::parse();

    match cli.command {
        Command::Client { listen, server } => client::run(&listen, &server).await?,
        Command::Server { listen } => server::run(&listen).await?,
    }

    Ok(())
}
