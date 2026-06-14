mod client;
mod server;

use clap::{Parser, Subcommand};

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
    let cli = Cli::parse();

    match cli.command {
        Command::Client { listen, server } => client::run(&listen, &server).await?,
        Command::Server { listen } => server::run(&listen).await?,
    }

    Ok(())
}
