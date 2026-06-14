use crate::protocol::{self, AddressType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    info!("VPN server listening on {listen}");

    loop {
        let (mut client, addr) = listener.accept().await?;
        info!("Client connected: {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut client).await {
                error!("Error handling client {addr}: {e}");
            }
        });
    }
}

async fn handle_client(client: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    client.read_exact(&mut buf[..1]).await?;
    let atyp = AddressType::from_u8(buf[0])
        .ok_or_else(|| format!("unsupported address type: {:#04x}", buf[0]))?;

    let target_addr = protocol::read_address(client, atyp, &mut buf).await?;

    client.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    let target = format!("{target_addr}:{port}");
    info!("Connecting to {target}");

    let mut remote = match TcpStream::connect(&target).await {
        Ok(conn) => {
            client.write_all(&[0x00]).await?;
            conn
        }
        Err(e) => {
            error!("Failed to connect to {target}: {e}");
            client.write_all(&[0x05]).await?;
            return Err(e.into());
        }
    };

    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();

    let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
    let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

    tokio::select! {
        r = client_to_remote => {
            if let Err(e) = r { error!("client->remote relay error: {e}"); }
        }
        r = remote_to_client => {
            if let Err(e) = r { error!("remote->client relay error: {e}"); }
        }
    }

    Ok(())
}
