use crate::crypto;
use crate::protocol::{self, AddressType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run(
    listen: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    info!("VPN server listening on {listen}");

    loop {
        let (mut client, addr) = listener.accept().await?;
        info!("Client connected: {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut client, secret).await {
                error!("Error handling client {addr}: {e}");
            }
        });
    }
}

async fn handle_client(
    client: &mut TcpStream,
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    if let Some(ref psk) = secret {
        let (client_key, server_key) = crypto::secure_handshake(client, psk, false).await?;

        let plain = crypto::read_encrypted_frame(client, &client_key).await?;
        let plain = plain.ok_or("client closed connection before tunnel header")?;
        let (_, target_addr, port) = protocol::parse_header(&plain)?;
        let target = format!("{target_addr}:{port}");
        info!("Secure tunnel -> {target}");

        let mut remote = match TcpStream::connect(&target).await {
            Ok(conn) => {
                let mut s_nonce: u64 = 0;
                crypto::write_encrypted_frame(client, &[0x00], &server_key, &mut s_nonce).await?;
                conn
            }
            Err(e) => {
                error!("Failed to connect to {target}: {e}");
                let mut s_nonce: u64 = 0;
                crypto::write_encrypted_frame(client, &[0x05], &server_key, &mut s_nonce).await?;
                return Err(e.into());
            }
        };

        let (mut cr, mut cw) = client.split();
        let (mut rr, mut rw) = remote.split();

        let client_to_remote = async {
            loop {
                let frame = crypto::read_encrypted_frame(&mut cr, &client_key).await?;
                match frame {
                    Some(plain) => rw.write_all(&plain).await?,
                    None => break Ok::<_, std::io::Error>(()),
                }
            }
        };

        let remote_to_client = async {
            let mut buf = vec![0u8; crypto::RELAY_BUF];
            let mut s_nonce = 1u64;
            loop {
                let n = rr.read(&mut buf).await?;
                if n == 0 {
                    break Ok::<_, std::io::Error>(());
                }
                crypto::write_encrypted_frame(&mut cw, &buf[..n], &server_key, &mut s_nonce)
                    .await?;
            }
        };

        tokio::pin!(client_to_remote);
        tokio::pin!(remote_to_client);

        tokio::select! {
            r = &mut client_to_remote => {
                if let Err(e) = r { error!("client->remote relay error: {e}"); }
            }
            r = &mut remote_to_client => {
                if let Err(e) = r { error!("remote->client relay error: {e}"); }
            }
        }
    } else {
        // ─── Plain-режим (без шифрования) ─────────────────────────────────
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
    }

    Ok(())
}
