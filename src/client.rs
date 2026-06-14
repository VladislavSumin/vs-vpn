use crate::protocol::{self, AddressType, SOCKS_VERSION, SocksCommand, SocksReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

pub async fn run(listen: &str, server_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    info!("SOCKS5 proxy listening on {listen}");

    loop {
        let (mut socks_conn, addr) = listener.accept().await?;
        info!("SOCKS5 connection from {addr}");

        let server_addr = server_addr.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_client(&mut socks_conn, &server_addr).await {
                error!("Error handling {addr}: {e}");
            }
        });
    }
}

async fn handle_socks_client(
    socks_conn: &mut TcpStream,
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    // SOCKS5 Handshake
    socks_conn.read_exact(&mut buf[..2]).await?;
    let nmethods = buf[1] as usize;
    socks_conn.read_exact(&mut buf[..nmethods]).await?;

    socks_conn.write_all(&[SOCKS_VERSION, 0x00]).await?;

    // SOCKS5 Request
    socks_conn.read_exact(&mut buf[..4]).await?;
    let cmd = SocksCommand::from_u8(buf[1]);
    if cmd != Some(SocksCommand::Connect) {
        send_socks_reply(socks_conn, SocksReply::CommandNotSupported).await?;
        return Err("unsupported SOCKS5 command".into());
    }

    let atyp = AddressType::from_u8(buf[3])
        .ok_or_else(|| format!("unsupported address type: {:#04x}", buf[3]))?;
    let target_addr = protocol::read_address(socks_conn, atyp, &mut buf).await?;
    socks_conn.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    info!("SOCKS5 CONNECT -> {target_addr}:{port}");

    // Connect to VPN server
    let mut server = TcpStream::connect(server_addr).await?;

    // Send target address to server: [atyp][addr...][port:2]
    let (header_atyp, addr_bytes) = protocol::encode_address(&target_addr);
    let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
    header.push(header_atyp as u8);
    header.extend_from_slice(&addr_bytes);
    header.extend_from_slice(&port.to_be_bytes());
    server.write_all(&header).await?;

    // Read server response
    server.read_exact(&mut buf[..1]).await?;
    let status = buf[0];
    if status != 0x00 {
        let socks_rep = match status {
            0x01 => SocksReply::GeneralFailure,
            0x02 => SocksReply::ConnectionNotAllowed,
            0x03 => SocksReply::NetworkUnreachable,
            0x04 => SocksReply::HostUnreachable,
            0x05 => SocksReply::ConnectionRefused,
            _ => SocksReply::GeneralFailure,
        };
        send_socks_reply(socks_conn, socks_rep).await?;
        return Err(format!("server rejected: status {status:#04x}").into());
    }

    send_socks_reply(socks_conn, SocksReply::Succeeded).await?;

    // Bidirectional relay
    let (mut sr, mut sw) = socks_conn.split();
    let (mut cr, mut cw) = server.split();

    let client_to_server = tokio::io::copy(&mut sr, &mut cw);
    let server_to_client = tokio::io::copy(&mut cr, &mut sw);

    tokio::select! {
        r = client_to_server => {
            if let Err(e) = r { error!("client->server relay error: {e}"); }
        }
        r = server_to_client => {
            if let Err(e) = r { error!("server->client relay error: {e}"); }
        }
    }

    Ok(())
}

async fn send_socks_reply(
    stream: &mut TcpStream,
    rep: SocksReply,
) -> Result<(), Box<dyn std::error::Error>> {
    stream
        .write_all(&[
            SOCKS_VERSION,
            rep as u8,
            0x00,
            AddressType::Ipv4 as u8,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
        .await?;
    Ok(())
}
