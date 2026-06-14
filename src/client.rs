use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn run(listen: &str, server_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("SOCKS5 proxy listening on {listen}");

    loop {
        let (mut socks_conn, addr) = listener.accept().await?;
        eprintln!("SOCKS5 connection from {addr}");

        let server_addr = server_addr.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_socks_client(&mut socks_conn, &server_addr).await {
                eprintln!("Error handling {addr}: {e}");
            }
        });
    }
}

async fn handle_socks_client(
    socks_conn: &mut TcpStream,
    server_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    // --- SOCKS5 Handshake ---
    socks_conn.read_exact(&mut buf[..2]).await?;
    let nmethods = buf[1] as usize;
    socks_conn.read_exact(&mut buf[..nmethods]).await?;

    // Respond: no authentication required (0x00)
    socks_conn.write_all(&[0x05, 0x00]).await?;

    // --- SOCKS5 Request ---
    socks_conn.read_exact(&mut buf[..4]).await?;
    let cmd = buf[1];
    if cmd != 0x01 {
        send_socks_reply(socks_conn, 0x07).await?; // Command not supported
        return Err("unsupported SOCKS5 command".into());
    }

    // Parse target address
    let atyp = buf[3];
    let target_addr = read_address(socks_conn, atyp, &mut buf).await?;
    socks_conn.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    let target = (target_addr, port);
    eprintln!("SOCKS5 CONNECT -> {}:{}", target.0, target.1);

    // --- Connect to VPN server ---
    let mut server = TcpStream::connect(server_addr).await?;

    // Send target address to server
    // Format: [atyp][addr...][port:2]
    let addr_bytes = encode_address(&target.0);
    let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
    header.push(atyp);
    header.extend_from_slice(&addr_bytes);
    header.extend_from_slice(&port.to_be_bytes());
    server.write_all(&header).await?;

    // Read server response (1 byte status)
    server.read_exact(&mut buf[..1]).await?;
    let status = buf[0];
    if status != 0x00 {
        let socks_rep = match status {
            0x01 => 0x01, // General failure
            0x02 => 0x02, // Connection not allowed
            0x03 => 0x03, // Network unreachable
            0x04 => 0x04, // Host unreachable
            0x05 => 0x05, // Connection refused
            _ => 0x01,
        };
        send_socks_reply(socks_conn, socks_rep).await?;
        return Err(format!("server rejected: status {status:#04x}").into());
    }

    // Send success reply to SOCKS5 client
    // BND.ADDR and BND.PORT — use zeros (RFC 1928: for CONNECT, these are bound address)
    let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    socks_conn.write_all(&reply).await?;

    // --- Bidirectional relay ---
    let (mut sr, mut sw) = socks_conn.split();
    let (mut cr, mut cw) = server.split();

    let client_to_server = tokio::io::copy(&mut sr, &mut cw);
    let server_to_client = tokio::io::copy(&mut cr, &mut sw);

    tokio::select! {
        r = client_to_server => {
            if let Err(e) = r {
                eprintln!("client->server relay error: {e}");
            }
        }
        r = server_to_client => {
            if let Err(e) = r {
                eprintln!("server->client relay error: {e}");
            }
        }
    }

    Ok(())
}

async fn read_address(
    stream: &mut TcpStream,
    atyp: u8,
    buf: &mut [u8],
) -> Result<String, Box<dyn std::error::Error>> {
    match atyp {
        0x01 => {
            // IPv4
            stream.read_exact(&mut buf[..4]).await?;
            Ok(format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]))
        }
        0x03 => {
            // Domain name
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len]).await?;
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        }
        0x04 => {
            // IPv6
            stream.read_exact(&mut buf[..16]).await?;
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", buf[i * 2], buf[i * 2 + 1]))
                .collect();
            Ok(groups.join(":"))
        }
        _ => Err(format!("unsupported address type: {atyp:#04x}").into()),
    }
}

fn encode_address(addr: &str) -> Vec<u8> {
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        ip.octets().to_vec()
    } else if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        ip.octets().to_vec()
    } else {
        let bytes = addr.as_bytes();
        let mut v = Vec::with_capacity(1 + bytes.len());
        v.push(bytes.len() as u8);
        v.extend_from_slice(bytes);
        v
    }
}

async fn send_socks_reply(
    stream: &mut TcpStream,
    rep: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
