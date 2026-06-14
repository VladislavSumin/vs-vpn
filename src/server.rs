use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn run(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("VPN server listening on {listen}");

    loop {
        let (mut client, addr) = listener.accept().await?;
        eprintln!("Client connected: {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut client).await {
                eprintln!("Error handling client {addr}: {e}");
            }
        });
    }
}

async fn handle_client(client: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    // Read address type
    client.read_exact(&mut buf[..1]).await?;
    let atyp = buf[0];

    // Read target address
    let target_addr = read_address(client, atyp, &mut buf).await?;

    // Read port
    client.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    let target = format!("{target_addr}:{port}");
    eprintln!("Connecting to {target}");

    // Connect to target
    let mut remote = match TcpStream::connect(&target).await {
        Ok(conn) => {
            client.write_all(&[0x00]).await?; // Success
            conn
        }
        Err(e) => {
            eprintln!("Failed to connect to {target}: {e}");
            client.write_all(&[0x05]).await?; // Connection refused
            return Err(e.into());
        }
    };

    // Bidirectional relay
    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();

    let client_to_remote = tokio::io::copy(&mut cr, &mut rw);
    let remote_to_client = tokio::io::copy(&mut rr, &mut cw);

    tokio::select! {
        r = client_to_remote => {
            if let Err(e) = r {
                eprintln!("client->remote relay error: {e}");
            }
        }
        r = remote_to_client => {
            if let Err(e) = r {
                eprintln!("remote->client relay error: {e}");
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
            stream.read_exact(&mut buf[..4]).await?;
            Ok(format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]))
        }
        0x03 => {
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len]).await?;
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        }
        0x04 => {
            stream.read_exact(&mut buf[..16]).await?;
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", buf[i * 2], buf[i * 2 + 1]))
                .collect();
            Ok(groups.join(":"))
        }
        _ => Err(format!("unsupported address type: {atyp:#04x}").into()),
    }
}
