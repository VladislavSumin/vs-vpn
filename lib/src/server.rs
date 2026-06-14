use crate::protocol;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use vs_vpn_tunnel::Tunnel;
use vs_vpn_tunnel_tcp_encrypted::{self, EncryptedTunnel, crypto};
use vs_vpn_tunnel_tcp_plain::PlainTunnel;

pub async fn run(
    listen: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
    ready: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    info!("VPN server listening on {listen}");

    // Отправляем наружу реальный адресс сокета, после того как он уже bind.
    // это позволяет использовать динамический порт в тестах, а так же дождаться реально bind.
    if let Some(tx) = ready {
        let _ = tx.send(listener.local_addr()?);
    }

    loop {
        let (client, addr) = listener.accept().await?;
        info!("Client connected: {addr}");

        tokio::spawn(async move {
            if let Err(e) = handle_client(client, secret).await {
                error!("Error handling client {addr}: {e}");
            }
        });
    }
}

async fn handle_client(
    client: TcpStream,
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(psk) = secret {
        let tunnel = EncryptedTunnel::new(client, psk, false).await?;
        run_tunnel_server(tunnel).await
    } else {
        let tunnel = PlainTunnel::new(client);
        run_tunnel_server(tunnel).await
    }
}

/// Общая логика туннельного протокола серверной стороны
/// (статическая диспетчеризация через `T`).
async fn run_tunnel_server<T: Tunnel>(mut tunnel: T) -> Result<(), Box<dyn std::error::Error>> {
    let plain = tunnel.recv_frame().await?;
    let plain = plain.ok_or("client closed connection before tunnel header")?;
    let (_, target_addr, port) = protocol::parse_header(&plain)?;
    let target = format!("{target_addr}:{port}");
    info!("Connecting to {target}");

    let mut remote = match TcpStream::connect(&target).await {
        Ok(conn) => {
            tunnel.send_frame(&[0x00]).await?;
            conn
        }
        Err(e) => {
            error!("Failed to connect to {target}: {e}");
            tunnel.send_frame(&[0x05]).await?;
            return Err(e.into());
        }
    };

    tunnel.relay_bidirectional(&mut remote).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{self};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use vs_vpn_tunnel_tcp_encrypted::crypto;

    #[tokio::test]
    async fn test_server_target_unreachable_plain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let result = handle_client(client, None).await;
            assert!(result.is_err());
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let port: u16 = 1;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());

        let len = header.len() as u16;
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&header).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let status_len = u16::from_be_bytes(len_buf) as usize;
        let mut status_buf = vec![0u8; status_len];
        client.read_exact(&mut status_buf).await.unwrap();
        assert_eq!(status_buf[0], 0x05);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_target_unreachable_encrypted() {
        let psk = crypto::generate_psk();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let result = handle_client(client, Some(psk)).await;
            assert!(result.is_err());
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (ck, sk) = crypto::secure_handshake(&mut client, &psk, true)
            .await
            .unwrap();

        // Отправляем зашифрованный заголовок для недоступной цели
        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let port: u16 = 1;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());

        let mut c_nonce: u64 = 0;
        crypto::write_encrypted_frame(&mut client, &header, &ck, &mut c_nonce)
            .await
            .unwrap();

        let plain = crypto::read_encrypted_frame(&mut client, &sk, &mut 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain[0], 0x05);

        server.await.unwrap();
    }

    /// Запускает эхо-сервер на случайном порту, возвращает порт
    async fn start_echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = conn.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn test_server_plain_relay_to_echo() {
        let echo_port = start_echo_server().await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_client(client, None).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();

        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&echo_port.to_be_bytes());

        let len = header.len() as u16;
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&header).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let status_len = u16::from_be_bytes(len_buf) as usize;
        let mut status_buf = vec![0u8; status_len];
        client.read_exact(&mut status_buf).await.unwrap();
        assert_eq!(status_buf[0], 0x00);

        // Отправляем данные — эхо-сервер должен вернуть их обратно
        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Закрываем клиентскую сторону, чтобы завершить ретрансляцию
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_encrypted_handshake_and_relay() {
        let psk = crypto::generate_psk();
        let echo_port = start_echo_server().await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_client(client, Some(psk)).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (ck, sk) = crypto::secure_handshake(&mut client, &psk, true)
            .await
            .unwrap();

        // Отправляем зашифрованный заголовок
        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&echo_port.to_be_bytes());

        let mut c_nonce: u64 = 0;
        crypto::write_encrypted_frame(&mut client, &header, &ck, &mut c_nonce)
            .await
            .unwrap();

        // Читаем зашифрованный статус
        let mut s_nonce: u64 = 0;
        let plain = crypto::read_encrypted_frame(&mut client, &sk, &mut s_nonce)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain[0], 0x00);

        // Отправляем зашифрованные данные — ждём эхо
        crypto::write_encrypted_frame(&mut client, b"ping", &ck, &mut c_nonce)
            .await
            .unwrap();
        let echoed = crypto::read_encrypted_frame(&mut client, &sk, &mut s_nonce)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, b"ping");

        // Закрываем клиентскую сторону
        drop(client);
        server.await.unwrap();
    }
}
