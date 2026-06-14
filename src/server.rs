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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::protocol::{self};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_server_target_unreachable_plain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let result = handle_client(&mut client, None).await;
            assert!(result.is_err());
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        // Отправляем заголовок для недоступной цели (порт 1 — privileged)
        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let port: u16 = 1;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());
        client.write_all(&header).await.unwrap();

        let mut status = [0u8; 1];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], 0x05);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_server_target_unreachable_encrypted() {
        let psk = crypto::generate_psk();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let result = handle_client(&mut client, Some(psk)).await;
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

        let plain = crypto::read_encrypted_frame(&mut client, &sk)
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
            let (mut client, _) = listener.accept().await.unwrap();
            // handle_client в plain-режиме: читает заголовок, подключается к цели,
            // отправляет статус и входит в ретрансляцию.
            handle_client(&mut client, None).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();

        // Заголовок: подключаемся к эхо-серверу
        let (atyp, addr_bytes) = protocol::encode_address("127.0.0.1");
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&header).await.unwrap();

        // Читаем статус
        let mut status = [0u8; 1];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], 0x00);

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
            let (mut client, _) = listener.accept().await.unwrap();
            handle_client(&mut client, Some(psk)).await.unwrap();
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
        let plain = crypto::read_encrypted_frame(&mut client, &sk)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain[0], 0x00);

        // Отправляем зашифрованные данные — ждём эхо
        crypto::write_encrypted_frame(&mut client, b"ping", &ck, &mut c_nonce)
            .await
            .unwrap();
        let echoed = crypto::read_encrypted_frame(&mut client, &sk)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, b"ping");

        // Закрываем клиентскую сторону
        drop(client);
        server.await.unwrap();
    }
}
