use crate::protocol;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{Instrument, Span, error, info, info_span, instrument};
use vs_vpn_tunnel::{Tunnel, TunnelAcceptor};
use vs_vpn_tunnel_tcp_encrypted::{self, EncryptedAcceptor, crypto};
use vs_vpn_tunnel_tcp_plain::PlainAcceptor;

#[instrument(skip(secret, ready), fields(listen = %listen, encrypted))]
pub async fn run(
    listen: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> Result<(), Box<dyn std::error::Error>> {
    Span::current().record("encrypted", secret.is_some());
    info!("VPN server started");

    match secret {
        Some(psk) => {
            let acceptor = EncryptedAcceptor::bind(listen, psk).await?;
            if let Some(tx) = ready {
                let _ = tx.send(acceptor.local_addr()?);
            }
            run_with(acceptor).await
        }
        None => {
            let acceptor = PlainAcceptor::bind(listen).await?;
            if let Some(tx) = ready {
                let _ = tx.send(acceptor.local_addr()?);
            }
            run_with(acceptor).await
        }
    }
}

/// Запуск сервера с произвольным акцептором (QUIC, etc.).
/// Публичная для использования с `--transport quic`.
pub async fn run_acceptor<A: TunnelAcceptor>(
    acceptor: A,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with(acceptor).await
}

async fn run_with<A: TunnelAcceptor>(acceptor: A) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (tunnel, client_addr) = acceptor.accept().await?;
        let connection_span = info_span!(parent: Span::current(), "connection", %client_addr);

        tokio::spawn(
            async move {
                if let Err(e) = run_tunnel_server(tunnel).await {
                    error!(%e, "Client connection failed");
                }
            }
            .instrument(connection_span),
        );
    }
}

/// Общая логика туннельного протокола серверной стороны
/// (статическая диспетчеризация через `T`).
#[instrument(skip(tunnel), fields(target))]
async fn run_tunnel_server<T: Tunnel>(mut tunnel: T) -> Result<(), Box<dyn std::error::Error>> {
    let plain = tunnel.recv_frame().await?;
    let plain = plain.ok_or("client closed connection before tunnel header")?;
    let (_, target_addr, port) = protocol::parse_header(&plain)?;
    let target = format!("{target_addr}:{port}");
    Span::current().record("target", &target);
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
        let acceptor = PlainAcceptor::bind("127.0.0.1:0").await.unwrap();
        let server_addr = acceptor.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tunnel, _) = acceptor.accept().await.unwrap();
            let result = run_tunnel_server(tunnel).await;
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
        let acceptor = EncryptedAcceptor::bind("127.0.0.1:0", psk).await.unwrap();
        let server_addr = acceptor.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tunnel, _) = acceptor.accept().await.unwrap();
            let result = run_tunnel_server(tunnel).await;
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

        let acceptor = PlainAcceptor::bind("127.0.0.1:0").await.unwrap();
        let server_addr = acceptor.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tunnel, _) = acceptor.accept().await.unwrap();
            run_tunnel_server(tunnel).await.unwrap();
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

        let acceptor = EncryptedAcceptor::bind("127.0.0.1:0", psk).await.unwrap();
        let server_addr = acceptor.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tunnel, _) = acceptor.accept().await.unwrap();
            run_tunnel_server(tunnel).await.unwrap();
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
