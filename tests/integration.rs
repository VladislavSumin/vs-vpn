use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vs_vpn::{client, crypto, server};

async fn start_echo() -> u16 {
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

async fn start_vpn_server(
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> (tokio::task::JoinHandle<()>, u16) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        server::run("127.0.0.1:0", secret, Some(tx))
            .await
            .expect("server run failed");
    });
    let addr = rx.await.expect("server failed to bind");
    (handle, addr.port())
}

async fn start_vpn_client(
    server_port: u16,
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> (tokio::task::JoinHandle<()>, u16) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_addr = format!("127.0.0.1:{server_port}");
    let handle = tokio::spawn(async move {
        client::run("127.0.0.1:0", &server_addr, secret, Some(tx))
            .await
            .expect("client run failed");
    });
    let addr = rx.await.expect("client failed to bind");
    (handle, addr.port())
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut socks = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();

    socks.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    socks.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00], "SOCKS5 handshake failed");

    let port_bytes = target_port.to_be_bytes();
    socks
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            port_bytes[0],
            port_bytes[1],
        ])
        .await
        .unwrap();

    let mut reply = [0u8; 10];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05, "SOCKS5 reply VER mismatch");
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT rejected");

    socks
}

async fn socks5_connect_expect_error(proxy_port: u16, target_port: u16) -> u8 {
    let mut socks = TcpStream::connect(format!("127.0.0.1:{proxy_port}"))
        .await
        .unwrap();

    socks.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut buf = [0u8; 2];
    socks.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, [0x05, 0x00]);

    let port_bytes = target_port.to_be_bytes();
    socks
        .write_all(&[
            0x05,
            0x01,
            0x00,
            0x01,
            127,
            0,
            0,
            1,
            port_bytes[0],
            port_bytes[1],
        ])
        .await
        .unwrap();

    let mut reply = [0u8; 10];
    socks.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    reply[1]
}

#[tokio::test]
async fn test_e2e_plain_echo() {
    let echo_port = start_echo().await;
    let (server_h, server_port) = start_vpn_server(None).await;
    let (client_h, client_port) = start_vpn_client(server_port, None).await;

    let mut socks = socks5_connect(client_port, echo_port).await;

    socks.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    socks.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    drop(socks);
    server_h.abort();
    client_h.abort();
}

#[tokio::test]
async fn test_e2e_encrypted_echo() {
    let psk = crypto::generate_psk();
    let echo_port = start_echo().await;
    let (server_h, server_port) = start_vpn_server(Some(psk)).await;
    let (client_h, client_port) = start_vpn_client(server_port, Some(psk)).await;

    let mut socks = socks5_connect(client_port, echo_port).await;

    socks.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    socks.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // Проверяем два сообщения подряд
    socks.write_all(b"pong").await.unwrap();
    let mut buf2 = [0u8; 4];
    socks.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"pong");

    drop(socks);
    server_h.abort();
    client_h.abort();
}

#[tokio::test]
async fn test_e2e_plain_unreachable() {
    let (server_h, server_port) = start_vpn_server(None).await;
    let (client_h, client_port) = start_vpn_client(server_port, None).await;

    let rep = socks5_connect_expect_error(client_port, 1).await;
    assert_ne!(rep, 0x00, "should reject unreachable target");

    server_h.abort();
    client_h.abort();
}

#[tokio::test]
async fn test_e2e_encrypted_unreachable() {
    let psk = crypto::generate_psk();
    let (server_h, server_port) = start_vpn_server(Some(psk)).await;
    let (client_h, client_port) = start_vpn_client(server_port, Some(psk)).await;

    let rep = socks5_connect_expect_error(client_port, 1).await;
    assert_ne!(rep, 0x00, "should reject unreachable target");

    server_h.abort();
    client_h.abort();
}

#[tokio::test]
async fn test_e2e_multiple_requests() {
    let echo_port = start_echo().await;
    let (server_h, server_port) = start_vpn_server(None).await;
    let (client_h, client_port) = start_vpn_client(server_port, None).await;

    for i in 0..3 {
        let mut socks = socks5_connect(client_port, echo_port).await;
        let msg = format!("msg{i}");
        socks.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        socks.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg.as_bytes());
        drop(socks);
        // Небольшая пауза, чтобы сервер успел закрыть предыдущее соединение
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    server_h.abort();
    client_h.abort();
}

#[tokio::test]
async fn test_e2e_concurrent_clients() {
    let echo_port = start_echo().await;
    let (server_h, server_port) = start_vpn_server(None).await;
    let (client_h, client_port) = start_vpn_client(server_port, None).await;

    let mut handles = Vec::new();
    for i in 0..5 {
        let port = client_port;
        let echo = echo_port;
        handles.push(tokio::spawn(async move {
            let mut socks = socks5_connect(port, echo).await;
            let msg = format!("ping{i}");
            socks.write_all(msg.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; msg.len()];
            socks.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, msg.as_bytes());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    server_h.abort();
    client_h.abort();
}
