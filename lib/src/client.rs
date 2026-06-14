use crate::protocol::{self, AddressType, SOCKS_VERSION, SocksCommand, SocksReply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use vs_vpn_tunnel::Tunnel;
use vs_vpn_tunnel_tcp_encrypted::{self, EncryptedTunnel, crypto};
use vs_vpn_tunnel_tcp_plain::PlainTunnel;

pub async fn run(
    listen: &str,
    server_addr: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
    ready: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(listen).await?;
    info!("SOCKS5 proxy listening on {listen}");

    if let Some(tx) = ready {
        let _ = tx.send(listener.local_addr()?);
    }

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("SOCKS5 proxy shutting down");
                break;
            }
            result = listener.accept() => {
                let (mut socks_conn, addr) = result?;
                info!("SOCKS5 connection from {addr}");

                let server_addr = server_addr.to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks_client(&mut socks_conn, &server_addr, secret).await {
                        error!("Error handling {addr}: {e}");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn handle_socks_client(
    socks_conn: &mut TcpStream,
    server_addr: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 512];

    // ── SOCKS5 Handshake (RFC 1928, раздел 3) ────────────────────────────
    // Клиент отправляет:
    //   ┌────────┬──────────┬─────────────────┐
    //   │ VER (1)│ NMETHODS │ METHODS (1..255)│
    //   │  0x05  │  1 байт  │  NMETHODS байт  │
    //   └────────┴──────────┴─────────────────┘
    // VER — версия протокола (0x05 = SOCKS5).
    // NMETHODS — количество перечисленных методов аутентификации.
    // METHODS — список кодов методов (0x00 = без аутентификации,
    //   0x02 = логин/пароль, 0xFF = нет приемлемых методов).

    // Читаем первые 2 байта: VER + NMETHODS.
    socks_conn.read_exact(&mut buf[..2]).await?;
    let nmethods = buf[1] as usize;
    // Читаем список METHODS (по одному байту на каждый метод).
    socks_conn.read_exact(&mut buf[..nmethods]).await?;

    // Ответ сервера на handshake (выбор метода):
    //   ┌────────┬────────┐
    //   │ VER (1)│ METHOD │
    //   │  0x05  │ 1 байт │
    //   └────────┴────────┘
    // METHOD — выбранный метод. Всегда выбираем 0x00 (без аутентификации),
    //   так как наш VPN-туннель сам по себе является защищённым каналом.
    socks_conn.write_all(&[SOCKS_VERSION, 0x00]).await?;

    // ── SOCKS5 Request (RFC 1928, раздел 4) ──────────────────────────────
    // Клиент отправляет запрос на установку соединения:
    //   ┌────────┬────────┬──────┬──────┬───────────────┬────────┐
    //   │ VER (1)│ CMD (1)│ RSV  │ ATYP │ DST.ADDR (var)│ DST.PORT│
    //   │  0x05  │ команда│ 0x00 │ тип  │   адрес цели   │  2 байта│
    //   └────────┴────────┴──────┴──────┴───────────────┴────────┘
    // CMD — команда: 0x01 = CONNECT (TCP), 0x02 = BIND, 0x03 = UDP ASSOCIATE.
    // RSV — зарезервированный байт, должен быть 0x00.
    // ATYP — тип адреса: 0x01 = IPv4 (4 байта), 0x03 = домен (1 байт длина + N
    //   байт имени), 0x04 = IPv6 (16 байт).
    // DST.ADDR — адрес цели (формат зависит от ATYP).
    // DST.PORT — порт цели в сетевом порядке байт (big-endian, 2 байта).

    // Читаем первые 4 байта: VER + CMD + RSV + ATYP.
    socks_conn.read_exact(&mut buf[..4]).await?;
    let cmd = SocksCommand::from_u8(buf[1]);
    if cmd != Some(SocksCommand::Connect) {
        // Поддерживаем только TCP CONNECT; для остальных — ошибка.
        send_socks_reply(socks_conn, SocksReply::CommandNotSupported).await?;
        return Err("unsupported SOCKS5 command".into());
    }

    // ATYP — байт buf[3], тип адреса цели.
    let atyp = AddressType::from_u8(buf[3])
        .ok_or_else(|| format!("unsupported address type: {:#04x}", buf[3]))?;
    // Читаем сам адрес цели в зависимости от ATYP (IPv4, IPv6 или домен).
    let target_addr = protocol::read_address(socks_conn, atyp, &mut buf).await?;
    // После адреса читаем 2-байтовый порт назначения (big-endian).
    socks_conn.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    info!("SOCKS5 CONNECT -> {target_addr}:{port}");

    // ── Построение туннельного заголовка ─────────────────────────────────
    let (header_atyp, addr_bytes) = protocol::encode_address(&target_addr);
    let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
    header.push(header_atyp as u8);
    header.extend_from_slice(&addr_bytes);
    header.extend_from_slice(&port.to_be_bytes());

    // ── Подключение к VPN-серверу и туннельный протокол ─────────────────
    let server = TcpStream::connect(server_addr).await?;

    if let Some(psk) = secret {
        let tunnel = EncryptedTunnel::new(server, psk, true).await?;
        run_tunnel_client(socks_conn, tunnel, &header).await
    } else {
        let tunnel = PlainTunnel::new(server);
        run_tunnel_client(socks_conn, tunnel, &header).await
    }
}

/// Общая логика туннельного протокола (статическая диспетчеризация через `T`).
async fn run_tunnel_client<T: Tunnel>(
    socks_conn: &mut TcpStream,
    mut tunnel: T,
    header: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    tunnel.send_frame(header).await?;
    let plain = tunnel.recv_frame().await?;
    let status = match plain {
        Some(ref p) if !p.is_empty() => p[0],
        _ => return Err("server closed connection before status".into()),
    };

    if status != 0x00 {
        // Маппим код ошибки туннельного протокола на код SOCKS5-ответа
        // и отправляем его клиенту.
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

    // ── SOCKS5 Reply (RFC 1928, раздел 6) ────────────────────────────────
    // Ответ сервера SOCKS5 клиенту при успешном соединении:
    //   ┌────────┬────────┬──────┬──────┬────────────────┬────────┐
    //   │ VER (1)│ REP (1)│ RSV  │ ATYP │ BND.ADDR (var) │ BND.PORT│
    //   │  0x05  │  0x00  │ 0x00 │ тип  │ адрес привязки │ 2 байта │
    //   └────────┴────────┴──────┴──────┴────────────────┴────────┘
    // REP — код ответа, 0x00 = успех (succeeded).
    // BND.ADDR / BND.PORT — адрес и порт, к которым сервер привязался
    //   на стороне цели. Для простоты всегда отправляем 0.0.0.0:0.
    send_socks_reply(socks_conn, SocksReply::Succeeded).await?;

    // ── Двунаправленная ретрансляция данных ──────────────────────────────
    tunnel.relay_bidirectional(socks_conn).await?;

    Ok(())
}

/// Отправляет SOCKS5-ответ клиенту.
///
/// Формат ответа (RFC 1928, раздел 6):
///   ┌────────┬────────┬──────┬──────┬────────────────┬────────┐
///   │ VER (1)│ REP (1)│ RSV  │ ATYP │ BND.ADDR (var) │ BND.PORT│
///   │  0x05  │  код   │ 0x00 │тип   │ адрес привязки │ 2 байта │
///   └────────┴────────┴──────┴──────┴────────────────┴────────┘
/// VER — версия протокола, всегда 0x05.
/// REP — код ответа:
///   0x00 — запрос выполнен успешно,
///   0x01 — общая ошибка SOCKS-сервера,
///   0x02 — соединение запрещено правилами,
///   0x03 — сеть недоступна,
///   0x04 — хост недоступен,
///   0x05 — соединение отклонено,
///   0x06 — превышен TTL,
///   0x07 — команда не поддерживается,
///   0x08 — тип адреса не поддерживается.
/// RSV — зарезервированный байт, всегда 0x00.
/// ATYP — тип адреса привязки (BND.ADDR).
/// BND.ADDR — адрес, к которому сервер привязался для соединения с целью.
///   В данной реализации всегда 0.0.0.0 (IPv4, 4 нулевых байта).
/// BND.PORT — порт привязки, всегда 0 (2 нулевых байта).
async fn send_socks_reply(
    stream: &mut TcpStream,
    rep: SocksReply,
) -> Result<(), Box<dyn std::error::Error>> {
    stream
        .write_all(&[
            SOCKS_VERSION,           // VER: версия SOCKS5
            rep as u8,               // REP: код ответа
            0x00,                    // RSV: зарезервировано
            AddressType::Ipv4 as u8, // ATYP: IPv4
            0,
            0,
            0,
            0, // BND.ADDR: 0.0.0.0
            0,
            0, // BND.PORT: 0
        ])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{self, AddressType, SOCKS_VERSION};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use vs_vpn_tunnel_tcp_encrypted::crypto;

    #[tokio::test]
    async fn test_tunnel_header_plain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut tunnel, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            tunnel.read_exact(&mut buf[..2]).await.unwrap();
            let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let mut frame = vec![0u8; frame_len];
            tunnel.read_exact(&mut frame).await.unwrap();
            let (atyp, addr, port) = protocol::parse_header(&frame).unwrap();
            tunnel.write_all(&1u16.to_be_bytes()).await.unwrap();
            tunnel.write_all(&[0x00]).await.unwrap();
            (atyp, addr, port)
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (atyp, addr_bytes) = protocol::encode_address("example.com");
        let port: u16 = 443;
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
        assert_eq!(status_buf[0], 0x00);

        let (s_atyp, s_addr, s_port) = server.await.unwrap();
        assert_eq!(s_atyp, atyp);
        assert_eq!(s_addr, "example.com");
        assert_eq!(s_port, port);
    }

    #[tokio::test]
    async fn test_tunnel_header_ipv4_plain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut tunnel, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            tunnel.read_exact(&mut buf[..2]).await.unwrap();
            let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let mut frame = vec![0u8; frame_len];
            tunnel.read_exact(&mut frame).await.unwrap();
            let (atyp, addr, port) = protocol::parse_header(&frame).unwrap();
            // Отвечаем ошибкой — эмулируем отказ сервера
            tunnel.write_all(&1u16.to_be_bytes()).await.unwrap();
            tunnel.write_all(&[0x05]).await.unwrap();
            (atyp, addr, port)
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (atyp, addr_bytes) = protocol::encode_address("10.0.0.1");
        let port: u16 = 8080;
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
        assert_eq!(status_buf[0], 0x05); // ConnectionRefused

        let (s_atyp, s_addr, s_port) = server.await.unwrap();
        assert_eq!(s_atyp, AddressType::Ipv4);
        assert_eq!(s_addr, "10.0.0.1");
        assert_eq!(s_port, port);
    }

    #[tokio::test]
    async fn test_tunnel_header_encrypted() {
        let psk = crypto::generate_psk();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut tunnel, _) = listener.accept().await.unwrap();
            let (ck, sk) = crypto::secure_handshake(&mut tunnel, &psk, false)
                .await
                .unwrap();
            let plain = crypto::read_encrypted_frame(&mut tunnel, &ck)
                .await
                .unwrap()
                .unwrap();
            let (atyp, addr, port) = protocol::parse_header(&plain).unwrap();
            let mut s_nonce: u64 = 0;
            crypto::write_encrypted_frame(&mut tunnel, &[0x00], &sk, &mut s_nonce)
                .await
                .unwrap();
            (atyp, addr, port)
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let (ck, sk) = crypto::secure_handshake(&mut client, &psk, true)
            .await
            .unwrap();

        let target = "10.0.0.1";
        let port: u16 = 8080;
        let (atyp, addr_bytes) = protocol::encode_address(target);
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
        assert_eq!(plain[0], 0x00);

        let (s_atyp, s_addr, s_port) = server.await.unwrap();
        assert_eq!(s_atyp, atyp);
        assert_eq!(s_addr, target);
        assert_eq!(s_port, port);
    }

    #[tokio::test]
    async fn test_socks5_handshake_and_connect_plain() {
        // Запускаем mock-сервер туннеля, который принимает заголовок и отвечает 0x00
        let tunnel_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tunnel_addr = tunnel_listener.local_addr().unwrap().to_string();

        let tunnel_server = tokio::spawn(async move {
            let (mut tunnel, _) = tunnel_listener.accept().await.unwrap();
            let mut buf = [0u8; 512];
            tunnel.read_exact(&mut buf[..2]).await.unwrap();
            let frame_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            let mut _frame = vec![0u8; frame_len];
            tunnel.read_exact(&mut _frame).await.unwrap();
            tunnel.write_all(&1u16.to_be_bytes()).await.unwrap();
            tunnel.write_all(&[0x00]).await.unwrap();
            // Держим соединение открытым для ретрансляции
            let _ = tokio::io::copy(&mut tunnel, &mut tokio::io::sink()).await;
        });

        // Принимаем SOCKS5-соединение и передаём в handle_socks_client
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut socks_conn, _) = socks_listener.accept().await.unwrap();
            handle_socks_client(&mut socks_conn, &tunnel_addr, None)
                .await
                .unwrap();
        });

        // Подключаемся как SOCKS5-клиент
        let mut socks_client = TcpStream::connect(socks_addr).await.unwrap();

        // SOCKS5 handshake: VER=5, NMETHODS=1, METHOD=0x00
        socks_client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00])
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        socks_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [SOCKS_VERSION, 0x00]);

        // SOCKS5 request: VER=5, CMD=1(CONNECT), RSV=0, ATYP=1(IPv4), 127.0.0.1:80
        socks_client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();

        // Читаем SOCKS5-ответ
        let mut reply = [0u8; 10];
        socks_client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS_VERSION);
        assert_eq!(reply[1], 0x00); // REP = succeeded

        // Закрываем соединение, чтобы handle_socks_client завершился
        drop(socks_client);

        handle.await.unwrap();
        tunnel_server.abort();
    }

    #[tokio::test]
    async fn test_socks5_unsupported_command() {
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let (mut socks_conn, _) = socks_listener.accept().await.unwrap();
            let result = handle_socks_client(&mut socks_conn, "127.0.0.1:1", None).await;
            assert!(result.is_err());
        });

        let mut socks_client = TcpStream::connect(socks_addr).await.unwrap();

        // SOCKS5 handshake
        socks_client
            .write_all(&[SOCKS_VERSION, 0x01, 0x00])
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        socks_client.read_exact(&mut buf).await.unwrap();

        // SOCKS5 request: CMD=0x02 (BIND) — не поддерживается
        socks_client
            .write_all(&[SOCKS_VERSION, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();

        // Читаем SOCKS5-ответ с ошибкой
        let mut reply = [0u8; 10];
        socks_client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], SOCKS_VERSION);
        assert_eq!(reply[1], 0x07); // CommandNotSupported

        handle.await.unwrap();
    }
}
