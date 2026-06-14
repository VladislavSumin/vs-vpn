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

    // ── Подключение к VPN-серверу и туннельный протокол ─────────────────
    // Устанавливаем TCP-соединение с VPN-сервером.
    let mut server = TcpStream::connect(server_addr).await?;

    // Туннельный протокол: клиент отправляет серверу заголовок с адресом цели.
    // Формат заголовка:
    //   ┌────────┬──────────────────┬────────┐
    //   │ ATYP   │ адрес цели (var) │ PORT   │
    //   │ 1 байт │ переменная длина │ 2 байта│
    //   └────────┴──────────────────┴────────┘
    // ATYP — тип адреса: 0x01 (IPv4) + 4 байта, 0x03 (домен) + 1 байт длины +
    //   N байт имени, 0x04 (IPv6) + 16 байт.
    // PORT — порт цели в сетевом порядке байт (big-endian).
    let (header_atyp, addr_bytes) = protocol::encode_address(&target_addr);
    let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
    header.push(header_atyp as u8);
    header.extend_from_slice(&addr_bytes);
    header.extend_from_slice(&port.to_be_bytes());
    server.write_all(&header).await?;

    // Читаем ответ сервера — один байт статуса:
    //   0x00 — успех (сервер подключился к цели).
    //   0x01 — общая ошибка / general SOCKS server failure.
    //   0x02 — соединение запрещено правилами.
    //   0x03 — сеть недоступна.
    //   0x04 — хост недоступен.
    //   0x05 — соединение отклонено (connection refused).
    //   остальное — общая ошибка.
    server.read_exact(&mut buf[..1]).await?;
    let status = buf[0];
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
    // После успешного handshake клиент SOCKS5 и VPN-сервер прозрачно
    // пересылают данные друг другу. Разделяем оба TCP-потока на
    // читающую (r) и пишущую (w) половины и запускаем два встречных
    // копирования: клиент → сервер и сервер → клиент.
    // tokio::select! завершает оба копирования, как только одно из них
    // останавливается (соединение разорвано с любой стороны).
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
