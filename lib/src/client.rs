use crate::protocol::{
    self, AddressType, SOCKS_AUTH_NO_ACCEPTABLE, SOCKS_VERSION, SocksCommand, SocksReply,
};
use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, debug, error, info, info_span, instrument, trace, warn};
use vs_vpn_tunnel::Tunnel;
use vs_vpn_tunnel_tcp_encrypted::{self, EncryptedTunnel, crypto};
use vs_vpn_tunnel_tcp_plain::PlainTunnel;

#[instrument(name = "SOCKS5", skip_all)]
pub async fn run(
    listen: &str,
    server_addr: &str,
    secret: Option<[u8; crypto::KEY_LEN]>,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
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
                let (mut socks_conn, client_addr) = result?;
                let server_addr = server_addr.to_string();
                let connection_span = info_span!(parent: Span::current(), "", c=%client_addr);

                tokio::spawn(
                    async move {
                        debug!("SOCKS5 connection accepted");
                        if let Err(e) =
                            handle_socks_client(&mut socks_conn, &server_addr, secret).await
                        {
                            error!(%e, "SOCKS5 connection failed");
                        }
                    }
                    .instrument(connection_span),
                );
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
    socks_conn.read_exact(&mut buf[..2]).await?; // VER + NMETHODS
    let n_methods = buf[1] as usize;
    socks_conn.read_exact(&mut buf[..n_methods]).await?; // nmethods list

    let methods = &buf[..n_methods];
    if methods.contains(&0x00) {
        socks_conn.write_all(&[SOCKS_VERSION, 0x00]).await?;
    } else {
        socks_conn
            .write_all(&[SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE])
            .await?;
        return Err("client does not support no-authentication method".into());
    }
    trace!("SOCKS5 handshake completed");

    // ── SOCKS5 Request (RFC 1928, раздел 4) ──────────────────────────────
    socks_conn.read_exact(&mut buf[..4]).await?; // VER + CMD + RSV + ATYP
    let cmd = SocksCommand::from_u8(buf[1]);
    if cmd != Some(SocksCommand::Connect) {
        // Поддерживаем только TCP CONNECT; для остальных — ошибка.
        warn!("unsupported SOCKS5 command: {cmd:?}");
        send_socks_reply(socks_conn, SocksReply::CommandNotSupported).await?;
        return Err("unsupported SOCKS5 command".into());
    }

    // Address type.
    let address_type = AddressType::from_u8(buf[3])
        .ok_or_else(|| format!("unsupported address type: {:#04x}", buf[3]))?;
    // Address.
    let target_addr = protocol::read_address(socks_conn, address_type, &mut buf).await?;
    // Port
    socks_conn.read_exact(&mut buf[..2]).await?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    let target = format!("{target_addr}:{port}");
    info!(%target, "SOCKS5 CONNECT");

    // ── Построение туннельного заголовка ─────────────────────────────────
    let (header_atyp, addr_bytes) = protocol::encode_address(&target_addr);
    let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
    header.push(header_atyp as u8);
    header.extend_from_slice(&addr_bytes);
    header.extend_from_slice(&port.to_be_bytes());

    // ── Подключение к VPN-серверу и туннельный протокол ─────────────────
    let server = TcpStream::connect(server_addr).await?;
    debug!("Connected to VPN server");

    if let Some(psk) = secret {
        let tunnel = EncryptedTunnel::new(server, psk, true).await?;
        run_tunnel_client(socks_conn, tunnel, &header, &target).await
    } else {
        let tunnel = PlainTunnel::new(server);
        run_tunnel_client(socks_conn, tunnel, &header, &target).await
    }
}

/// Общая логика туннельного протокола (статическая диспетчеризация через `T`).
#[instrument(name="tun", skip(socks_conn, tunnel, header), fields(target = %target))]
async fn run_tunnel_client<T: Tunnel>(
    socks_conn: &mut TcpStream,
    mut tunnel: T,
    header: &[u8],
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    tunnel.send_frame(header).await?;
    trace!("Tunnel header sent");

    let plain = tunnel.recv_frame().await?;
    let status = match plain {
        Some(ref p) if !p.is_empty() => p[0],
        _ => {
            warn!("Server closed connection before status");
            return Err("server closed connection before status".into());
        }
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
        let reason = match status {
            0x01 => "General SOCKS failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            _ => "Unknown error",
        };
        warn!(status = %status, reason, "Tunnel rejected by server");
        return Err(format!("server rejected: {reason} (status {status:#04x})").into());
    }

    // ── SOCKS5 Reply (RFC 1928, раздел 6) ────────────────────────────────
    send_socks_reply(socks_conn, SocksReply::Succeeded).await?;
    info!("Tunnel established, starting relay");

    // ── Двунаправленная ретрансляция данных ──────────────────────────────
    let relay_result = tunnel.relay_bidirectional(socks_conn).await;

    match &relay_result {
        Ok(()) => info!(duration = ?start.elapsed(), "Tunnel relay completed"),
        Err(e) => error!(%e, duration = ?start.elapsed(), "Tunnel relay failed"),
    }

    relay_result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Отправляет SOCKS5-ответ клиенту.
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
            let plain = crypto::read_encrypted_frame(&mut tunnel, &ck, &mut 0)
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

        let plain = crypto::read_encrypted_frame(&mut client, &sk, &mut 0)
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
            let (mut socks_conn, _addr) = socks_listener.accept().await.unwrap();
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
            let (mut socks_conn, _addr) = socks_listener.accept().await.unwrap();
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
