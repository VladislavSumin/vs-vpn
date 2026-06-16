pub mod cert;

use async_trait::async_trait;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info};
use vs_vpn_tunnel::{Tunnel, TunnelAcceptor, TunnelConnector};

pub struct QuicTunnel {
    _connection: quinn::Connection,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
}

impl QuicTunnel {
    fn new(
        connection: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            _connection: connection,
            send: Some(send),
            recv: Some(recv),
        }
    }
}

// ── Фрейминг (2-byte BE length prefix, как PlainTunnel) ───────────────────

#[async_trait]
impl Tunnel for QuicTunnel {
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let send = self.send.as_mut().expect("stream уже ушёл в relay");
        let len = data.len() as u16;
        send.write_all(&len.to_be_bytes()).await.map_err(quic_err)?;
        send.write_all(data).await.map_err(quic_err)?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let recv = self.recv.as_mut().expect("stream уже ушёл в relay");
        let mut len_buf = [0u8; 2];
        read_exact_quic(recv, &mut len_buf).await?;
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; frame_len];
        read_exact_quic(recv, &mut data).await?;
        Ok(Some(data))
    }

    async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()> {
        let mut send = self.send.take().expect("stream уже ушёл в relay");
        let mut recv = self.recv.take().expect("stream уже ушёл в relay");
        let (mut er, mut ew) = tokio::io::split(external);

        tokio::select! {
            r = relay_external_to_quic(&mut er, &mut send) => {
                match r {
                    Ok(()) => info!("QUIC relay finished: external->tunnel"),
                    Err(e) => error!(%e, "QUIC relay error: external->tunnel"),
                }
            }
            r = relay_quic_to_external(&mut recv, &mut ew) => {
                match r {
                    Ok(()) => info!("QUIC relay finished: tunnel->external"),
                    Err(e) => error!(%e, "QUIC relay error: tunnel->external"),
                }
            }
        }
        Ok(())
    }
}

// ── Коннектор (клиентская сторона) ───────────────────────────────────────

#[derive(Clone)]
pub struct QuicConnector {
    server_addr: String,
    tls_config: Arc<rustls::ClientConfig>,
}

impl QuicConnector {
    pub fn new(server_addr: String, tls_config: rustls::ClientConfig) -> Self {
        Self {
            server_addr,
            tls_config: Arc::new(tls_config),
        }
    }
}

#[async_trait]
impl TunnelConnector for QuicConnector {
    type TunnelType = QuicTunnel;

    async fn connect(&self) -> io::Result<QuicTunnel> {
        let (host, port) = split_host_port(&self.server_addr)?;
        let addr = tokio::net::lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| io_err(format!("could not resolve: {}", self.server_addr)))?;

        let quic_tls =
            quinn::crypto::rustls::QuicClientConfig::try_from(self.tls_config.as_ref().clone())
                .map_err(|e| io_err(format!("invalid QUIC TLS config: {e}")))?;

        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(io_err)?)
            .map_err(|e| io_err(format!("endpoint creation: {e}")))?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        let conn = endpoint
            .connect_with(client_config, addr, host)
            .map_err(|e| io_err(format!("connect_with: {e}")))?
            .await
            .map_err(|e| io_err(format!("handshake: {e}")))?;

        let (send, recv) = conn.open_bi().await.map_err(io_err)?;
        Ok(QuicTunnel::new(conn, send, recv))
    }
}

// ── Акцептор (серверная сторона) ─────────────────────────────────────────

pub struct QuicAcceptor {
    endpoint: quinn::Endpoint,
}

impl QuicAcceptor {
    pub async fn bind(
        addr: &str,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(io_err)?;
        tls_config.alpn_protocols = vec![b"vs-vpn".to_vec()];

        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(io_err)?;

        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let endpoint = quinn::Endpoint::server(server_config, addr.parse().map_err(io_err)?)
            .map_err(io_err)?;

        Ok(Self { endpoint })
    }
}

#[async_trait]
impl TunnelAcceptor for QuicAcceptor {
    type TunnelType = QuicTunnel;

    async fn accept(&self) -> io::Result<(QuicTunnel, SocketAddr)> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| io_err("endpoint closed"))?;
        let conn = incoming.await.map_err(io_err)?;
        let remote = conn.remote_address();
        let (send, recv) = conn.accept_bi().await.map_err(io_err)?;
        Ok((QuicTunnel::new(conn, send, recv), remote))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr().map_err(io_err)
    }
}

// ── Релейные хелперы ─────────────────────────────────────────────────────

async fn relay_external_to_quic<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut quinn::SendStream,
) -> io::Result<()> {
    let mut buf = vec![0u8; 16384];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.finish().map_err(quic_err)?;
            break Ok(());
        }
        writer.write_all(&buf[..n]).await.map_err(quic_err)?;
    }
}

async fn relay_quic_to_external<W: AsyncWrite + Unpin>(
    reader: &mut quinn::RecvStream,
    writer: &mut W,
) -> io::Result<()> {
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match reader.read(&mut buf).await.map_err(quic_err)? {
            Some(n) if n > 0 => n,
            _ => break Ok(()),
        };
        writer.write_all(&buf[..n]).await?;
    }
}

// ── Вспомогательные ──────────────────────────────────────────────────────

/// Читает ровно `buf.len()` байт из Quinn-стрима, возвращает `Ok(None)` на EOF.
async fn read_exact_quic(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> io::Result<Option<()>> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = match recv.read(&mut buf[offset..]).await.map_err(quic_err)? {
            Some(n) if n > 0 => n,
            _ => return Ok(None),
        };
        offset += n;
    }
    Ok(Some(()))
}

fn split_host_port(addr: &str) -> io::Result<(&str, u16)> {
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| io_err(format!("invalid address: {addr} (expected host:port)")))?;

    let port: u16 = port_str.parse().map_err(io_err)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Ok((host, port))
}

fn quic_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::cert;
    use super::*;
    use std::sync::Once;

    static RUSTLS_INIT: Once = Once::new();

    fn ensure_rustls() {
        RUSTLS_INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("failed to install rustls crypto provider");
        });
    }

    fn trusted_client_tls(cert_der: &CertificateDer<'_>) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"vs-vpn".to_vec()];
        config
    }

    #[tokio::test]
    async fn test_quic_send_recv_frame() {
        ensure_rustls();
        let (cert, key) = cert::generate_self_signed().unwrap();
        let acceptor = QuicAcceptor::bind("127.0.0.1:0", cert.clone(), key)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut tunnel, _) = acceptor.accept().await.unwrap();
            let frame = tunnel.recv_frame().await.unwrap().unwrap();
            assert_eq!(&frame, b"hello-quic");
            tunnel.send_frame(b"ack").await.unwrap();
            let _ = done_rx.await;
        });

        let host_port = format!("127.0.0.1:{}", addr.port());
        let tls = trusted_client_tls(&cert);
        let connector = QuicConnector::new(host_port, tls);
        let mut client = connector.connect().await.unwrap();

        client.send_frame(b"hello-quic").await.unwrap();
        let frame = client.recv_frame().await.unwrap().unwrap();
        assert_eq!(&frame, b"ack");

        let _ = done_tx.send(());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_quic_with_trusted_cert() {
        ensure_rustls();
        let (cert, key) = cert::generate_self_signed().unwrap();
        let fp = cert::fingerprint(&cert);
        let fp2 = fp.clone();
        let acceptor = QuicAcceptor::bind("127.0.0.1:0", cert.clone(), key)
            .await
            .unwrap();
        let addr = acceptor.local_addr().unwrap();

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut tunnel, _) = acceptor.accept().await.unwrap();
            let frame = tunnel.recv_frame().await.unwrap().unwrap();
            assert_eq!(frame, format!("fp={fp}").as_bytes());
            let _ = done_rx.await;
        });

        let host_port = format!("127.0.0.1:{}", addr.port());
        let tls = trusted_client_tls(&cert);
        let connector = QuicConnector::new(host_port, tls);
        let mut client = connector.connect().await.unwrap();

        client
            .send_frame(format!("fp={fp2}").as_bytes())
            .await
            .unwrap();
        let _ = done_tx.send(());
        server.await.unwrap();
    }
}
