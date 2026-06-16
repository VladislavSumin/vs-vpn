pub mod crypto;

use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use vs_vpn_tunnel::{Tunnel, TunnelAcceptor, TunnelConnector};

pub struct EncryptedTunnel {
    stream: Option<TcpStream>,
    client_key: [u8; crypto::KEY_LEN],
    server_key: [u8; crypto::KEY_LEN],
    c_nonce: u64,
    s_nonce: u64,
    is_client: bool,
}

impl EncryptedTunnel {
    pub async fn new(
        mut stream: TcpStream,
        psk: [u8; crypto::KEY_LEN],
        is_client: bool,
    ) -> io::Result<Self> {
        let (client_key, server_key) =
            crypto::secure_handshake(&mut stream, &psk, is_client).await?;
        Ok(Self {
            stream: Some(stream),
            client_key,
            server_key,
            c_nonce: 0,
            s_nonce: 0,
            is_client,
        })
    }
}

#[async_trait]
impl Tunnel for EncryptedTunnel {
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let stream = self.stream.as_mut().expect("stream уже ушёл в relay");
        if self.is_client {
            crypto::write_encrypted_frame(stream, data, &self.client_key, &mut self.c_nonce).await
        } else {
            crypto::write_encrypted_frame(stream, data, &self.server_key, &mut self.s_nonce).await
        }
    }

    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let stream = self.stream.as_mut().expect("stream уже ушёл в relay");
        if self.is_client {
            crypto::read_encrypted_frame(stream, &self.server_key, &mut self.s_nonce).await
        } else {
            crypto::read_encrypted_frame(stream, &self.client_key, &mut self.c_nonce).await
        }
    }

    async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()> {
        let stream = self.stream.take().expect("stream уже ушёл в relay");
        let (mut tr, mut tw) = tokio::io::split(stream);
        let (mut er, mut ew) = tokio::io::split(external);

        let send_key;
        let recv_key;
        let send_nonce;
        let recv_nonce;
        if self.is_client {
            send_key = &self.client_key;
            recv_key = &self.server_key;
            send_nonce = &mut self.c_nonce;
            recv_nonce = &mut self.s_nonce;
        } else {
            send_key = &self.server_key;
            recv_key = &self.client_key;
            send_nonce = &mut self.s_nonce;
            recv_nonce = &mut self.c_nonce;
        }

        tokio::select! {
            r = crypto::relay_plain_to_encrypted(&mut er, &mut tw, send_key, send_nonce) => {
                match r {
                    Ok(()) => info!("Encrypted relay finished: external->tunnel"),
                    Err(e) => error!(%e, "Encrypted relay error: external->tunnel"),
                }
            }
            r = crypto::relay_encrypted_to_plain(&mut tr, &mut ew, recv_key, recv_nonce) => {
                match r {
                    Ok(()) => info!("Encrypted relay finished: tunnel->external"),
                    Err(e) => error!(%e, "Encrypted relay error: tunnel->external"),
                }
            }
        }
        Ok(())
    }
}

// ── Коннектор (клиентская сторона) ───────────────────────────────────────

#[derive(Clone)]
pub struct EncryptedConnector {
    server_addr: String,
    psk: [u8; crypto::KEY_LEN],
}

impl EncryptedConnector {
    pub fn new(server_addr: String, psk: [u8; crypto::KEY_LEN]) -> Self {
        Self { server_addr, psk }
    }
}

#[async_trait]
impl TunnelConnector for EncryptedConnector {
    type TunnelType = EncryptedTunnel;

    async fn connect(&self) -> io::Result<EncryptedTunnel> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        EncryptedTunnel::new(stream, self.psk, true).await
    }
}

// ── Акцептор (серверная сторона) ─────────────────────────────────────────

pub struct EncryptedAcceptor {
    listener: TcpListener,
    psk: [u8; crypto::KEY_LEN],
}

impl EncryptedAcceptor {
    pub async fn bind(addr: &str, psk: [u8; crypto::KEY_LEN]) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            psk,
        })
    }
}

#[async_trait]
impl TunnelAcceptor for EncryptedAcceptor {
    type TunnelType = EncryptedTunnel;

    async fn accept(&self) -> io::Result<(EncryptedTunnel, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let tunnel = EncryptedTunnel::new(stream, self.psk, false).await?;
        Ok((tunnel, addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}
