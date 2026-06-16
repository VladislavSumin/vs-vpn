use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};
use vs_vpn_tunnel::{Tunnel, TunnelAcceptor, TunnelConnector};

pub struct PlainTunnel {
    stream: Option<TcpStream>,
}

impl PlainTunnel {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

#[async_trait]
impl Tunnel for PlainTunnel {
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        let stream = self.stream.as_mut().expect("stream уже ушёл в relay");
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let stream = self.stream.as_mut().expect("stream уже ушёл в relay");
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; frame_len];
        stream.read_exact(&mut data).await?;
        Ok(Some(data))
    }

    async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()> {
        let stream = self.stream.take().expect("stream уже ушёл в relay");
        let (mut tr, mut tw) = tokio::io::split(stream);
        let (mut er, mut ew) = tokio::io::split(external);

        tokio::select! {
            r = tokio::io::copy(&mut er, &mut tw) => {
                match r {
                    Ok(n) => info!(bytes = n, "Plain relay finished: external->tunnel"),
                    Err(e) => error!(%e, "Plain relay error: external->tunnel"),
                }
            }
            r = tokio::io::copy(&mut tr, &mut ew) => {
                match r {
                    Ok(n) => info!(bytes = n, "Plain relay finished: tunnel->external"),
                    Err(e) => error!(%e, "Plain relay error: tunnel->external"),
                }
            }
        }
        Ok(())
    }
}

// ── Коннектор (клиентская сторона) ───────────────────────────────────────

#[derive(Clone)]
pub struct PlainConnector {
    server_addr: String,
}

impl PlainConnector {
    pub fn new(server_addr: String) -> Self {
        Self { server_addr }
    }
}

#[async_trait]
impl TunnelConnector for PlainConnector {
    type TunnelType = PlainTunnel;

    async fn connect(&self) -> io::Result<PlainTunnel> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        Ok(PlainTunnel::new(stream))
    }
}

// ── Акцептор (серверная сторона) ─────────────────────────────────────────

pub struct PlainAcceptor {
    listener: TcpListener,
}

impl PlainAcceptor {
    pub async fn bind(addr: &str) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
        })
    }
}

#[async_trait]
impl TunnelAcceptor for PlainAcceptor {
    type TunnelType = PlainTunnel;

    async fn accept(&self) -> io::Result<(PlainTunnel, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        Ok((PlainTunnel::new(stream), addr))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}
