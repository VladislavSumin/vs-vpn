use crate::crypto;
use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::error;

/// Супер-trait для dyn-совместимого параметра ретрансляции.
trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// Публичная обёртка над конкретным режимом туннеля.
/// Скрывает `if secret` за единым trait-интерфейсом.
pub struct Tunnel {
    inner: Box<dyn TunnelInner>,
}

#[async_trait]
trait TunnelInner: Send {
    /// Отправить один фрейм данных в туннель.
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    /// Принять один фрейм данных из туннеля (None = EOF).
    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Двунаправленная ретрансляция: внутренний поток ↔ внешний поток.
    /// Потребляет внутренний поток (self.stream.take()) для доступа к полям
    /// ключей/nonce без конфликтов заимствования.
    async fn relay_bidirectional(&mut self, external: &mut dyn IoStream) -> io::Result<()>;
}

impl Tunnel {
    /// Создаёт туннель: выполняет рукопожатие (для encrypted) и возвращает
    /// готовый объект, владеющий потоком.
    pub async fn new(
        stream: TcpStream,
        secret: Option<[u8; crypto::KEY_LEN]>,
        is_client: bool,
    ) -> io::Result<Self> {
        let inner: Box<dyn TunnelInner> = match secret {
            Some(psk) => Box::new(EncryptedTunnel::new(stream, psk, is_client).await?),
            None => Box::new(PlainTunnel::new(stream)),
        };
        Ok(Self { inner })
    }

    pub async fn send_frame(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.send_frame(data).await
    }

    pub async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.inner.recv_frame().await
    }

    pub async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()> {
        self.inner.relay_bidirectional(external).await
    }
}

// ── PlainTunnel ──────────────────────────────────────────────────────────────

struct PlainTunnel {
    stream: Option<TcpStream>,
}

impl PlainTunnel {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

#[async_trait]
impl TunnelInner for PlainTunnel {
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

    async fn relay_bidirectional(&mut self, external: &mut dyn IoStream) -> io::Result<()> {
        let stream = self.stream.take().expect("stream уже ушёл в relay");
        let (mut tr, mut tw) = tokio::io::split(stream);
        let (mut er, mut ew) = tokio::io::split(external);

        tokio::select! {
            r = tokio::io::copy(&mut er, &mut tw) => {
                if let Err(e) = r { error!("relay plain tunnel-send error: {e}"); }
            }
            r = tokio::io::copy(&mut tr, &mut ew) => {
                if let Err(e) = r { error!("relay plain tunnel-recv error: {e}"); }
            }
        }
        Ok(())
    }
}

// ── EncryptedTunnel ─────────────────────────────────────────────────────────

struct EncryptedTunnel {
    stream: Option<TcpStream>,
    client_key: [u8; crypto::KEY_LEN],
    server_key: [u8; crypto::KEY_LEN],
    c_nonce: u64,
    s_nonce: u64,
    is_client: bool,
}

impl EncryptedTunnel {
    async fn new(
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
impl TunnelInner for EncryptedTunnel {
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
            crypto::read_encrypted_frame(stream, &self.server_key).await
        } else {
            crypto::read_encrypted_frame(stream, &self.client_key).await
        }
    }

    async fn relay_bidirectional(&mut self, external: &mut dyn IoStream) -> io::Result<()> {
        let stream = self.stream.take().expect("stream уже ушёл в relay");
        let (mut tr, mut tw) = tokio::io::split(stream);
        let (mut er, mut ew) = tokio::io::split(external);

        let send_key;
        let recv_key;
        let send_nonce;
        if self.is_client {
            send_key = &self.client_key;
            recv_key = &self.server_key;
            send_nonce = &mut self.c_nonce;
        } else {
            send_key = &self.server_key;
            recv_key = &self.client_key;
            send_nonce = &mut self.s_nonce;
        }

        tokio::select! {
            r = crypto::relay_plain_to_encrypted(&mut er, &mut tw, send_key, send_nonce) => {
                if let Err(e) = r { error!("relay encrypted tunnel-send error: {e}"); }
            }
            r = crypto::relay_encrypted_to_plain(&mut tr, &mut ew, recv_key) => {
                if let Err(e) = r { error!("relay encrypted tunnel-recv error: {e}"); }
            }
        }
        Ok(())
    }
}
