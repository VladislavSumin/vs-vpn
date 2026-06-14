use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::error;
use vs_vpn_tunnel::Tunnel;

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
                if let Err(e) = r { error!("relay plain tunnel-send error: {e}"); }
            }
            r = tokio::io::copy(&mut tr, &mut ew) => {
                if let Err(e) = r { error!("relay plain tunnel-recv error: {e}"); }
            }
        }
        Ok(())
    }
}
