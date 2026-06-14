use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

/// Абстрактный туннель: владеет TCP-потоком, предоставляет фреймовый протокол
/// и двунаправленную ретрансляцию (статическая диспетчеризация — без dyn).
#[async_trait]
pub trait Tunnel: Send {
    /// Отправить один фрейм данных в туннель.
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    /// Принять один фрейм данных из туннеля (None = EOF).
    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Двунаправленная ретрансляция: внутренний поток ↔ внешний поток.
    /// Потребляет внутренний поток (self.stream.take()) для доступа к полям
    /// ключей/nonce без конфликтов заимствования.
    async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()>;
}
