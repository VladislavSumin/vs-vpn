use async_trait::async_trait;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Абстрактный туннель: предоставляет фреймовый протокол
/// и двунаправленную ретрансляцию (статическая диспетчеризация — без dyn).
#[async_trait]
pub trait Tunnel: Send + 'static {
    /// Отправить один фрейм данных в туннель.
    async fn send_frame(&mut self, data: &[u8]) -> io::Result<()>;

    /// Принять один фрейм данных из туннеля (None = EOF).
    async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>>;

    /// Двунаправленная ретрансляция: внутренний поток ↔ внешний поток.
    async fn relay_bidirectional<E: AsyncRead + AsyncWrite + Unpin + Send>(
        &mut self,
        external: &mut E,
    ) -> io::Result<()>;
}

/// Фабрика туннелей для клиента: создаёт туннель к удалённому серверу.
/// Статическая диспетчеризация: конкретный тип через `associated type`.
#[async_trait]
pub trait TunnelConnector: Send + Sync {
    type TunnelType: Tunnel;

    /// Установить соединение с удалённой стороной и создать туннель.
    async fn connect(&self) -> io::Result<Self::TunnelType>;
}

/// Приёмник туннелей для сервера: принимает входящие соединения
/// и создаёт туннели (статическая диспетчеризация).
#[async_trait]
pub trait TunnelAcceptor: Send + Sync {
    type TunnelType: Tunnel;

    /// Принять входящее соединение и создать туннель.
    async fn accept(&self) -> io::Result<(Self::TunnelType, SocketAddr)>;

    /// Локальный адрес слушателя (для тестов и порт-дискавери).
    fn local_addr(&self) -> io::Result<SocketAddr>;
}
