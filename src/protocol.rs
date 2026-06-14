use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub const SOCKS_VERSION: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl AddressType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Ipv4),
            0x03 => Some(Self::Domain),
            0x04 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksReply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    // TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    // AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl SocksCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Connect),
            0x02 => Some(Self::Bind),
            0x03 => Some(Self::UdpAssociate),
            _ => None,
        }
    }
}

pub async fn read_address(
    stream: &mut TcpStream,
    atyp: AddressType,
    buf: &mut [u8],
) -> Result<String, Box<dyn std::error::Error>> {
    match atyp {
        AddressType::Ipv4 => {
            stream.read_exact(&mut buf[..4]).await?;
            Ok(format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]))
        }
        AddressType::Domain => {
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len]).await?;
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        }
        AddressType::Ipv6 => {
            stream.read_exact(&mut buf[..16]).await?;
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", buf[i * 2], buf[i * 2 + 1]))
                .collect();
            Ok(groups.join(":"))
        }
    }
}

pub fn encode_address(addr: &str) -> (AddressType, Vec<u8>) {
    if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
        (AddressType::Ipv4, ip.octets().to_vec())
    } else if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        (AddressType::Ipv6, ip.octets().to_vec())
    } else {
        let bytes = addr.as_bytes();
        let mut v = Vec::with_capacity(1 + bytes.len());
        v.push(bytes.len() as u8);
        v.extend_from_slice(bytes);
        (AddressType::Domain, v)
    }
}
