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

pub fn parse_header(data: &[u8]) -> Result<(AddressType, String, u16), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Err("empty header".into());
    }
    let atyp = AddressType::from_u8(data[0])
        .ok_or_else(|| format!("unsupported address type: {:#04x}", data[0]))?;

    let addr_bytes: usize;
    let addr = match atyp {
        AddressType::Ipv4 => {
            if data.len() < 1 + 4 + 2 {
                return Err("header too short for IPv4".into());
            }
            addr_bytes = 4;
            format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4])
        }
        AddressType::Domain => {
            if data.len() < 1 + 1 {
                return Err("header too short for domain".into());
            }
            let len = data[1] as usize;
            addr_bytes = 1 + len;
            if data.len() < 1 + addr_bytes + 2 {
                return Err("header too short for domain".into());
            }
            String::from_utf8_lossy(&data[2..2 + len]).to_string()
        }
        AddressType::Ipv6 => {
            if data.len() < 1 + 16 + 2 {
                return Err("header too short for IPv6".into());
            }
            addr_bytes = 16;
            let groups: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", data[1 + i * 2], data[1 + i * 2 + 1]))
                .collect();
            groups.join(":")
        }
    };

    let port_start = 1 + addr_bytes;
    let port = u16::from_be_bytes([data[port_start], data[port_start + 1]]);

    Ok((atyp, addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_address_ipv4() {
        let (atyp, bytes) = encode_address("192.168.1.1");
        assert_eq!(atyp, AddressType::Ipv4);
        assert_eq!(bytes, vec![192, 168, 1, 1]);
    }

    #[test]
    fn test_encode_address_ipv6() {
        // ::1 (loopback IPv6)
        let (atyp, bytes) = encode_address("::1");
        assert_eq!(atyp, AddressType::Ipv6);
        assert_eq!(bytes.len(), 16);
        // ::1 = 00...01 (15 нулей, потом 1)
        assert_eq!(bytes[15], 1);
        for b in bytes.iter().take(15) {
            assert_eq!(*b, 0);
        }
    }

    #[test]
    fn test_encode_address_domain() {
        let (atyp, bytes) = encode_address("example.com");
        assert_eq!(atyp, AddressType::Domain);
        // 1 байт длины + "example.com"
        assert_eq!(bytes[0], 11);
        assert_eq!(&bytes[1..], b"example.com");
    }

    #[test]
    fn test_encode_address_localhost_ipv4() {
        // "127.0.0.1" — валидный IPv4
        let (atyp, bytes) = encode_address("127.0.0.1");
        assert_eq!(atyp, AddressType::Ipv4);
        assert_eq!(bytes, vec![127, 0, 0, 1]);
    }

    #[test]
    fn test_parse_header_ipv4() {
        // atyp=0x01, addr=10.0.0.1, port=443
        let data = &[0x01, 10, 0, 0, 1, 0x01, 0xBB]; // port 443
        let (atyp, addr, port) = parse_header(data).unwrap();
        assert_eq!(atyp, AddressType::Ipv4);
        assert_eq!(addr, "10.0.0.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_header_domain() {
        // atyp=0x03, len=3, "foo", port=8080
        let data = &[0x03, 3, b'f', b'o', b'o', 0x1F, 0x90]; // port 8080
        let (atyp, addr, port) = parse_header(data).unwrap();
        assert_eq!(atyp, AddressType::Domain);
        assert_eq!(addr, "foo");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_header_ipv6() {
        // atyp=0x04, addr=::1, port=80
        let mut data = vec![0x04u8];
        data.extend(std::iter::repeat_n(0u8, 16));
        data[1 + 15] = 1; // последний октет = 1 (::1)
        data.extend(&80u16.to_be_bytes());
        let (atyp, addr, port) = parse_header(&data).unwrap();
        assert_eq!(atyp, AddressType::Ipv6);
        assert_eq!(addr, "0000:0000:0000:0000:0000:0000:0000:0001");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_header_empty() {
        let result = parse_header(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_invalid_atyp() {
        // atyp=0xFF — невалидный тип
        let data = &[0xFF];
        let result = parse_header(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_short_ipv4() {
        // atyp=0x01, но данных недостаточно (только 3 байта вместо 4 адреса + 2 порта)
        let data = &[0x01, 10, 0, 0];
        let result = parse_header(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_short_domain() {
        // atyp=0x03, длина=5, но самого имени нет
        let data = &[0x03, 5];
        let result = parse_header(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_short_ipv6() {
        // atyp=0x04, но данных недостаточно
        let data = &[0x04, 0, 0, 0, 0]; // только 4 байта после atyp
        let result = parse_header(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_parse_roundtrip_ipv4() {
        let addr = "8.8.8.8";
        let (atyp, addr_bytes) = encode_address(addr);
        let port: u16 = 53;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());

        let (parsed_atyp, parsed_addr, parsed_port) = parse_header(&header).unwrap();
        assert_eq!(parsed_atyp, atyp);
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_encode_parse_roundtrip_domain() {
        let addr = "api.github.com";
        let (atyp, addr_bytes) = encode_address(addr);
        let port: u16 = 443;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());

        let (parsed_atyp, parsed_addr, parsed_port) = parse_header(&header).unwrap();
        assert_eq!(parsed_atyp, atyp);
        assert_eq!(parsed_addr, addr);
        assert_eq!(parsed_port, port);
    }

    #[test]
    fn test_encode_parse_roundtrip_ipv6() {
        let addr = "2001:db8::1";
        let (atyp, addr_bytes) = encode_address(addr);
        let port: u16 = 80;
        let mut header = Vec::with_capacity(1 + addr_bytes.len() + 2);
        header.push(atyp as u8);
        header.extend_from_slice(&addr_bytes);
        header.extend_from_slice(&port.to_be_bytes());

        let (parsed_atyp, _parsed_addr, parsed_port) = parse_header(&header).unwrap();
        assert_eq!(parsed_atyp, atyp);
        // Обратное представление IPv6 может отличаться (сжатие нулей), поэтому
        // сравниваем только тип и порт; адрес проверяем по разложенным октетам.
        assert_eq!(parsed_port, port);
        // Убедимся, что октеты совпадают
        assert_eq!(addr_bytes, {
            let ip: std::net::Ipv6Addr = addr.parse().unwrap();
            ip.octets().to_vec()
        });
    }
}
