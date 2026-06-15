use std::net::SocketAddr;

/// Информация о процессе, установившем соединение.
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

impl std::fmt::Display for ProcessInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.name, self.pid)
    }
}

/// Определяет локальный процесс по peer-адресу TCP-подключения.
///
/// Тяжёлая блокирующая операция (вызов `lsof`).
/// Вызывающий код должен обернуть в `tokio::task::spawn_blocking`.
/// Возвращает `None`, если определить процесс невозможно.
pub fn identify_peer(peer_addr: SocketAddr, _local_addr: SocketAddr) -> Option<ProcessInfo> {
    identify_peer_impl(peer_addr)
}

#[cfg(target_os = "macos")]
fn identify_peer_impl(peer_addr: SocketAddr) -> Option<ProcessInfo> {
    use std::process::Command;

    let port = peer_addr.port();
    let host = peer_addr.ip();

    let filter = format!("TCP@{host}:{port}");
    let output = Command::new("/usr/sbin/lsof")
        .args(["-n", "-P", "-i", &filter, "-F", "pcn"])
        .output()
        .ok()?;

    parse_lsof_f(String::from_utf8_lossy(&output.stdout).as_ref())
}

#[cfg(target_os = "macos")]
fn parse_lsof_f(stdout: &str) -> Option<ProcessInfo> {
    let mut pid: Option<u32> = None;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match line.as_bytes()[0] {
            b'p' => {
                pid = line[1..].parse::<u32>().ok();
            }
            b'c' => {
                if let Some(p) = pid {
                    let name = line[1..].to_string();
                    return Some(ProcessInfo { pid: p, name });
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(not(target_os = "macos"))]
fn identify_peer_impl(_peer_addr: SocketAddr) -> Option<ProcessInfo> {
    None
}
