use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring, JNI_VERSION_1_6};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// ── Лог-буфер (общий, живёт всё время жизни библиотеки) ───────────────────────

static LOG_BUF: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();

fn log_buf() -> &'static Arc<Mutex<Vec<String>>> {
    LOG_BUF.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Writer, который пишет в stderr (на Android попадает в logcat)
/// и одновременно добавляет строки в буфер для отдачи в Kotlin.
struct TeeWriter {
    buf: Arc<Mutex<Vec<String>>>,
}

impl Write for TeeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        io::stderr().write_all(data)?;
        let s = String::from_utf8_lossy(data);
        let mut lines = self.buf.lock().unwrap();
        for line in s.lines() {
            let t = line.trim();
            if !t.is_empty() {
                lines.push(t.to_string());
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

fn init_logging() {
    let lc_buf = log_buf().clone();
    let make_writer = move || TeeWriter {
        buf: lc_buf.clone(),
    };

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(make_writer),
        )
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .try_init();
}

// ── Состояние прокси ─────────────────────────────────────────────────────────

struct ProxyState {
    shutdown: CancellationToken,
    handle: std::thread::JoinHandle<()>,
}

static STATE: Mutex<Option<ProxyState>> = Mutex::new(None);

// ── Вспомогательная функция парсинга secret ─────────────────────────────────

fn parse_secret_opt(hex_str: Option<&str>) -> Option<[u8; 32]> {
    let s = hex_str?;
    if s.is_empty() {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

// ── JNI_OnLoad ───────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jint {
    init_logging();
    JNI_VERSION_1_6
}

// ── JNI: запуск прокси ──────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vs_vpn_NativeLib_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    server: JString,
    secret: JString,
    listen: JString,
) -> jint {
    let server: String = match env.get_string(&server) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let listen: String = match env.get_string(&listen) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let secret_str: Option<String> = if secret.is_null() {
        None
    } else {
        match env.get_string(&secret) {
            Ok(s) if !s.is_empty() => Some(s.into()),
            Ok(_) => None,
            Err(_) => return -1,
        }
    };

    let secret_key = parse_secret_opt(secret_str.as_deref());

    // Проверяем, что прокси ещё не запущен
    {
        let state = STATE.lock().unwrap();
        if state.is_some() {
            tracing::warn!("Proxy already running");
            return -2;
        }
    }

    // Очищаем лог-буфер для новой сессии
    log_buf().lock().unwrap().clear();
    tracing::info!(
        "Starting proxy: listen={}, server={}",
        listen,
        server
    );

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            if let Err(e) = vs_vpn::client::run(
                &listen,
                &server,
                secret_key,
                Some(ready_tx),
                shutdown_clone,
            )
            .await
            {
                tracing::error!("Proxy error: {e}");
            }
        });
    });

    // Ждём, пока прокси привяжется к порту (или упадёт с ошибкой)
    match ready_rx.blocking_recv() {
        Ok(addr) => {
            let port = addr.port();
            tracing::info!("Proxy bound to port {port}");

            let mut state = STATE.lock().unwrap();
            *state = Some(ProxyState { shutdown, handle });

            port as jint
        }
        Err(_) => {
            // Канал закрыт без сообщения — значит bind не удался
            tracing::error!("Proxy failed to bind");
            // Ждём завершения потока
            let _ = handle.join();
            -1
        }
    }
}

// ── JNI: остановка прокси ────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vs_vpn_NativeLib_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let mut state = STATE.lock().unwrap();
    match state.take() {
        Some(s) => {
            tracing::info!("Stopping proxy...");
            s.shutdown.cancel();
            // join с таймаутом 5 секунд
            let _ = s.handle.join();
            tracing::info!("Proxy stopped");
            jni::sys::JNI_TRUE
        }
        None => {
            tracing::warn!("Stop called but proxy not running");
            jni::sys::JNI_FALSE
        }
    }
}

// ── JNI: получение накопившихся логов ────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vs_vpn_NativeLib_nativePollLogs(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let mut lines = log_buf().lock().unwrap();
    let result: Vec<String> = lines.drain(..).collect();
    drop(lines);

    let output = result.join("\n");
    match env.new_string(&output) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
