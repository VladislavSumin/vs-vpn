use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT: usize = u16::MAX as usize - TAG_LEN;
pub const RELAY_BUF: usize = 16384;

const HKDF_INFO: &[u8] = b"vs-vpn-tunnel-v1";

pub fn generate_psk() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill_bytes(&mut key);
    key
}

fn io_err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

fn derive_session_keys(
    psk: &[u8; KEY_LEN],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> io::Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let hk = Hkdf::<Sha256>::new(None, psk);
    let mut okm = [0u8; 64];
    let mut info = Vec::from(HKDF_INFO);
    info.extend_from_slice(client_nonce);
    info.extend_from_slice(server_nonce);
    hk.expand(&info, &mut okm)
        .map_err(|e| io_err(format!("HKDF expand: {e}")))?;
    let mut ck = [0u8; KEY_LEN];
    let mut sk = [0u8; KEY_LEN];
    ck.copy_from_slice(&okm[..KEY_LEN]);
    sk.copy_from_slice(&okm[KEY_LEN..]);
    Ok((ck, sk))
}

pub async fn secure_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    psk: &[u8; KEY_LEN],
    is_client: bool,
) -> io::Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let mut client_nonce = [0u8; KEY_LEN];
    let mut server_nonce = [0u8; KEY_LEN];

    if is_client {
        rand::rng().fill_bytes(&mut client_nonce);
        stream.write_all(&client_nonce).await?;
        stream.read_exact(&mut server_nonce).await?;
    } else {
        stream.read_exact(&mut client_nonce).await?;
        rand::rng().fill_bytes(&mut server_nonce);
        stream.write_all(&server_nonce).await?;
    }

    derive_session_keys(psk, &client_nonce, &server_nonce)
}

pub async fn write_encrypted_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce_counter: &mut u64,
) -> io::Result<()> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(io_err(format!(
            "plaintext too large: {} bytes (max {})",
            plaintext.len(),
            MAX_PLAINTEXT
        )));
    }

    let mut full_nonce = [0u8; NONCE_LEN];
    full_nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| io_err(format!("invalid key: {e}")))?;
    let ciphertext = cipher
        .encrypt(&full_nonce.into(), plaintext)
        .map_err(|e| io_err(format!("encryption error (nonce={nonce_counter}): {e}")))?;

    let frame_len = ciphertext.len() as u16;
    writer.write_all(&frame_len.to_be_bytes()).await?;
    writer.write_all(&ciphertext).await?;

    *nonce_counter += 1;
    Ok(())
}

pub async fn read_encrypted_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: &[u8; KEY_LEN],
    nonce_counter: &mut u64,
) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let frame_len = u16::from_be_bytes(len_buf) as usize;

    if frame_len < TAG_LEN {
        return Err(io_err(format!("frame too short: {} bytes", frame_len)));
    }

    let mut ciphertext = vec![0u8; frame_len];
    reader.read_exact(&mut ciphertext).await?;

    let mut full_nonce = [0u8; NONCE_LEN];
    full_nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| io_err(format!("invalid key: {e}")))?;
    let plaintext = cipher
        .decrypt(&full_nonce.into(), ciphertext.as_slice())
        .map_err(|e| io_err(format!("decryption error (nonce={nonce_counter}): {e}")))?;

    *nonce_counter += 1;
    Ok(Some(plaintext))
}

pub async fn relay_plain_to_encrypted<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; KEY_LEN],
    nonce: &mut u64,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("operation=read: {e}")))?;
        if n == 0 {
            break Ok(());
        }
        write_encrypted_frame(writer, &buf[..n], key, nonce)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("operation=write: {e}")))?;
    }
}

pub async fn relay_encrypted_to_plain<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    key: &[u8; KEY_LEN],
    nonce: &mut u64,
) -> io::Result<()> {
    loop {
        let frame = read_encrypted_frame(reader, key, nonce)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("operation=read: {e}")))?;
        match frame {
            Some(plain) => writer
                .write_all(&plain)
                .await
                .map_err(|e| io::Error::new(e.kind(), format!("operation=write: {e}")))?,
            None => break Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    #[test]
    fn test_generate_psk_length() {
        let psk = generate_psk();
        assert_eq!(psk.len(), KEY_LEN);
    }

    #[test]
    fn test_generate_psk_random() {
        let psk1 = generate_psk();
        let psk2 = generate_psk();
        assert_ne!(psk1, psk2);
    }

    #[test]
    fn test_derive_session_keys_different() {
        let psk = generate_psk();
        let client_nonce = [0xAAu8; KEY_LEN];
        let server_nonce = [0x55u8; KEY_LEN];
        let (ck, sk) = derive_session_keys(&psk, &client_nonce, &server_nonce).unwrap();
        assert_ne!(ck, sk);
        assert_eq!(ck.len(), KEY_LEN);
        assert_eq!(sk.len(), KEY_LEN);
    }

    #[test]
    fn test_derive_session_keys_deterministic() {
        let psk = [0x42u8; KEY_LEN];
        let cn = [0x01u8; KEY_LEN];
        let sn = [0x02u8; KEY_LEN];
        let (ck1, sk1) = derive_session_keys(&psk, &cn, &sn).unwrap();
        let (ck2, sk2) = derive_session_keys(&psk, &cn, &sn).unwrap();
        assert_eq!(ck1, ck2);
        assert_eq!(sk1, sk2);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let psk = generate_psk();
        let (ck, _sk) = derive_session_keys(&psk, &[0u8; KEY_LEN], &[0u8; KEY_LEN]).unwrap();

        let (mut writer, mut reader) = duplex(4096);

        let plaintext = b"Hello, secure tunnel!";
        let mut nonce: u64 = 0;
        write_encrypted_frame(&mut writer, plaintext, &ck, &mut nonce)
            .await
            .unwrap();

        let decrypted = read_encrypted_frame(&mut reader, &ck, &mut 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_empty_plaintext() {
        let psk = generate_psk();
        let (ck, _sk) = derive_session_keys(&psk, &[0u8; KEY_LEN], &[0u8; KEY_LEN]).unwrap();

        let (mut writer, mut reader) = duplex(4096);

        let mut nonce: u64 = 0;
        write_encrypted_frame(&mut writer, b"", &ck, &mut nonce)
            .await
            .unwrap();

        let decrypted = read_encrypted_frame(&mut reader, &ck, &mut 0)
            .await
            .unwrap()
            .unwrap();
        assert!(decrypted.is_empty());
    }

    #[tokio::test]
    async fn test_multiple_frames_nonce_progression() {
        let psk = generate_psk();
        let (ck, _sk) = derive_session_keys(&psk, &[0u8; KEY_LEN], &[0u8; KEY_LEN]).unwrap();

        let (mut writer, mut reader) = duplex(65536);

        let messages: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("message {i}").into_bytes())
            .collect();
        let msg_count = messages.len();
        let messages_clone = messages.clone();

        let write_task = {
            tokio::spawn(async move {
                let mut nonce: u64 = 0;
                for msg in &messages_clone {
                    write_encrypted_frame(&mut writer, msg, &ck, &mut nonce)
                        .await
                        .unwrap();
                }
            })
        };

        let mut received = Vec::new();
        let mut read_nonce: u64 = 0;
        for _ in 0..msg_count {
            let plain = read_encrypted_frame(&mut reader, &ck, &mut read_nonce)
                .await
                .unwrap()
                .unwrap();
            received.push(plain);
        }

        write_task.await.unwrap();
        assert_eq!(received, messages);
    }

    #[tokio::test]
    async fn test_secure_handshake_both_sides() {
        let psk = generate_psk();
        let (mut client_stream, mut server_stream) = duplex(4096);

        let (client_result, server_result) = tokio::join!(
            secure_handshake(&mut client_stream, &psk, true),
            secure_handshake(&mut server_stream, &psk, false),
        );

        let (ck_client, sk_client) = client_result.unwrap();
        let (ck_server, sk_server) = server_result.unwrap();

        // Ключи должны совпадать: клиент и сервер вычисляют одинаковые пары
        assert_eq!(ck_client, ck_server);
        assert_eq!(sk_client, sk_server);
        assert_ne!(ck_client, sk_client);
    }

    #[tokio::test]
    async fn test_read_frame_eof() {
        let (mut reader, writer) = duplex(64);
        drop(writer); // закрываем писателя — читатель получает EOF

        let key = [0u8; KEY_LEN];
        let result = read_encrypted_frame(&mut reader, &key, &mut 0)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_write_frame_too_large() {
        let (mut writer, _reader) = duplex(65536);
        let key = [0u8; KEY_LEN];
        let huge = vec![0u8; MAX_PLAINTEXT + 1];
        let result = write_encrypted_frame(&mut writer, &huge, &key, &mut 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_frame_too_short() {
        let (mut reader, mut writer) = duplex(64);
        let key = [0u8; KEY_LEN];
        // Записываем длину фрейма меньше TAG_LEN
        let short_len = (TAG_LEN - 1) as u16;
        writer.write_all(&short_len.to_be_bytes()).await.unwrap();
        let result = read_encrypted_frame(&mut reader, &key, &mut 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_with_wrong_key() {
        let psk = generate_psk();
        let (ck, _sk) = derive_session_keys(&psk, &[0u8; KEY_LEN], &[0u8; KEY_LEN]).unwrap();
        let wrong_key = [0xFFu8; KEY_LEN];

        let (mut writer, mut reader) = duplex(4096);

        let mut nonce: u64 = 0;
        write_encrypted_frame(&mut writer, b"secret", &ck, &mut nonce)
            .await
            .unwrap();

        let result = read_encrypted_frame(&mut reader, &wrong_key, &mut 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secure_handshake_then_encrypted_exchange() {
        let psk = generate_psk();
        let (mut client_stream, mut server_stream) = duplex(8192);

        let client_task = async {
            let (ck, sk) = secure_handshake(&mut client_stream, &psk, true)
                .await
                .unwrap();

            // Клиент шифрует и отправляет
            let mut nonce: u64 = 0;
            write_encrypted_frame(&mut client_stream, b"ping", &ck, &mut nonce)
                .await
                .unwrap();

            // Клиент читает ответ
            let reply = read_encrypted_frame(&mut client_stream, &sk, &mut 0)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"pong");

            (ck, sk)
        };

        let server_task = async {
            let (ck, sk) = secure_handshake(&mut server_stream, &psk, false)
                .await
                .unwrap();

            // Сервер читает запрос
            let req = read_encrypted_frame(&mut server_stream, &ck, &mut 0)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(req, b"ping");

            // Сервер шифрует и отправляет ответ
            let mut nonce: u64 = 0;
            write_encrypted_frame(&mut server_stream, b"pong", &sk, &mut nonce)
                .await
                .unwrap();

            (ck, sk)
        };

        let ((cck, csk), (sck, ssk)) = tokio::join!(client_task, server_task);

        assert_eq!(cck, sck);
        assert_eq!(csk, ssk);
        assert_ne!(cck, csk);
    }
}
