use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT: usize = u16::MAX as usize - NONCE_LEN - TAG_LEN;
pub const RELAY_BUF: usize = 16384;

const HKDF_INFO: &[u8] = b"vs-vpn-tunnel-v1";

pub fn generate_psk() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);
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
        rand::rngs::OsRng.fill_bytes(&mut client_nonce);
        stream.write_all(&client_nonce).await?;
        stream.read_exact(&mut server_nonce).await?;
    } else {
        stream.read_exact(&mut client_nonce).await?;
        rand::rngs::OsRng.fill_bytes(&mut server_nonce);
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
        .map_err(|e| io_err(format!("encryption error: {e}")))?;

    let frame_len = (NONCE_LEN + ciphertext.len()) as u16;
    writer.write_all(&frame_len.to_be_bytes()).await?;
    writer.write_all(&full_nonce).await?;
    writer.write_all(&ciphertext).await?;

    *nonce_counter += 1;
    Ok(())
}

pub async fn read_encrypted_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: &[u8; KEY_LEN],
) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let frame_len = u16::from_be_bytes(len_buf) as usize;

    if frame_len < NONCE_LEN + TAG_LEN {
        return Err(io_err(format!("frame too short: {} bytes", frame_len)));
    }

    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;

    let nonce = &payload[..NONCE_LEN];
    let ciphertext = &payload[NONCE_LEN..];

    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|e| io_err(format!("invalid key: {e}")))?;
    let plaintext = cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|e| io_err(format!("decryption error: {e}")))?;

    Ok(Some(plaintext))
}
