use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Non-destructive wrapper that replays peeked bytes before delegating reads to `inner`.
pub struct PrefixedStream<S> {
    prefix: Bytes,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeekedProtocol {
    Tls { sni: Option<String> },
    PlainHttp { host: Option<String> },
    Unknown,
}

pub fn inspect_first_bytes(data: &[u8]) -> PeekedProtocol {
    if is_tls_client_hello(data) {
        return PeekedProtocol::Tls {
            sni: parse_tls_client_hello_sni(data),
        };
    }
    if is_plain_http(data) {
        return PeekedProtocol::PlainHttp {
            host: parse_http_host_header(data),
        };
    }
    PeekedProtocol::Unknown
}

pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01
}

/// Pure-Rust TLS ClientHello SNI extension extractor.
pub fn parse_tls_client_hello_sni(data: &[u8]) -> Option<String> {
    if !is_tls_client_hello(data) {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let end = (5 + record_len).min(data.len());
    let mut pos = 5;

    // Handshake header: 1B type (0x01) + 3B length
    if pos + 4 > end {
        return None;
    }
    pos += 4;

    // ClientHello: 2B legacy_version + 32B random
    if pos + 34 > end {
        return None;
    }
    pos += 34;

    // Session ID: 1B len + bytes
    if pos + 1 > end {
        return None;
    }
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;

    // Cipher suites: 2B len + bytes
    if pos + 2 > end {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression methods: 1B len + bytes
    if pos + 1 > end {
        return None;
    }
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;

    // Extensions: 2B total len
    if pos + 2 > end {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(end);

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == 0x0000 {
            // server_name extension: 2B list_len + entries (1B type + 2B name_len + name)
            let mut epos = pos;
            if epos + 2 > pos + ext_len {
                return None;
            }
            let list_len = u16::from_be_bytes([data[epos], data[epos + 1]]) as usize;
            epos += 2;
            let list_end = (epos + list_len).min(pos + ext_len);
            while epos + 3 <= list_end {
                let name_type = data[epos];
                let name_len = u16::from_be_bytes([data[epos + 1], data[epos + 2]]) as usize;
                epos += 3;
                if epos + name_len > list_end {
                    break;
                }
                if name_type == 0x00 {
                    let s = std::str::from_utf8(&data[epos..epos + name_len]).ok()?;
                    return Some(s.trim_end_matches('.').to_ascii_lowercase());
                }
                epos += name_len;
            }
        }
        pos += ext_len;
    }
    None
}

fn is_plain_http(data: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"PATCH ",
        b"OPTIONS ",
    ];
    METHODS.iter().any(|m| data.starts_with(m))
}

fn parse_http_host_header(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                let host = v.trim();
                let without_port = host.split(':').next().unwrap_or(host);
                return Some(without_port.trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_from_synthetic_client_hello() {
        let hostname = b"api.github.com";
        let mut sni_ext = Vec::new();
        let entry_len = (1 + 2 + hostname.len()) as u16;
        sni_ext.extend_from_slice(&entry_len.to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(hostname);

        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&0x0000u16.to_be_bytes());
        ext_block.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len = body.len() as u32;
        hs.extend_from_slice(&[(hs_len >> 16) as u8, (hs_len >> 8) as u8, hs_len as u8]);
        hs.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        assert_eq!(
            parse_tls_client_hello_sni(&record).as_deref(),
            Some("api.github.com")
        );
    }
}
