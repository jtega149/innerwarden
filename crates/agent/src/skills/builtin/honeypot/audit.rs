//! Audit-trail helpers extracted from session.rs.
//!
//! Pure functions: transcript sanitisation, hex encoding, hashing,
//! protocol guessing, and preview truncation. The session code uses them
//! to record what the attacker did without keeping the raw bytes (which
//! may contain binary payloads or control sequences that corrupt logs).

use sha2::{Digest, Sha256};

/// Truncate a Unicode string to at most `max_chars` characters, appending
/// `"..."` when truncated. Counts characters, not bytes, so a string of
/// emoji won't be cut mid-codepoint.
pub(super) fn truncate_preview(value: &str, max_chars: usize) -> String {
    let mut out = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

/// Lowercase hex encoding of arbitrary bytes.
pub(super) fn bytes_to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// SHA-256 digest of `data`, as lowercase hex.
pub(super) fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    bytes_to_hex(digest.as_slice())
}

/// Convert a raw attacker transcript (arbitrary bytes) into a printable
/// preview. Whitespace escapes are spelled out, ASCII printable is kept,
/// everything else becomes `.`. Caps at `preview_limit` bytes so one rogue
/// megabyte upload can't produce a megabyte-long log entry.
pub(super) fn sanitize_transcript(data: &[u8], preview_limit: usize) -> String {
    let mut out = String::new();
    for &b in data.iter().take(preview_limit) {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push('.'),
        }
    }
    out
}

/// Cheap protocol fingerprinting from the first bytes the attacker sent.
///
/// Rules, in order:
/// * Empty → `"none"`.
/// * `SSH-` prefix → `"ssh"`.
/// * HTTP method prefix OR `HTTP/` substring in the window → `"http"`.
/// * ≥70% printable ASCII → `"text"`.
/// * Else → `"binary"`.
pub(super) fn guess_protocol(data: &[u8]) -> String {
    if data.is_empty() {
        return "none".to_string();
    }
    if data.starts_with(b"SSH-") {
        return "ssh".to_string();
    }
    if data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"HEAD ")
        || data.windows(5).any(|w| w == b"HTTP/")
    {
        return "http".to_string();
    }

    let printable = data
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7e | b'\r' | b'\n' | b'\t'))
        .count();
    if printable * 100 / data.len().max(1) >= 70 {
        "text".to_string()
    } else {
        "binary".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_preview_keeps_short_strings_unchanged() {
        assert_eq!(truncate_preview("abc", 10), "abc");
        assert_eq!(truncate_preview("", 10), "");
    }

    #[test]
    fn truncate_preview_caps_and_marks_long_strings() {
        assert_eq!(truncate_preview("abcdef", 3), "abc...");
    }

    #[test]
    fn truncate_preview_counts_chars_not_bytes() {
        assert_eq!(truncate_preview("🦀🦀🦀🦀", 2), "🦀🦀...");
    }

    #[test]
    fn bytes_to_hex_pads_to_two_chars_per_byte() {
        assert_eq!(bytes_to_hex(&[]), "");
        assert_eq!(bytes_to_hex(&[0x00]), "00");
        assert_eq!(bytes_to_hex(&[0xff]), "ff");
        assert_eq!(bytes_to_hex(&[0x0a, 0x1b, 0xfe]), "0a1bfe");
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sanitize_transcript_escapes_whitespace() {
        assert_eq!(
            sanitize_transcript(b"hello\r\nworld\t!", 100),
            "hello\\r\\nworld\\t!"
        );
    }

    #[test]
    fn sanitize_transcript_replaces_nonprintable_with_dot() {
        assert_eq!(sanitize_transcript(&[0x01, 0x02, 0xff, b'a'], 100), "...a");
    }

    #[test]
    fn sanitize_transcript_respects_preview_limit() {
        assert_eq!(sanitize_transcript(b"abcdefgh", 3), "abc");
    }

    #[test]
    fn guess_protocol_handles_known_shapes() {
        assert_eq!(guess_protocol(b""), "none");
        assert_eq!(guess_protocol(b"SSH-2.0-OpenSSH\r\n"), "ssh");
        assert_eq!(guess_protocol(b"GET /index.html HTTP/1.1"), "http");
        assert_eq!(guess_protocol(b"POST /login HTTP/1.1"), "http");
        assert_eq!(guess_protocol(b"HEAD /api HTTP/1.1"), "http");
    }

    #[test]
    fn guess_protocol_falls_back_to_text_or_binary() {
        assert_eq!(guess_protocol(b"hello world plain text"), "text");
        assert_eq!(
            guess_protocol(&[0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f, 0x03, 0x04, 0x05, 0x06]),
            "binary"
        );
    }

    #[test]
    fn guess_protocol_http_substring_beyond_method() {
        let mut buf = b"----HTTP/1.1 200".to_vec();
        buf.extend_from_slice(&[0u8; 10]);
        assert_eq!(guess_protocol(&buf), "http");
    }
}
