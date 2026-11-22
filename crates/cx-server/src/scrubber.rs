use secrecy::{ExposeSecret, SecretString};

const REDACTED: &[u8] = b"[REDACTED]";

/// Defense-in-depth response scrubber: replaces any accidental upstream echo of real secrets.
pub fn scrub_bytes(input: &[u8], secrets: &[&SecretString]) -> Vec<u8> {
    let mut buf = input.to_vec();
    for secret in secrets {
        let needle = secret.expose_secret().as_bytes();
        if needle.len() < 6 {
            continue;
        }
        buf = replace_all_bytes(&buf, needle, REDACTED);
    }
    buf
}

pub fn scrub_headers(headers: &mut [(String, Vec<u8>)], secrets: &[&SecretString]) {
    for (_, val) in headers.iter_mut() {
        let scrubbed = scrub_bytes(val, secrets);
        if scrubbed.len() != val.len() || scrubbed != *val {
            *val = scrubbed;
        }
    }
}

fn replace_all_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i <= haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out.extend_from_slice(&haystack[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_echoed_secret_from_body() {
        let sec = SecretString::from("ghp_RealSuperSecretToken999".to_string());
        let body = b"echo: ghp_RealSuperSecretToken999 end";
        let scrubbed = scrub_bytes(body, &[&sec]);
        assert_eq!(scrubbed, b"echo: [REDACTED] end");
    }
}
