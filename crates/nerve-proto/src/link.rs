//! The center's base URL, the pairing link and the pairing request.
//!
//! Both are parsed by hand: they are small, and a strict parser that refuses user
//! info, queries and odd schemes is easier to reason about than a general one.

use std::fmt;

use serde::{Deserialize, Serialize};

/// `https://host[:port][/base]`, or `http://` for a center on the same machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CenterUrl {
    pub tls: bool,
    /// Host name or IP address, IPv6 without brackets.
    pub host: String,
    pub port: u16,
    /// Path prefix when the center is served below `/`, without a trailing slash.
    pub base: String,
}

impl CenterUrl {
    pub fn parse(s: &str) -> Result<CenterUrl, String> {
        let bad = |why: &str| format!("center URL {s:?}: {why}");
        let (tls, rest) = if let Some(r) = strip_prefix_ci(s, "https://") {
            (true, r)
        } else if let Some(r) = strip_prefix_ci(s, "http://") {
            (false, r)
        } else {
            return Err(bad(
                "must start with https:// (or http:// for a center on the same machine)",
            ));
        };
        if rest.contains(['?', '#']) {
            return Err(bad("no query or fragment allowed"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return Err(bad("no user name or password allowed"));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let end = v6.find(']').ok_or_else(|| bad("unclosed ["))?;
            let host = &v6[..end];
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(bad("bad IPv6 address"));
            }
            let after = &v6[end + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p),
                None if after.is_empty() => None,
                None => return Err(bad("junk after the IPv6 address")),
            };
            (host.to_string(), port)
        } else {
            let (h, p) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            if h.contains(':') {
                return Err(bad("an IPv6 address needs brackets"));
            }
            (h.to_ascii_lowercase(), p)
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
        {
            return Err(bad("bad host"));
        }
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| bad("bad port"))?,
            None if tls => 443,
            None => 80,
        };
        let base = path.trim_end_matches('/').to_string();
        // The URL is shown to the owner before pairing: a path with spaces,
        // quotes or other scripts could read as more text of the question.
        if !plain_path(&base) {
            return Err(bad(
                "the path may hold only letters, digits, - . _ ~ / and %XX escapes",
            ));
        }
        // Checked decoded: a server or proxy that decodes `%2e` or `%2f`
        // would otherwise resolve the endpoints outside the path shown.
        let decoded = pct_bytes(&base, false).ok_or_else(|| bad("bad escape in the path"))?;
        if decoded
            .split(|c| matches!(c, b'/' | b'\\'))
            .any(|c| c == b".." || c == b".")
        {
            return Err(bad("no . or .. in the path, escaped or not"));
        }
        Ok(CenterUrl {
            tls,
            host,
            port,
            base,
        })
    }

    /// `host[:port]` for the `Host` header, the port left out when it is the default.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The WebSocket URL of `path` (`/nerve/v0/connect`).
    pub fn ws(&self, path: &str) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!("{scheme}://{}{}{path}", self.authority(), self.base)
    }
}

impl fmt::Display for CenterUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.authority(), self.base)
    }
}

/// ASCII letters, digits, `-._~/` and `%` with two hex digits.
fn plain_path(p: &str) -> bool {
    let b = p.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if b
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) =>
            {
                i += 3
            }
            c if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~' | b'/') => {
                i += 1
            }
            _ => return false,
        }
    }
    true
}

/// `s` without `prefix`, matched ignoring ASCII case; `None` when it does not
/// start with it.
pub fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    // `get`: the prefix's length may end inside a character of `s`.
    match (s.get(..prefix.len()), s.get(prefix.len()..)) {
        (Some(head), Some(rest)) if head.eq_ignore_ascii_case(prefix) => Some(rest),
        _ => None,
    }
}

/// `nerve://pair?center=<url>&code=<code>[&pin=<spki pin>]`, as `pair new` and
/// the center's web UI show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairLink {
    pub center: CenterUrl,
    pub code: String,
    /// base64url (no padding) sha256 of the center certificate's
    /// SubjectPublicKeyInfo; `None` trusts the system roots.
    pub pin: Option<String>,
}

/// The longest pairing link a node reads.
pub const PAIR_LINK_BYTES: usize = 4096;

impl PairLink {
    pub fn parse(s: &str) -> Result<PairLink, String> {
        let s = s.trim();
        if s.len() > PAIR_LINK_BYTES {
            return Err("the pairing link is longer than 4 KiB".into());
        }
        // Windows hands a link from the browser or the shell over with an empty
        // path made `/` (`nerve://pair/?...`): that one form is taken too.
        let query = strip_prefix_ci(s, "nerve://pair?")
            .or_else(|| strip_prefix_ci(s, "nerve://pair/?"))
            .ok_or("a pairing link starts with nerve://pair?")?;
        if query.contains('#') {
            return Err("no fragment allowed in the pairing link".into());
        }
        let (mut center, mut code, mut pin) = (None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = pct_decode(v).ok_or_else(|| format!("bad escape in {k}"))?;
            let slot = match k {
                "center" => &mut center,
                "code" => &mut code,
                "pin" => &mut pin,
                // Unknown keys are refused rather than ignored: a link from a newer
                // center should fail loudly, not pair with half its meaning.
                _ => return Err(format!("unknown key {k:?} in the pairing link")),
            };
            if slot.replace(v).is_some() {
                return Err(format!("{k} given twice"));
            }
        }
        let center = CenterUrl::parse(&center.ok_or("the pairing link has no center")?)?;
        let code = code.ok_or("the pairing link has no code")?;
        if !valid_code(&code) {
            return Err("bad pairing code".into());
        }
        let pin = pin.filter(|p| !p.is_empty());
        if let Some(p) = &pin
            && !valid_pin(p)
        {
            return Err("bad pin: expected 43 base64url characters".into());
        }
        Ok(PairLink { center, code, pin })
    }

    /// The link's text form; `parse` reads it back.
    pub fn render(&self) -> String {
        let mut s = format!(
            "nerve://pair?center={}&code={}",
            pct_encode(&self.center.to_string()),
            self.code
        );
        if let Some(p) = &self.pin {
            s.push_str("&pin=");
            s.push_str(p);
        }
        s
    }
}

/// `nerve://relay?address=<host:port>&node=<name>&token=<token>&pin=<pin>`:
/// all a node needs to reach its centers through a relay, as `relay add`
/// and `relay token` on the relay show it, in one piece to paste
/// (docs/dev/node-link.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    /// Where the relayed node reaches the relay: a host name or address and
    /// the port, `relay.example:7490`, `[2001:db8::7]:7490`.
    pub address: String,
    /// The relayed node's name on the relay, its proxy login.
    pub node: String,
    /// Its token, the proxy password.
    pub token: String,
    /// The pin of the relay's certificate.
    pub pin: String,
}

impl RelayLink {
    pub fn parse(s: &str) -> Result<RelayLink, String> {
        let s = s.trim();
        if s.len() > PAIR_LINK_BYTES {
            return Err("the relay link is longer than 4 KiB".into());
        }
        let query = strip_prefix_ci(s, "nerve://relay?")
            .or_else(|| strip_prefix_ci(s, "nerve://relay/?"))
            .ok_or("a relay link starts with nerve://relay?")?;
        if query.contains('#') {
            return Err("no fragment allowed in the relay link".into());
        }
        let (mut address, mut node, mut token, mut pin) = (None, None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = pct_decode(v).ok_or_else(|| format!("bad escape in {k}"))?;
            let slot = match k {
                "address" => &mut address,
                "node" => &mut node,
                "token" => &mut token,
                "pin" => &mut pin,
                _ => return Err(format!("unknown key {k:?} in the relay link")),
            };
            if slot.replace(v).is_some() {
                return Err(format!("{k} given twice"));
            }
        }
        let address = address.ok_or("the relay link has no address")?;
        if !valid_host_port(&address) {
            return Err("the relay link's address is not host:port".into());
        }
        let node = node.ok_or("the relay link has no node")?;
        if !crate::valid_node_name(&node) {
            return Err("the relay link's node is not a node name".into());
        }
        let token = token.ok_or("the relay link has no token")?;
        if token.is_empty()
            || token.len() > 128
            || !token.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err("bad relay token".into());
        }
        let pin = pin.ok_or("the relay link has no pin")?;
        if !valid_pin(&pin) {
            return Err("bad pin: expected 43 base64url characters".into());
        }
        Ok(RelayLink {
            address,
            node,
            token,
            pin,
        })
    }

    /// The link's text form; `parse` reads it back.
    pub fn render(&self) -> String {
        format!(
            "nerve://relay?address={}&node={}&token={}&pin={}",
            pct_encode(&self.address),
            self.node,
            self.token,
            self.pin
        )
    }

    /// The proxy URL a relayed node sets (`proxy set`): the relay over TLS,
    /// the node's name and token as its login.
    pub fn proxy_url(&self) -> String {
        format!("https://{}:{}@{}", self.node, self.token, self.address)
    }
}

/// `host:port`, with an IPv6 address in brackets: what a relay link's
/// address may be.
pub fn valid_host_port(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let port_ok = port.parse::<u16>().is_ok_and(|p| p > 0);
    let host_ok = match host.strip_prefix('[') {
        Some(v6) => v6
            .strip_suffix(']')
            .is_some_and(|a| a.parse::<std::net::Ipv6Addr>().is_ok()),
        None => {
            !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        }
    };
    port_ok && host_ok
}

/// Pairing codes: 1 to 64 ASCII letters and digits.
pub fn valid_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 64 && code.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A SPKI pin: sha256 in base64url without padding, 43 characters.
pub fn valid_pin(p: &str) -> bool {
    p.len() == 43
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Escapes everything but unreserved characters.
pub fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn pct_decode(s: &str) -> Option<String> {
    String::from_utf8(pct_bytes(s, true)?).ok()
}

/// `s` with its `%XX` escapes decoded, and `+` as a space when `plus`.
fn pct_bytes(s: &str, plus: bool) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// `POST {center}/nerve/v0/pair` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub code: String,
    pub name: String,
    pub platform: String,
    pub arch: String,
    /// The node's Ed25519 public key for this center, lowercase hex.
    pub public_key: String,
}

/// The center's answer to a pairing request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairResponse {
    pub center_id: String,
    pub center_name: String,
    pub node_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// schemas/pair-request.schema.json says what the code takes: the fields
    /// of [`PairRequest`], all of them required and no other
    /// (`deny_unknown_fields`), a code as [`valid_code`] takes it and a name
    /// as [`crate::valid_node_name`] does.
    #[test]
    fn the_published_pair_request_schema_is_the_code_s() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/pair-request.schema.json"
        );
        let s: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let req = PairRequest {
            code: "a".into(),
            name: "n".into(),
            platform: "linux".into(),
            arch: "x86_64".into(),
            public_key: "0".repeat(64),
        };
        let mut fields: Vec<String> = serde_json::to_value(&req)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        fields.sort();
        let mut properties: Vec<String> = s["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        properties.sort();
        let mut required: Vec<String> = s["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        required.sort();
        assert_eq!(properties, fields);
        assert_eq!(required, fields);
        assert_eq!(s["additionalProperties"], false);
        let p = &s["properties"];
        assert_eq!(p["code"]["pattern"], "^[A-Za-z0-9]{1,64}$");
        assert!(valid_code(&"a".repeat(64)) && !valid_code(&"a".repeat(65)) && !valid_code("a-b"));
        assert_eq!(p["name"]["pattern"], "^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$");
        for (name, ok) in [
            ("a", true),
            ("a-b", true),
            ("-a", false),
            ("a-", false),
            ("A", false),
        ] {
            assert_eq!(crate::valid_node_name(name), ok, "{name}");
        }
        assert!(
            crate::valid_node_name(&"a".repeat(32)) && !crate::valid_node_name(&"a".repeat(33))
        );
        assert_eq!(p["public_key"]["pattern"], "^[0-9a-f]{64}$");
    }

    #[test]
    fn center_urls() {
        let u = CenterUrl::parse("HTTPS://Center.example:8443/nerve/").unwrap();
        assert_eq!(u.to_string(), "https://center.example:8443/nerve");
        assert_eq!(
            u.ws("/nerve/v0/connect"),
            "wss://center.example:8443/nerve/nerve/v0/connect"
        );
        assert_eq!(CenterUrl::parse("https://[::1]").unwrap().port, 443);
        for bad in [
            "ftp://x",
            "https://u@x",
            "https://x?q",
            "https://x#f",
            "https://x/%2e%2e/y",
            "https://x/a b",
            "https://x:0",
            "https://::1",
        ] {
            assert!(CenterUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pair_links() {
        let pin = "A".repeat(43);
        let s = format!("nerve://pair?center=https%3A%2F%2Fc.example%3A7443&code=abc123&pin={pin}");
        let l = PairLink::parse(&s).unwrap();
        assert_eq!(l.center.port, 7443);
        assert_eq!(l.pin.as_deref(), Some(pin.as_str()));
        assert_eq!(PairLink::parse(&l.render()).unwrap(), l);
        assert!(PairLink::parse("nerve://pair/?center=https%3A%2F%2Fc&code=a").is_ok());
        for bad in [
            "nerve://pair?center=https%3A%2F%2Fc&code=a&x=1",
            "nerve://pair?center=https%3A%2F%2Fc&code=a&code=b",
            "nerve://pair?center=https%3A%2F%2Fc&code=a%zz",
            "nerve://pair?center=https%3A%2F%2Fc&code=a-b",
            "nerve://pair?center=https%3A%2F%2Fc&code=a&pin=short",
            "nerve://pair?center=https%3A%2F%2Fc%2F..&code=a",
            "nerve://pair?code=a",
            "nerve://pair?center=https%3A%2F%2Fc&code=a#frag",
            "other-app://pair?portal=x",
        ] {
            assert!(PairLink::parse(bad).is_err(), "{bad}");
        }
        let long = format!(
            "nerve://pair?center=https%3A%2F%2Fc&code=a&{}",
            "x".repeat(5000)
        );
        assert!(PairLink::parse(&long).unwrap_err().contains("4 KiB"));
    }

    #[test]
    fn relay_links() {
        let pin = "q".repeat(43);
        let l = RelayLink {
            address: "[2001:db8::7]:7490".into(),
            node: "lab-pc".into(),
            token: "abc123".into(),
            pin: pin.clone(),
        };
        let text = l.render();
        assert!(text.starts_with("nerve://relay?address=%5B2001%3Adb8%3A%3A7%5D%3A7490&"));
        assert_eq!(RelayLink::parse(&text).unwrap(), l);
        assert_eq!(l.proxy_url(), "https://lab-pc:abc123@[2001:db8::7]:7490");
        let ok =
            format!("nerve://relay?address=relay.example:7490&node=lab-pc&token=t0k&pin={pin}");
        assert_eq!(RelayLink::parse(&ok).unwrap().address, "relay.example:7490");
        for bad in [
            format!("nerve://relay?address=relay.example&node=lab-pc&token=t&pin={pin}"),
            format!("nerve://relay?address=a@b:1&node=lab-pc&token=t&pin={pin}"),
            format!("nerve://relay?address=r:7490&node=Lab&token=t&pin={pin}"),
            format!("nerve://relay?address=r:7490&node=lab&token=t-t&pin={pin}"),
            "nerve://relay?address=r:7490&node=lab&token=t&pin=short".into(),
            format!("nerve://relay?address=r:7490&node=lab&token=t&pin={pin}&x=1"),
            format!("nerve://relay?address=r:7490&node=lab&pin={pin}"),
            format!("nerve://pair?address=r:7490&node=lab&token=t&pin={pin}"),
        ] {
            assert!(RelayLink::parse(&bad).is_err(), "{bad}");
        }
    }
}
