//! The node's Ed25519 key per center, its node id, and the connect signature
//! (docs/dev/spec/protocol.md §2 and §4.2); and the secret key of the MAC the node keeps
//! over its own config file ([`MacKey`]).
//!
//! Where the node keeps these keys (a 0600 file, or the system keyring with
//! `machine.secret_storage = "keyring"`) is the node's business; this module
//! reads and writes their text and, for the MAC key, its file.

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use nerve_proto::msg::{hex, unhex};

pub struct NodeKey {
    pair: Ed25519KeyPair,
    pkcs8: Vec<u8>,
}

impl NodeKey {
    pub fn generate() -> Result<NodeKey, String> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "cannot generate a key".to_string())?;
        NodeKey::from_pkcs8(pkcs8.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<NodeKey, String> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| "the node key file is not an Ed25519 key".to_string())?;
        Ok(NodeKey {
            pair,
            pkcs8: pkcs8.to_vec(),
        })
    }

    /// The key as stored: PKCS#8, hex encoded, one line.
    pub fn to_text(&self) -> String {
        hex(&self.pkcs8) + "\n"
    }

    pub fn from_text(s: &str) -> Result<NodeKey, String> {
        let raw = unhex(s.trim()).ok_or("the node key file is not hex")?;
        NodeKey::from_pkcs8(&raw)
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    pub fn public_hex(&self) -> String {
        hex(&self.public_key())
    }

    pub fn node_id(&self) -> String {
        node_id(&self.public_key())
    }

    /// The `auth.sig` of `hello`: hex Ed25519 over the connect message.
    pub fn sign_connect(&self, center_id: &str, nonce: &[u8]) -> String {
        hex(self
            .pair
            .sign(&nerve_proto::connect_message(center_id, nonce))
            .as_ref())
    }

    /// The `sig` of a `settings.sudo-offer` result: hex Ed25519 over
    /// [`crate::sudo::Offer::message`].
    pub fn sign_sudo_offer(&self, center_id: &str, offer: &crate::sudo::Offer) -> String {
        hex(self.pair.sign(&offer.message(center_id)).as_ref())
    }

    /// A signature of `key.rotate` (spec §4.10): hex Ed25519 over the rotate
    /// message for `new_key`. The key it replaces makes `sig`, the new key
    /// itself `proof`.
    pub fn sign_rotate(&self, center_id: &str, new_key: &[u8]) -> String {
        hex(self
            .pair
            .sign(&nerve_proto::rotate_node_message(center_id, new_key))
            .as_ref())
    }

    /// The `sig` of `key.retire`: hex Ed25519 over the retire message for
    /// this key.
    pub fn sign_retire(&self, center_id: &str) -> String {
        hex(self
            .pair
            .sign(&nerve_proto::retire_node_message(
                center_id,
                &self.public_key(),
            ))
            .as_ref())
    }
}

/// Checks a signature (hex) by the node key `public_hex` over `message`.
pub fn verify_node_signature(public_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    let (Some(pk), Some(sig)) = (unhex(public_hex), unhex(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(message, &sig)
        .is_ok()
}

/// A node id: base32 of the first 16 bytes of sha256 of the public key.
pub fn node_id(public_key: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, public_key);
    nerve_proto::base32::encode(&d.as_ref()[..16])
}

/// Checks a sudo offer's signature against a node's stored public key (hex).
pub fn verify_sudo_offer(
    public_hex: &str,
    center_id: &str,
    offer: &crate::sudo::Offer,
    sig_hex: &str,
) -> bool {
    let (Some(pk), Some(sig)) = (unhex(public_hex), unhex(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(&offer.message(center_id), &sig)
        .is_ok()
}

/// Checks a `hello` signature against a node's stored public key (hex).
pub fn verify_connect(public_hex: &str, center_id: &str, nonce: &[u8], sig_hex: &str) -> bool {
    let (Some(pk), Some(sig)) = (unhex(public_hex), unhex(sig_hex)) else {
        return false;
    };
    UnparsedPublicKey::new(&ED25519, pk)
        .verify(&nerve_proto::connect_message(center_id, nonce), &sig)
        .is_ok()
}

/// The node's secret for the MAC over its own config file (HMAC-SHA256).
/// Whoever can read it can sign a config the node accepts, so it lives in a
/// 0600 file in a folder no command of a center may reach.
pub struct MacKey(ring::hmac::Key);

impl MacKey {
    /// The key at `path`; `None` when there is none yet.
    pub fn load(path: &std::path::Path) -> Result<Option<MacKey>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        MacKey::from_text(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The key from its stored text: 32 bytes, hex. The error does not
    /// quote the text.
    pub fn from_text(text: &str) -> Result<MacKey, String> {
        let raw = unhex(text.trim())
            .filter(|r| r.len() == 32)
            .ok_or("not a 32-byte hex key")?;
        Ok(MacKey(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &raw)))
    }

    /// A new random key and its text, for a place other than a file.
    pub fn generate() -> (MacKey, String) {
        let raw = random_bytes(32);
        (
            MacKey(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &raw)),
            hex(&raw),
        )
    }

    /// The key at `path`, made and written there first when there is none.
    /// An existing key is never replaced: it would turn every file it signed
    /// into one the node refuses.
    pub fn load_or_create(path: &std::path::Path) -> Result<MacKey, String> {
        if let Some(k) = MacKey::load(path)? {
            return Ok(k);
        }
        let raw = random_bytes(32);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("key");
        let tmp = path.with_file_name(format!(".{name}.{}.new", random_token(8)));
        crate::files::write_private(&tmp, (hex(&raw) + "\n").as_bytes())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        // A hard link fails when the name exists, so two processes that both
        // found no key end up with the same one.
        let linked = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(MacKey(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &raw))),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                MacKey::load(path)?.ok_or_else(|| format!("{}: the key vanished", path.display()))
            }
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// The MAC over `data`, hex.
    pub fn sign(&self, data: &[u8]) -> String {
        hex(ring::hmac::sign(&self.0, data).as_ref())
    }

    /// Whether `mac_hex` is the MAC over `data` (compared in constant time).
    pub fn verify(&self, data: &[u8], mac_hex: &str) -> bool {
        unhex(mac_hex).is_some_and(|m| ring::hmac::verify(&self.0, data, &m).is_ok())
    }
}

/// `n` random bytes from the system.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; n];
    // A failing system RNG leaves nothing sensible to do but stop.
    SystemRandom::new()
        .fill(&mut b)
        .expect("the system random generator failed");
    b
}

/// A random token of `n` characters from `a-z0-9` (pairing codes, harness
/// tokens), drawn without modulo bias.
pub fn random_token(n: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    while out.len() < n {
        for b in random_bytes(n) {
            // 252 = 7 * 36: bytes at or above it would favour the first letters.
            if b < 252 && out.len() < n {
                out.push(A[(b % 36) as usize] as char);
            }
        }
    }
    out
}

/// Compares two byte strings in time that depends only on their lengths:
/// for tokens, codes and their hashes.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The SHA-256 of `data` in lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_bytes_compare_equal_and_no_others() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sudo_offers_are_signed_for_one_center() {
        let k = NodeKey::generate().unwrap();
        let p = crate::sudo::Pending::new(5).unwrap();
        let sig = k.sign_sudo_offer("c1", p.offer());
        assert!(verify_sudo_offer(&k.public_hex(), "c1", p.offer(), &sig));
        assert!(!verify_sudo_offer(&k.public_hex(), "c2", p.offer(), &sig));
        let mut other = p.offer().clone();
        other.ts += 1;
        assert!(!verify_sudo_offer(&k.public_hex(), "c1", &other, &sig));
    }

    #[test]
    fn rotations_are_signed_for_one_center_and_one_key() {
        let (old, new) = (NodeKey::generate().unwrap(), NodeKey::generate().unwrap());
        let msg = |c: &str, k: &NodeKey| nerve_proto::rotate_node_message(c, &k.public_key());
        let sig = old.sign_rotate("c1", &new.public_key());
        assert!(verify_node_signature(
            &old.public_hex(),
            &msg("c1", &new),
            &sig
        ));
        // Not for another center, another new key, or under another key.
        assert!(!verify_node_signature(
            &old.public_hex(),
            &msg("c2", &new),
            &sig
        ));
        assert!(!verify_node_signature(
            &old.public_hex(),
            &msg("c1", &old),
            &sig
        ));
        assert!(!verify_node_signature(
            &new.public_hex(),
            &msg("c1", &new),
            &sig
        ));
        // A retire signature is no rotate signature.
        let retire = new.sign_retire("c1");
        let retire_msg = nerve_proto::retire_node_message("c1", &new.public_key());
        assert!(verify_node_signature(
            &new.public_hex(),
            &retire_msg,
            &retire
        ));
        assert!(!verify_node_signature(
            &new.public_hex(),
            &nerve_proto::rotate_node_message("c1", &new.public_key()),
            &retire
        ));
        assert!(!verify_node_signature("zz", &retire_msg, &retire));
    }

    #[test]
    fn sign_and_verify() {
        let k = NodeKey::generate().unwrap();
        let back = NodeKey::from_text(&k.to_text()).unwrap();
        assert_eq!(back.public_key(), k.public_key());
        assert_eq!(k.node_id().len(), 26);
        let nonce = random_bytes(32);
        let sig = k.sign_connect("c1", &nonce);
        assert!(verify_connect(&k.public_hex(), "c1", &nonce, &sig));
        assert!(!verify_connect(&k.public_hex(), "c2", &nonce, &sig));
        let other = NodeKey::generate().unwrap();
        assert!(!verify_connect(&other.public_hex(), "c1", &nonce, &sig));
        assert!(!verify_connect("zz", "c1", &nonce, &sig));
        assert!(NodeKey::from_text("abcd").is_err());
    }

    #[test]
    fn mac_keys_are_made_once_and_verify_only_their_own_macs() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("state/config.key");
        assert!(MacKey::load(&path).unwrap().is_none());
        let k = MacKey::load_or_create(&path).unwrap();
        let mac = k.sign(b"node.toml");
        // Made once: a second call reads the same key back.
        let again = MacKey::load_or_create(&path).unwrap();
        assert!(again.verify(b"node.toml", &mac));
        assert!(!again.verify(b"node.toml!", &mac));
        assert!(!again.verify(b"node.toml", "zz"));
        let other = MacKey::load_or_create(&d.path().join("other.key")).unwrap();
        assert!(!other.verify(b"node.toml", &mac));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Only the key is left in its folder.
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
        std::fs::write(&path, "abcd\n").unwrap();
        assert!(MacKey::load(&path).is_err());
    }

    #[test]
    fn mac_keys_round_trip_through_their_text() {
        let (k, text) = MacKey::generate();
        let mac = k.sign(b"node.toml");
        let back = MacKey::from_text(&format!("{text}\n")).unwrap();
        assert!(back.verify(b"node.toml", &mac));
        assert_ne!(MacKey::generate().1, text);
        // The error names no part of what it was given.
        let err = MacKey::from_text("secret-ish").err().unwrap();
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn tokens() {
        let t = random_token(20);
        assert_eq!(t.len(), 20);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert_ne!(random_token(20), t);
    }
}
