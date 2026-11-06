//! Key rotation (docs/dev/spec/protocol.md §4.10): the node's key for a
//! center, which the owner rotates here (`nerve-node center rotate-key`),
//! and the center's key, which the center rotates and tells the node of
//! over the link (`center.rotate`).
//!
//! The node's new key is kept aside before it is sent, so a rotation the
//! center took is never lost with the process. It becomes the node's key
//! only once the center answered that it took it. A refusal drops it; no
//! answer keeps it, and the next link sends it again. Until then the node
//! signs with its old key, which the center takes either way.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use nerve_policy::config::SecretStorage;
use nerve_policy::{CenterEntry, OldPin};
use nerve_proto::ROTATE_GRACE_MS;
use nerve_proto::msg::{CenterRotate, KeyRetire, KeyRetired, KeyRotate, KeyRotated, method};
use nerve_proto::rpc::{Message, params};
use nerve_transport::keys::NodeKey;
use nerve_transport::log::span;

use crate::daemon::{LinkHandle, Shared};

/// How long the node waits for the center's answer.
pub(crate) const ANSWER: Duration = Duration::from_secs(15);

/// The grace in words, for messages.
fn grace() -> String {
    span(Duration::from_millis(ROTATE_GRACE_MS))
}

/// `center rotate-key`: makes a new key for `center` and has the center take
/// it in place of the old one. A rotation that got no answer before is sent
/// again with the key it made then.
pub(crate) async fn rotate(shared: &Arc<Shared>, center: &str) -> Result<Value, String> {
    let (storage, entry) = entry(shared, center)?;
    let cs = shared.center(center);
    let _one = cs.rotating.lock().await;
    let link = linked(shared, center)?;
    let (current, next) = keys(shared, storage, center).await?;
    let (next, resumed) = match next {
        Some(k) => (k, true),
        None => {
            let k = NodeKey::generate()?;
            let (paths, name) = (shared.paths.clone(), center.to_string());
            let k = tokio::task::spawn_blocking(move || {
                crate::secrets::store_center_next_key(&paths, storage, &name, &k).map(|()| k)
            })
            .await
            .map_err(|e| format!("keeping the new key stopped: {e}"))?
            .map_err(|e| format!("{e}; nothing was changed"))?;
            (k, false)
        }
    };
    let mut out = send(shared, &entry, storage, &link, &current, next).await?;
    out["resumed"] = json!(resumed);
    Ok(out)
}

/// `center rotate-key --end-grace`: the center stops taking the node's old
/// key now instead of at the end of the grace.
pub(crate) async fn end_grace(shared: &Arc<Shared>, center: &str) -> Result<Value, String> {
    let (storage, entry) = entry(shared, center)?;
    let cs = shared.center(center);
    let _one = cs.rotating.lock().await;
    let link = linked(shared, center)?;
    let (current, next) = keys(shared, storage, center).await?;
    if next.is_some() {
        return Err(format!(
            "the rotation of the key for center {center} has not heard back from the center yet; run `nerve-node center rotate-key {center}` first, which sends it again"
        ));
    }
    let retire = KeyRetire {
        public_key: current.public_hex(),
        sig: current.sign_retire(&entry.center_id),
    };
    let reply: Option<KeyRetired> = ask(
        &link,
        method::KEY_RETIRE,
        json!(retire),
        method::KEY_RETIRED,
    )
    .await;
    match reply {
        None => Err(format!(
            "center {center} did not answer within {}; its grace for the old key may still run",
            span(ANSWER)
        )),
        Some(KeyRetired { error: Some(e) }) => Err(format!(
            "center {center} did not end the grace of the old key: {}",
            clip(&e)
        )),
        Some(KeyRetired { error: None }) => {
            tracing::info!(
                "center {center} no longer takes this node's old key: the owner ended its grace"
            );
            shared.audit_key(
                center,
                "node-key-grace-ended",
                &format!(
                    "the center takes only the key {} from now on",
                    current.public_hex()
                ),
            );
            Ok(json!({"center": center, "public_key": current.public_hex()}))
        }
    }
}

/// Sends the rotation of a new link again when the last one got no answer.
pub(crate) async fn resume(shared: Arc<Shared>, center: String) {
    let cs = shared.center(&center);
    let _one = cs.rotating.lock().await;
    let (Ok((storage, entry)), Ok(link)) = (entry(&shared, &center), linked(&shared, &center))
    else {
        return;
    };
    match keys(&shared, storage, &center).await {
        Ok((current, Some(next))) => {
            tracing::info!(
                "center {center}: sending the rotation of this node's key again, which got no answer before"
            );
            if let Err(e) = send(&shared, &entry, storage, &link, &current, next).await {
                tracing::warn!("center {center}: {e}");
            }
        }
        Ok((_, None)) => {}
        Err(e) => tracing::warn!("center {center}: the key rotation cannot go on: {e}"),
    }
}

/// The center's entry and where the node keeps its keys.
fn entry(shared: &Shared, center: &str) -> Result<(SecretStorage, CenterEntry), String> {
    let cfg = shared.config();
    let e = cfg
        .center(center)
        .cloned()
        .ok_or_else(|| crate::folder_change::no_center_named(&cfg, center))?;
    Ok((cfg.machine.secret_storage, e))
}

/// The live link to `center`.
fn linked(shared: &Shared, center: &str) -> Result<Arc<LinkHandle>, String> {
    shared.center(center).link().ok_or_else(|| {
        format!(
            "the node has no link to center {center} now, and a key rotation goes over it; nothing was changed. Try again once `nerve-node status` shows the center connected"
        )
    })
}

/// The node's key for `center` and the new one of a rotation under way.
async fn keys(
    shared: &Shared,
    storage: SecretStorage,
    center: &str,
) -> Result<(NodeKey, Option<NodeKey>), String> {
    let (paths, name) = (shared.paths.clone(), center.to_string());
    // The keyring may block (the Secret Service asks to unlock).
    tokio::task::spawn_blocking(move || {
        Ok((
            crate::secrets::center_key(&paths, storage, &name)?,
            crate::secrets::center_next_key(&paths, storage, &name)?,
        ))
    })
    .await
    .map_err(|e| format!("the key read stopped: {e}"))?
}

/// Sends `method` with `p` and waits for the center's `answer`; `None` when
/// none came in time, the link ended, or it cannot be read.
async fn ask<T: serde::de::DeserializeOwned>(
    link: &LinkHandle,
    method: &str,
    p: Value,
    answer: &'static str,
) -> Option<T> {
    let rx = link.expect(answer);
    // A counted frame: on a link that drops and resumes it goes out again.
    link.send(Message::notification(method, p).encode()).await;
    let got: Map<String, Value> = tokio::time::timeout(ANSWER, rx).await.ok()?.ok()?;
    params::<T>(&got).ok()
}

/// Sends `key.rotate` for `next` and acts on the answer.
async fn send(
    shared: &Shared,
    entry: &CenterEntry,
    storage: SecretStorage,
    link: &LinkHandle,
    current: &NodeKey,
    next: NodeKey,
) -> Result<Value, String> {
    let center = entry.name.as_str();
    let new_hex = next.public_hex();
    let rotate = KeyRotate {
        public_key: new_hex.clone(),
        sig: current.sign_rotate(&entry.center_id, &next.public_key()),
        proof: next.sign_rotate(&entry.center_id, &next.public_key()),
    };
    let reply: Option<KeyRotated> =
        ask(link, method::KEY_ROTATE, json!(rotate), method::KEY_ROTATED).await;
    let reply = match reply {
        Some(r) if r.public_key == new_hex => r,
        // No answer, or one about another key: the center may have taken it
        // all the same, so the new key stays aside for the next link.
        _ => {
            shared.audit_key(
                center,
                "node-key-unanswered",
                &format!(
                    "the new key {new_hex} was sent, but no answer came; the old key {} stays in use and the rotation is sent again on the next link",
                    current.public_hex()
                ),
            );
            return Err(format!(
                "center {center} did not answer the key rotation within {}; the old key stays in use, and the new key is kept: the node sends it again on its next link, or run this command again",
                span(ANSWER)
            ));
        }
    };
    settle(
        shared,
        center,
        storage,
        &current.public_hex(),
        next,
        reply.error,
    )
    .await
}

/// Acts on the center's answer about `next`: `error` drops it, else it
/// becomes the node's key and the copy aside goes. Should that fail, the
/// copy aside is sent again on the next link, and the center answers it the
/// same.
async fn settle(
    shared: &Shared,
    center: &str,
    storage: SecretStorage,
    current_hex: &str,
    next: NodeKey,
    error: Option<String>,
) -> Result<Value, String> {
    let new_hex = next.public_hex();
    let paths = shared.paths.clone();
    let name = center.to_string();
    if let Some(e) = error {
        let e = clip(&e);
        let dropped = tokio::task::spawn_blocking(move || {
            crate::secrets::remove_center_next_key(&paths, storage, &name)
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        if let Err(d) = dropped {
            tracing::warn!("center {center}: the refused new key could not be deleted: {d}");
        }
        shared.audit_key(
            center,
            "node-key-refused",
            &format!(
                "the center refused the new key {new_hex}: {e}; the old key {current_hex} stays"
            ),
        );
        return Err(format!(
            "center {center} refused the new key: {e}; the old key stays in use"
        ));
    }
    // The config names the new key first, which its node id no longer does,
    // so that a backup can tell it belongs to this pairing. Should that fail,
    // nothing else changes: the key aside goes again on the next link, and
    // the center answers it the same.
    let named = new_hex.clone();
    // Counted once per key: a rotation settled again (its first try did not
    // finish) is the same one.
    let recorded = shared.mark_center(center, |e| {
        if e.public_key.as_ref() != Some(&named) {
            e.public_key = Some(named);
            e.key_rotations += 1;
        }
    });
    if !recorded {
        return Err(format!(
            "center {center} took the new key, but node.toml could not record it; the old key stays in use for now, and the new key is kept: the node settles it on its next link, or run this command again"
        ));
    }
    tokio::task::spawn_blocking(move || {
        crate::secrets::store_center_key(&paths, storage, &name, &next)?;
        crate::secrets::remove_center_next_key(&paths, storage, &name)
    })
    .await
    .map_err(|e| format!("keeping the new key stopped: {e}"))?
    .map_err(|e| {
        format!(
            "center {center} took the new key, but the node could not keep it as its key: {e}. The old key works at the center for {}; run this command again",
            grace()
        )
    })?;
    tracing::info!(
        "center {center} took this node's new key {new_hex}; the old key works there for {} more, or until `nerve-node center rotate-key --end-grace`",
        grace()
    );
    shared.audit_key(
        center,
        "node-key",
        &format!(
            "the center took the new key {new_hex} in place of {current_hex}, which it takes for {} more",
            grace()
        ),
    );
    Ok(json!({
        "center": center,
        "public_key": new_hex,
        "grace_until_ms": crate::now_ms() + ROTATE_GRACE_MS,
    }))
}

/// A `key.rotated` that came when nothing waited for it any more (the
/// owner's command gave up after [`ANSWER`]): about the new key kept aside,
/// it settles the rotation all the same, so a key the center took is never
/// left unused on a link that stays up.
pub(crate) async fn late_answer(shared: Arc<Shared>, center: String, p: Map<String, Value>) {
    let Ok(reply) = params::<KeyRotated>(&p) else {
        return;
    };
    let cs = shared.center(&center);
    let _one = cs.rotating.lock().await;
    let Ok((storage, _)) = entry(&shared, &center) else {
        return;
    };
    match keys(&shared, storage, &center).await {
        Ok((current, Some(next))) if next.public_hex() == reply.public_key => {
            let current = current.public_hex();
            if let Err(e) = settle(&shared, &center, storage, &current, next, reply.error).await {
                tracing::warn!("center {center}: {e}");
            }
        }
        Ok(_) => tracing::debug!(
            "center {center}: key.rotated about a key this node does not hold aside; ignored"
        ),
        Err(e) => tracing::warn!("center {center}: the key rotation cannot go on: {e}"),
    }
}

/// The center took a hello signed with the new key kept aside: it holds
/// that key for the node, so the rotation is settled without asking again.
pub(crate) async fn adopt(shared: Arc<Shared>, center: String, public_key: String) {
    let cs = shared.center(&center);
    let _one = cs.rotating.lock().await;
    let Ok((storage, _)) = entry(&shared, &center) else {
        return;
    };
    match keys(&shared, storage, &center).await {
        Ok((current, Some(next))) if next.public_hex() == public_key => {
            tracing::info!(
                "center {center} took a hello signed with this node's new key, so it took the rotation that got no answer"
            );
            let current = current.public_hex();
            if let Err(e) = settle(&shared, &center, storage, &current, next, None).await {
                tracing::warn!("center {center}: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("center {center}: the key rotation cannot go on: {e}"),
    }
}

/// `center.rotate` from `center`: the center has a new key, signed by the old
/// one. The node pins the new key and takes the old one until the grace the
/// center names ends, at most [`ROTATE_GRACE_MS`]; a center that told the
/// rotation before and names a shorter grace now (it serves the new key
/// already) ends it.
pub(crate) fn center_rotated(shared: &Shared, center: &str, p: &Map<String, Value>) {
    let r: CenterRotate = match params(p) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                "center {center} sent a center.rotate the node cannot read ({}); ignored",
                e.message
            );
            return;
        }
    };
    let cfg = shared.config();
    let Some(entry) = cfg.center(center) else {
        return;
    };
    let Some(pin) = entry.pin.clone() else {
        tracing::info!(
            "center {center} rotated its key; this pairing checks the center's certificate against the system's roots, not a pin, so nothing changes here"
        );
        return;
    };
    let raw = nerve_transport::tls::unb64url;
    let (Some(old), Some(new), Some(sig)) = (raw(&r.old_spki), raw(&r.new_spki), raw(&r.sig))
    else {
        tracing::warn!("center {center} sent a center.rotate that is not base64url; ignored");
        return;
    };
    let old_pin = nerve_transport::tls::pin_of_spki(&old);
    let new_pin = nerve_transport::tls::pin_of_spki(&new);
    let new_raw = ring::digest::digest(&ring::digest::SHA256, &new);
    let message = nerve_proto::rotate_center_message(&entry.center_id, new_raw.as_ref());
    // The old key's signature is what makes the new key trusted: the link it
    // came over may still run on an even older key in its grace.
    if !nerve_transport::tls::verify_spki_signature(&old, &message, &sig) {
        tracing::warn!(
            "center {center} sent a new key that its old key did not sign; the node keeps the pin it has"
        );
        shared.audit_key(
            center,
            "center-key-refused",
            &format!("the new pin {new_pin} is not signed by the key of {old_pin}"),
        );
        return;
    }
    let now = crate::now_ms();
    let grace_ms = r.grace_ms.min(ROTATE_GRACE_MS);
    let keep = |pin: &str| {
        (grace_ms > 0).then(|| OldPin {
            pin: pin.to_string(),
            until_ms: now + grace_ms,
        })
    };
    if same_pin(&pin, &old_pin) && !same_pin(&new_pin, &old_pin) {
        let old_kept = keep(&old_pin);
        let saved = shared.mark_center(center, |e| {
            if e.pin.as_deref().is_some_and(|p| same_pin(p, &pin)) {
                e.pin = Some(new_pin.clone());
                e.old_pin = old_kept;
                e.pin_rotations += 1;
            }
        });
        // Not kept, the node pins the old key as before; the center tells
        // the rotation again on the next link.
        if !saved {
            tracing::warn!(
                "center {center} rotated its key to the pin {new_pin}, but node.toml could not be saved; the node keeps the old pin until it is told again"
            );
            return;
        }
        let taken = if grace_ms > 0 {
            format!(
                "the old one is taken for {} more",
                span(Duration::from_millis(grace_ms))
            )
        } else {
            "the old one no longer".to_string()
        };
        tracing::info!("center {center} rotated its key: the new pin is {new_pin}; {taken}");
        shared.audit_key(
            center,
            "center-key",
            &format!("the center's new pin is {new_pin} in place of {old_pin}; {taken}"),
        );
        return;
    }
    let told_before = same_pin(&pin, &new_pin)
        && entry
            .old_pin
            .as_ref()
            .is_some_and(|o| same_pin(&o.pin, &old_pin) && now + grace_ms < o.until_ms);
    if told_before {
        let shorter = keep(&old_pin);
        let ended = shorter.is_none();
        let saved = shared.mark_center(center, |e| {
            if e.pin.as_deref().is_some_and(|p| same_pin(p, &new_pin)) {
                e.old_pin = shorter;
            }
        });
        if ended && saved {
            tracing::info!(
                "center {center} serves its new key now; the old pin {old_pin} is no longer taken"
            );
            shared.audit_key(
                center,
                "center-key-grace-ended",
                &format!("the old pin {old_pin} is no longer taken"),
            );
        }
        return;
    }
    if !same_pin(&pin, &new_pin) {
        tracing::warn!(
            "center {center} sent a rotation from a key this node does not pin ({old_pin}); ignored"
        );
    }
}

/// How long the node waits before it tries again to drop an expired old pin
/// it could not save.
const OLD_PIN_RETRY: Duration = Duration::from_secs(600);

/// Drops the old pin of `center` from node.toml once its grace is over
/// (it is no longer taken by then); whether it did. Asked at each dial and
/// on a live link's tick. A save that fails is tried again only after
/// [`OLD_PIN_RETRY`], so a full disk does not fill the log.
pub(crate) fn drop_old_pin(shared: &Shared, center: &str) -> bool {
    // Kept the slack longer than its time: a live link under it ends only
    // then (crate::link::OLD_PIN_LINK_SLACK_MS). New dials take it no more
    // from its time on (`pins_at`).
    let expired = |e: &CenterEntry| {
        e.old_pin.as_ref().is_some_and(|o| {
            crate::now_ms()
                >= o.until_ms
                    .saturating_add(crate::link::OLD_PIN_LINK_SLACK_MS)
        })
    };
    if !shared.config().center(center).is_some_and(expired) {
        return false;
    }
    let cs = shared.center(center);
    if crate::daemon::lock(&cs.old_pin_failed).is_some_and(|t| t.elapsed() < OLD_PIN_RETRY) {
        return false;
    }
    let saved = shared.mark_center(center, |e| {
        if expired(e) {
            e.old_pin = None;
        }
    });
    if !saved {
        *crate::daemon::lock(&cs.old_pin_failed) = Some(std::time::Instant::now());
        tracing::warn!(
            "center {center}: the grace of its old key has ended, but its old pin could not be dropped from node.toml; trying again in {}",
            span(OLD_PIN_RETRY)
        );
        return false;
    }
    *crate::daemon::lock(&cs.old_pin_failed) = None;
    tracing::info!("center {center}: the grace of its old key has ended; its old pin is dropped");
    true
}

/// Whether two pins name the same key: compared by their 32 bytes, so a pin
/// written with base64 padding is the same as one without.
pub(crate) fn same_pin(a: &str, b: &str) -> bool {
    match (
        nerve_transport::tls::decode_pin(a),
        nerve_transport::tls::decode_pin(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// A center's text as the node repeats it: one line, cut.
fn clip(s: &str) -> String {
    let one: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    nerve_proto::text::clip(&one, 300)
}
