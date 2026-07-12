//! Trust-anchor rotation (design.md §9): mint a fresh signing key vouched for by the outgoing one.

use common::crypto::CoordinatorKey;
use common::now_unix;
use common::rotation::RotationCert;
use common::wire::Signed;

use crate::store::Store;

/// Rotate the coordinator's signing key. Generates a new key, signs a `prev → new` cert with the
/// **old** key (so already-pinned clients can follow the chain and re-pin), appends the cert to the
/// stored chain, then swaps in the new seed. Returns the new anchor. A running coordinator must be
/// restarted to pick up the new key for signing.
pub async fn rotate_key(store: &Store) -> anyhow::Result<[u8; 32]> {
    let old = CoordinatorKey::from_seed(&store.load_or_create_seed().await?);
    let new = CoordinatorKey::generate();
    let cert = Signed::sign(
        &old,
        &RotationCert {
            prev_anchor: old.anchor_bytes(),
            new_anchor: new.anchor_bytes(),
            issued_at: now_unix(),
        },
    )?;
    // Append the cert before swapping the seed: if we crash between the two, clients still see the
    // old anchor (which still signs) plus a harmless dangling cert — never a new anchor with no path.
    store.append_rotation_cert(&cert.to_base64()).await?;
    store.replace_seed(&new.to_seed()).await?;
    Ok(new.anchor_bytes())
}
