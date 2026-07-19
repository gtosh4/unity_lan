//! Targeted-wake registry and long-poll parking for the register/refresh long-poll.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use crate::versions::Scope;

use super::AppState;

/// Per-client targeted-wake registry (see [`AppState::wakers`]). A parked `/register` subscribes to
/// its own pubkey; a pair-specific report *about* that pubkey bumps only its channel, waking that one
/// client instead of the whole long-poll herd. Entries live only while a client is parked — the
/// sender-only leftovers are swept periodically — so the map stays bounded to in-flight parks.
#[derive(Default)]
pub struct Wakers {
    inner: Mutex<WakersInner>,
}

#[derive(Default)]
struct WakersInner {
    #[allow(clippy::type_complexity)]
    map: HashMap<[u8; 32], tokio::sync::watch::Sender<u64>>,
    /// Subscribe counter gating the amortized sweep (see [`Wakers::subscribe`]).
    subs: u32,
}

/// Sweep stale (sender-only) entries once per this many subscribes. Amortizes the `O(map)` sweep so a
/// herd of `N` subscribes costs `O(N²/GC_EVERY)`, not `O(N²)`, under the lock; at most this many stale
/// entries accumulate between sweeps.
const WAKERS_GC_EVERY: u32 = 64;

impl Wakers {
    /// Register interest for `pk`, returning a receiver that fires on each [`Wakers::wake`].
    pub fn subscribe(&self, pk: [u8; 32]) -> tokio::sync::watch::Receiver<u64> {
        let mut inner = self.inner.lock().unwrap();
        inner.subs = inner.subs.wrapping_add(1);
        // Amortized GC: don't scan the whole map on every subscribe (that would be O(N²) under a
        // herd — the exact cost this registry exists to avoid). Sweep sender-only leftovers of
        // clients whose parks have ended only once per WAKERS_GC_EVERY subscribes.
        if inner.subs.is_multiple_of(WAKERS_GC_EVERY) {
            inner.map.retain(|_, tx| tx.receiver_count() > 0);
        }
        inner
            .map
            .entry(pk)
            .or_insert_with(|| tokio::sync::watch::channel(0u64).0)
            .subscribe()
    }

    /// Wake the client currently parked on `pk`, if any (no-op otherwise). Edge-triggered via a
    /// version bump, so a wake that races a subscribe is still delivered on the next `changed()`.
    pub fn wake(&self, pk: &[u8; 32]) {
        if let Some(tx) = self.inner.lock().unwrap().map.get(pk) {
            tx.send_modify(|v| *v = v.wrapping_add(1));
        }
    }
}

/// Why a parked `/register` woke — [`wait_park`]'s outcome. Only a `Herd` wake (global membership
/// bump) is jittered; a `Personal` (targeted) wake is one client and needs no fan-in smoothing.
pub(super) enum Woke {
    Herd,
    Personal,
    Elapsed,
}

/// Park until the caller's aggregate membership version moves off `since` (a herd wake — but a herd
/// bounded to one guild, not the deployment), this client's `personal` targeted-wake channel fires,
/// or the renewal hold elapses.
///
/// Subscribes to each of the caller's own [`Scope`]s — its user scope plus the guilds it holds a
/// network in, so typically 2–4 receivers. A bump in any other scope never reaches it.
pub(super) async fn wait_park(
    st: &AppState,
    scopes: &BTreeSet<Scope>,
    since: u64,
    personal: &mut tokio::sync::watch::Receiver<u64>,
) -> Woke {
    let mut rxs: Vec<_> = scopes.iter().map(|s| st.versions.subscribe(*s)).collect();
    let hold = tokio::time::sleep(std::time::Duration::from_secs(st.longpoll_hold_secs));
    tokio::pin!(hold);
    loop {
        // Mark every receiver seen *before* re-reading the aggregate, so a bump that lands in the
        // gap is still pending on its receiver and fires immediately below (no lost wakeup).
        for rx in rxs.iter_mut() {
            rx.borrow_and_update();
        }
        if st.versions.aggregate(scopes) != since {
            return Woke::Herd;
        }
        tokio::select! {
            r = any_changed(&mut rxs) => if r.is_err() { return Woke::Elapsed; },
            r = personal.changed() => return if r.is_err() { Woke::Elapsed } else { Woke::Personal },
            _ = &mut hold => return Woke::Elapsed,
        }
    }
}

/// Resolve when any of `rxs` changes. `tokio::select!` needs a statically known arm count and the
/// scope set is dynamic, so poll each receiver by hand — polling all of them registers all their
/// wakers, which is exactly what a select does.
async fn any_changed(
    rxs: &mut [tokio::sync::watch::Receiver<u64>],
) -> Result<(), tokio::sync::watch::error::RecvError> {
    let mut futs: Vec<_> = rxs.iter_mut().map(|rx| Box::pin(rx.changed())).collect();
    std::future::poll_fn(|cx| {
        for f in futs.iter_mut() {
            if let std::task::Poll::Ready(r) = std::future::Future::poll(f.as_mut(), cx) {
                return std::task::Poll::Ready(r);
            }
        }
        std::task::Poll::Pending
    })
    .await
}

/// Max stagger applied to a herd wake so a single version bump doesn't release every parked client
/// into the coordinator at the same instant.
const WAKE_JITTER_MAX_MS: u64 = 1000;

/// A deterministic per-client wake offset in `[0, WAKE_JITTER_MAX_MS)`, derived from the client's
/// (uniformly distributed) pubkey — spreads a herd across the window without pulling in an RNG, and
/// keeps a given client's slot stable across successive wakes.
pub(super) fn wake_jitter(wg_pubkey: &[u8; 32]) -> std::time::Duration {
    let n = u64::from_le_bytes(wg_pubkey[..8].try_into().unwrap());
    std::time::Duration::from_millis(n % WAKE_JITTER_MAX_MS)
}

/// Park until the **global** membership version moves off `since`, or the given hold elapses.
/// `watch` tracks the latest version internally, so a bump between snapshot and subscribe is not
/// lost. Only the admin dashboard uses this: it renders the whole deployment, so it genuinely wants
/// every scope's bumps (clients use the scoped [`wait_park`] instead). It passes a short heartbeat
/// so its held request survives reverse-proxy idle timeouts and its "updated" clock stays fresh, at
/// the cost of a cheap re-poll.
/// Returns `true` if it woke because the version moved, `false` if the hold elapsed first or the
/// sender was dropped.
pub(super) async fn wait_for_change_until(
    st: &AppState,
    since: u64,
    hold: std::time::Duration,
) -> bool {
    let mut rx = st.versions.subscribe_global();
    let deadline = tokio::time::sleep(hold);
    tokio::pin!(deadline);
    loop {
        if *rx.borrow_and_update() != since {
            return true;
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return false; },
            _ = &mut deadline => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn wakers_fire_only_the_target() {
        let w = super::Wakers::default();
        let rx = w.subscribe([1u8; 32]);
        assert!(!rx.has_changed().unwrap(), "no wake yet");
        // A pubkey nobody parked on is a silent no-op — and doesn't touch our channel.
        w.wake(&[2u8; 32]);
        assert!(
            !rx.has_changed().unwrap(),
            "wake for another pubkey must not fire us"
        );
        // Waking our pubkey fires our receiver.
        w.wake(&[1u8; 32]);
        assert!(
            rx.has_changed().unwrap(),
            "targeted wake fires the parked client"
        );
        // Dropping the receiver lets the next subscribe sweep the sender-only entry (no leak).
        drop(rx);
        let _rx2 = w.subscribe([1u8; 32]);
    }

    #[test]
    fn wake_jitter_bounded_deterministic_and_spread() {
        let a = super::wake_jitter(&[7u8; 32]);
        assert_eq!(a, super::wake_jitter(&[7u8; 32]), "same pubkey → same slot");
        assert!((a.as_millis() as u64) < super::WAKE_JITTER_MAX_MS);
        // Distinct pubkeys land in distinct slots → the herd spreads across the window.
        assert_ne!(a, super::wake_jitter(&[8u8; 32]));
    }
}
