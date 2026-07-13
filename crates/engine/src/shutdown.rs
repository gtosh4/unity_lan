//! A cloneable, fire-once shutdown signal shared by the daemon's await points.
//!
//! The daemon awaits shutdown in more than one place (the register loop and the main refresh loop),
//! so it needs a signal that any number of tasks can await and that stays "fired" once tripped.
//! Console mode wires Ctrl-C into it; the Windows service wires the SCM Stop control into it.
//!
//! Built on a `watch<bool>`: the sender flips it to `true`, and every receiver — now or later — sees
//! the latched value, so a stop that races ahead of an await point is never missed.

use tokio::sync::watch;

/// The receiving half handed to the daemon. Clone it freely; every clone observes the same signal.
#[derive(Clone)]
pub struct Shutdown {
    rx: watch::Receiver<bool>,
}

/// The sending half held by whoever owns the stop source (Ctrl-C task / SCM control handler).
/// Keep it alive for the process/service lifetime; the latched value survives it being dropped.
pub struct ShutdownTrigger {
    tx: watch::Sender<bool>,
}

/// Create a linked (trigger, signal) pair, initially un-fired.
pub fn channel() -> (ShutdownTrigger, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (ShutdownTrigger { tx }, Shutdown { rx })
}

impl Shutdown {
    /// Resolve once shutdown has been triggered — immediately if it already has. Safe to call from
    /// many await points; each gets its own view of the latched signal.
    pub async fn wait(&self) {
        let mut rx = self.rx.clone();
        if *rx.borrow() {
            return;
        }
        // `changed()` errors only if the sender was dropped without firing; with no way left to
        // signal, waking to shut down is the safe interpretation.
        let _ = rx.changed().await;
    }
}

impl ShutdownTrigger {
    /// Latch the signal. Idempotent; subsequent calls are no-ops.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }
}
