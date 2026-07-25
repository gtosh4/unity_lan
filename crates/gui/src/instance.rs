//! Single-instance enforcement, keyed by the engine control socket this GUI drives. Only one GUI
//! may own a given socket: a second launch signals the running one to show/focus its window, then
//! exits quietly instead of opening a duplicate.
//!
//! The lock is a **namespaced** local socket (Linux abstract socket / Windows named pipe), distinct
//! from the engine's control-socket namespace. Both vanish when their owning process dies, so a
//! crashed GUI leaves no stale lock to reclaim — a fresh launch just binds the freed name.
//!
//! Shape mirrors the tray: the owner runs a dedicated accept thread and hands "show yourself"
//! events back to the iced runtime over a channel (see [`crate::App::instance_subscription`]).

use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::Path;

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericNamespaced, Listener, ListenerOptions, Name, Stream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// A stable, short id for the GUI instance owning `socket`, derived from the socket's absolute path
/// so two launches aimed at the same engine collide while launches at distinct engines don't.
fn lock_id(socket: &Path) -> String {
    let abs = if socket.is_absolute() {
        socket.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(socket))
            .unwrap_or_else(|_| socket.to_path_buf())
    };
    // DefaultHasher (SipHash with fixed keys) is deterministic across processes — a plain, short
    // name that dodges the path's slashes and length limits of the namespaced-name spaces.
    let mut h = std::collections::hash_map::DefaultHasher::new();
    abs.hash(&mut h);
    format!("unitylan-gui-{:016x}", h.finish())
}

/// Build the namespaced local-socket name for `id` (owned → `'static`). `Err` on platforms without
/// namespaced local sockets, which the caller treats as "single-instance unsupported".
fn to_name(id: String) -> std::io::Result<Name<'static>> {
    id.to_ns_name::<GenericNamespaced>()
}

/// Outcome of trying to become the sole GUI for a socket.
pub enum Startup {
    /// We own the lock. Drive this receiver: each `()` is a "show yourself" request from a later
    /// launch that found us already running.
    Primary(UnboundedReceiver<()>),
    /// Another instance already owns the lock and has been asked to show its window — exit quietly.
    AlreadyRunning,
    /// Single-instance couldn't be established here (no namespaced local sockets). Run normally
    /// without the guard rather than refusing to start.
    Unsupported,
}

/// Try to claim the single-instance lock for `socket`. Binds a namespaced listener; if it's already
/// held, connects to signal the owner and reports [`Startup::AlreadyRunning`].
pub fn start(socket: &Path) -> Startup {
    let id = lock_id(socket);
    // Bind-first, so exactly one process wins the lock. A crashed owner's namespaced name is
    // already released, so if the owner vanishes between our bind and our signal we loop to reclaim
    // the now-free name rather than exiting into nothing.
    for _ in 0..3 {
        let name = match to_name(id.clone()) {
            Ok(n) => n,
            Err(_) => return Startup::Unsupported,
        };
        match ListenerOptions::new().name(name).create_sync() {
            Ok(listener) => return Startup::Primary(spawn_accept(listener)),
            // Name already taken (AddrInUse on unix abstract sockets, AlreadyExists on a
            // first-instance Windows pipe) → an owner exists; ask it to show itself.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AlreadyExists
                ) =>
            {
                if signal(&id) {
                    return Startup::AlreadyRunning;
                }
                // Owner vanished before we could reach it — loop to reclaim the freed name.
            }
            Err(_) => return Startup::Unsupported,
        }
    }
    Startup::Unsupported
}

/// Connect to the lock and nudge the owner to surface its window. Returns whether an owner answered.
fn signal(id: &str) -> bool {
    let name = match to_name(id.to_string()) {
        Ok(n) => n,
        Err(_) => return false,
    };
    match Stream::connect(name) {
        Ok(mut stream) => {
            // The connection itself is the signal; the byte just guarantees the pipe is realized
            // before we drop it (a bare connect+close races the server's accept on Windows pipes).
            let _ = stream.write_all(b"1");
            let _ = stream.flush();
            true
        }
        Err(_) => false,
    }
}

/// Own the bound listener on a dedicated thread, turning each incoming connection into a `()` on the
/// returned channel — the "show yourself" event the iced app consumes.
fn spawn_accept(listener: Listener) -> UnboundedReceiver<()> {
    let (tx, rx) = unbounded_channel();
    if let Err(e) = std::thread::Builder::new()
        .name("unitylan-instance".into())
        .spawn(move || accept_loop(listener, tx))
    {
        // No accept thread means no second-launch focus, but the GUI itself runs fine.
        eprintln!("instance: accept thread spawn failed: {e}");
    }
    rx
}

fn accept_loop(listener: Listener, tx: UnboundedSender<()>) {
    loop {
        match listener.accept() {
            Ok(mut conn) => {
                // Drain the one-byte nudge so the peer's write completes cleanly, then drop it.
                let mut buf = [0u8; 8];
                let _ = conn.read(&mut buf);
                if tx.send(()).is_err() {
                    break; // the app is gone; stop accepting
                }
            }
            Err(e) => {
                eprintln!("instance: accept failed: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::lock_id;
    use std::path::Path;

    #[test]
    fn lock_id_is_stable_and_path_specific() {
        // Absolute paths hash the same across calls (and processes), and differ per socket.
        let a = lock_id(Path::new("/run/unitylan/control.sock"));
        assert_eq!(a, lock_id(Path::new("/run/unitylan/control.sock")));
        assert_ne!(a, lock_id(Path::new("/run/other/control.sock")));
        assert!(a.starts_with("unitylan-gui-"));
    }
}
