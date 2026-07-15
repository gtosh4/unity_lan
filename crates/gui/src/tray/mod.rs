//! System-tray integration, platform-split behind a thin `spawn()` entry (mirroring the engine's
//! `fw`/`resolver` per-OS modules). Linux uses **ksni** — StatusNotifierItem over D-Bus, native on
//! KDE/GNOME/wayland with no gtk dependency; Windows uses **tray-icon** (a Shell_NotifyIcon window
//! we pump ourselves). Other platforms fall to a no-op stub.
//!
//! The tray runs on its **own thread with its own tokio runtime**: it polls the engine control
//! socket to reflect the mesh's connected state on the icon, and drives connect/disconnect over
//! that socket directly. Only window show/hide and quit cross back into the iced runtime, over the
//! returned channel.

use std::path::PathBuf;

use tokio::sync::mpsc::UnboundedReceiver;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(any(target_os = "linux", windows)))]
mod stub;
#[cfg(windows)]
mod windows;

/// Actions the tray asks the iced app to perform (everything else it does itself over the socket).
#[derive(Debug, Clone, Copy)]
pub enum TrayMsg {
    /// Toggle the main window between shown and hidden (minimize-to-tray / restore).
    ToggleWindow,
    /// Quit the GUI. The engine keeps running — this is a viewer/controller, not the daemon.
    Quit,
}

/// Spawn the platform tray on its own thread. Returns a receiver of window/quit requests, or
/// `None` when the platform has no tray backend yet or the system exposes no SNI host.
pub fn spawn(socket: PathBuf) -> Option<UnboundedReceiver<TrayMsg>> {
    #[cfg(target_os = "linux")]
    {
        linux::spawn(socket)
    }
    #[cfg(windows)]
    {
        windows::spawn(socket)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        stub::spawn(socket)
    }
}

/// A 22×22 RGBA dot for the tray icon — green when the mesh is connected, grey when not. Backends
/// convert to their native pixel order. A filled circle with a 1px feathered edge (no asset files).
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn dot_rgba(connected: bool) -> (u32, Vec<u8>) {
    const N: i32 = 22;
    let (r, g, b) = if connected {
        (0x35, 0xc7, 0x59)
    } else {
        (0x88, 0x88, 0x88)
    };
    let mut px = vec![0u8; (N * N * 4) as usize];
    let c = (N - 1) as f32 / 2.0;
    let rad = c - 1.0;
    for y in 0..N {
        for x in 0..N {
            let (dx, dy) = (x as f32 - c, y as f32 - c);
            let d = (dx * dx + dy * dy).sqrt();
            let a = ((rad - d) + 0.5).clamp(0.0, 1.0); // 1px feather for a smooth edge
            let i = ((y * N + x) * 4) as usize;
            px[i] = r;
            px[i + 1] = g;
            px[i + 2] = b;
            px[i + 3] = (a * 255.0) as u8;
        }
    }
    (N as u32, px)
}
