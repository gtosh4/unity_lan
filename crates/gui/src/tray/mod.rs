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

/// A 22×22 straight-alpha RGBA tray glyph: the Woven-U mark, stripped to its bold silhouette for
/// legibility at tray size, tinted green when the mesh is connected and grey when not. Backends
/// convert to their native pixel order. Rendered from an inline SVG via resvg — the rasteriser iced
/// already links — so the tray path still carries no asset files.
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn dot_rgba(connected: bool) -> (u32, Vec<u8>) {
    use resvg::{tiny_skia, usvg};

    const N: u32 = 22;
    let color = if connected { "#33C58A" } else { "#888888" };
    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{N}" height="{N}" viewBox="0 0 100 100"><path d="M26 26 26 50 Q26 72 50 72 Q74 72 74 50 L74 26" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round"/></svg>"##
    );

    let tree =
        usvg::Tree::from_str(&svg, &usvg::Options::default()).expect("static tray glyph is valid");
    let mut pixmap = tiny_skia::Pixmap::new(N, N).expect("22×22 is a valid pixmap size");
    resvg::render(&tree, tiny_skia::Transform::default(), &mut pixmap.as_mut());

    // tiny-skia hands back premultiplied alpha; the tray backends want straight-alpha RGBA.
    let mut px = pixmap.take();
    for p in px.chunks_exact_mut(4) {
        let a = p[3] as u32;
        for c in &mut p[..3] {
            // Straight = premultiplied · 255 / alpha; fully-transparent pixels stay 0.
            *c = (*c as u32 * 255).checked_div(a).map_or(0, |v| v.min(255)) as u8;
        }
    }
    (N, px)
}
