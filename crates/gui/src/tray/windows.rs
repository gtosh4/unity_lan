//! Windows tray via the `tray-icon` crate (a hidden Shell_NotifyIcon window). Unlike ksni, this
//! backend needs a **Win32 message pump** on the thread that owns the icon — menu clicks arrive as
//! window messages, and the context menu is drawn by Windows during message dispatch. So the tray
//! runs on two threads:
//!
//!   * a **UI thread** that creates the icon + menu and runs a blocking `GetMessage` loop; a 500ms
//!     Win32 timer wakes it to repaint the icon from the shared connected-state, and menu clicks are
//!     drained from tray-icon's global event channels each iteration;
//!   * a **net thread** with a current-thread tokio runtime that polls `ctl::fetch_status` (writing
//!     the connected flag the UI thread reads) and drains connect/disconnect requests into
//!     `ctl::set_connected`.
//!
//! Only window show/hide and quit cross back into iced, over the returned channel (same contract as
//! `linux.rs`). tray-icon's `TrayIcon`/`Menu` are `!Send`, hence they live entirely on the UI thread.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, KillTimer, SetTimer, TranslateMessage, MSG, WM_TIMER,
};

use super::TrayMsg;

/// Custom timer id for the repaint tick (arbitrary; the timer is thread-scoped, `hwnd == null`).
const REPAINT_TIMER_ID: usize = 1;

pub fn spawn(socket: PathBuf) -> Option<UnboundedReceiver<TrayMsg>> {
    let (to_app_tx, to_app_rx) = unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("unitylan-tray".into())
        .spawn(move || ui_thread(socket, to_app_tx));
    match spawned {
        Ok(_) => Some(to_app_rx),
        Err(e) => {
            eprintln!("tray: thread spawn failed: {e}");
            None
        }
    }
}

/// The UI thread: owns the icon + menu and pumps Win32 messages. Spawns the net thread once the
/// window (hence a message queue) exists.
fn ui_thread(socket: PathBuf, to_app: UnboundedSender<TrayMsg>) {
    // Shared connected-state: the net thread writes it, we read it on each repaint tick. Start
    // `true` (optimistic, like `linux.rs`); the first poll corrects it within ~2s.
    let connected = Arc::new(AtomicBool::new(true));

    let show = MenuItem::new("Show / hide window", true, None);
    let toggle = MenuItem::new(toggle_label(true), true, None);
    let quit = MenuItem::new("Quit", true, None);
    let menu = Menu::new();
    let built = menu
        .append(&show)
        .and_then(|_| menu.append(&PredefinedMenuItem::separator()))
        .and_then(|_| menu.append(&toggle))
        .and_then(|_| menu.append(&PredefinedMenuItem::separator()))
        .and_then(|_| menu.append(&quit));
    if let Err(e) = built {
        eprintln!("tray: menu build failed: {e}");
        return;
    }

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip(tooltip(true))
        .with_icon(icon(true))
        .build();
    let tray = match tray {
        Ok(t) => t,
        Err(e) => {
            // No shell tray (rare) — the GUI still works without it, same as a missing SNI host.
            eprintln!("tray: create failed: {e}");
            return;
        }
    };

    // The tray window now exists, so this thread has a message queue. Start the socket worker.
    let (to_conn_tx, to_conn_rx) = unbounded_channel::<bool>();
    let net_connected = connected.clone();
    if let Err(e) = std::thread::Builder::new()
        .name("unitylan-tray-net".into())
        .spawn(move || net_thread(socket, net_connected, to_conn_rx))
    {
        eprintln!("tray: net thread spawn failed: {e}");
    }

    // A periodic tick so we repaint the icon when the net thread flips the connected flag. Icon
    // updates must happen on this thread (the one that owns the icon), so we poll rather than let
    // the net thread touch it. `null` hwnd → the timer posts WM_TIMER to this thread's queue.
    // SAFETY: FFI call with a null window handle and no callback (we handle WM_TIMER in the loop).
    unsafe { SetTimer(std::ptr::null_mut(), REPAINT_TIMER_ID, 500, None) };

    let menu_rx = MenuEvent::receiver();
    let tray_rx = TrayIconEvent::receiver();
    let (show_id, toggle_id, quit_id) = (show.id().clone(), toggle.id().clone(), quit.id().clone());
    let mut rendered = true; // matches the initial icon/label we built above

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    loop {
        // Blocking wait for the next message; the 500ms timer guarantees we wake to repaint even
        // when nothing else is happening.
        // SAFETY: standard Win32 message-loop calls on a zeroed-then-filled MSG we own.
        let ret = unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) };
        if ret <= 0 {
            break; // 0 = WM_QUIT, -1 = error
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let mut quitting = false;
        // Menu clicks: dispatched above into tray-icon's global channel, drain them now.
        while let Ok(ev) = menu_rx.try_recv() {
            if ev.id == show_id {
                let _ = to_app.send(TrayMsg::ToggleWindow);
            } else if ev.id == toggle_id {
                let want = !connected.load(Ordering::Relaxed);
                let _ = to_conn_tx.send(want);
            } else if ev.id == quit_id {
                let _ = to_app.send(TrayMsg::Quit);
                quitting = true;
            }
        }
        // A double-click on the icon restores/hides the window (standard Windows behaviour).
        while let Ok(ev) = tray_rx.try_recv() {
            if let TrayIconEvent::DoubleClick { .. } = ev {
                let _ = to_app.send(TrayMsg::ToggleWindow);
            }
        }
        if quitting {
            break;
        }

        // Repaint on the timer tick if the mesh state changed under us.
        if msg.message == WM_TIMER {
            let now = connected.load(Ordering::Relaxed);
            if now != rendered {
                rendered = now;
                let _ = tray.set_icon(Some(icon(now)));
                let _ = tray.set_tooltip(Some(tooltip(now)));
                toggle.set_text(toggle_label(now));
            }
        }
    }

    // SAFETY: cancel our thread timer; matches the SetTimer above (null hwnd, same id).
    unsafe { KillTimer(std::ptr::null_mut(), REPAINT_TIMER_ID) };
}

/// The net thread: a current-thread tokio runtime driving the control socket. Polls status into the
/// shared flag and applies connect/disconnect requests from the menu.
fn net_thread(socket: PathBuf, connected: Arc<AtomicBool>, mut conn_rx: UnboundedReceiver<bool>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tray: runtime init failed: {e}");
            return;
        }
    };
    rt.block_on(async move {
        // Connect/disconnect menu clicks → drive the control socket.
        let conn_socket = socket.clone();
        tokio::spawn(async move {
            while let Some(want) = conn_rx.recv().await {
                if let Err(e) = crate::ctl::set_connected(conn_socket.clone(), want).await {
                    eprintln!("tray: set_connected failed: {e}");
                }
            }
        });

        // Reflect the mesh's connected state on the shared flag (the UI thread repaints from it).
        loop {
            if let Ok(s) = crate::ctl::fetch_status(socket.clone()).await {
                connected.store(s.connected, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// tray-icon wants straight RGBA — exactly what the shared helper emits, no repack needed.
fn icon(connected: bool) -> Icon {
    let (n, px) = super::dot_rgba(connected);
    // The bytes come from our own generator at a fixed 22×22, so this can't fail; fall back to an
    // unwrap rather than thread an error up a path that has no icon to show anyway.
    Icon::from_rgba(px, n, n).expect("valid 22x22 rgba tray icon")
}

fn toggle_label(connected: bool) -> &'static str {
    if connected {
        "Disconnect mesh"
    } else {
        "Connect mesh"
    }
}

fn tooltip(connected: bool) -> String {
    let state = if connected {
        "connected"
    } else {
        "disconnected"
    };
    format!("UnityLAN — {state}")
}
