//! Linux tray via ksni (StatusNotifierItem over D-Bus). Runs on a dedicated thread with its own
//! current-thread tokio runtime — winit can't be reused here (iced owns the one event loop), and
//! ksni needs no native UI loop of its own.

use std::path::PathBuf;
use std::time::Duration;

use ksni::menu::{MenuItem, StandardItem};
use ksni::{Handle, Icon, Status, Tray, TrayMethods};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::TrayMsg;

/// The ksni tray model. `connected` drives the icon colour + the toggle label; the two senders are
/// how menu clicks act (window/quit go to the app, connect/disconnect to the socket task).
struct UnityTray {
    connected: bool,
    to_app: UnboundedSender<TrayMsg>,
    to_conn: UnboundedSender<bool>,
}

impl Tray for UnityTray {
    fn id(&self) -> String {
        "unitylan".into()
    }

    fn title(&self) -> String {
        let state = if self.connected {
            "connected"
        } else {
            "disconnected"
        };
        format!("UnityLAN — {state}")
    }

    fn status(&self) -> Status {
        Status::Active
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        let (n, data) = argb_dot(self.connected);
        vec![Icon {
            width: n as i32,
            height: n as i32,
            data,
        }]
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let toggle_label = if self.connected {
            "Disconnect mesh"
        } else {
            "Connect mesh"
        };
        vec![
            StandardItem {
                label: "Show / hide window".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.to_app.send(TrayMsg::ToggleWindow);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: toggle_label.into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.to_conn.send(!t.connected);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.to_app.send(TrayMsg::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// ksni wants ARGB32 in network byte order; the shared helper emits RGBA — repack in place.
fn argb_dot(connected: bool) -> (u32, Vec<u8>) {
    let (n, mut px) = super::dot_rgba(connected);
    for p in px.chunks_exact_mut(4) {
        let (r, g, b, a) = (p[0], p[1], p[2], p[3]);
        p[0] = a;
        p[1] = r;
        p[2] = g;
        p[3] = b;
    }
    (n, px)
}

pub fn spawn(socket: PathBuf) -> Option<UnboundedReceiver<TrayMsg>> {
    let (to_app_tx, to_app_rx) = unbounded_channel();
    let spawned = std::thread::Builder::new()
        .name("unitylan-tray".into())
        .spawn(move || {
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
            rt.block_on(tray_main(socket, to_app_tx));
        });
    match spawned {
        Ok(_) => Some(to_app_rx),
        Err(e) => {
            eprintln!("tray: thread spawn failed: {e}");
            None
        }
    }
}

async fn tray_main(socket: PathBuf, to_app: UnboundedSender<TrayMsg>) {
    let (to_conn, mut conn_rx) = unbounded_channel::<bool>();
    let tray = UnityTray {
        connected: true,
        to_app,
        to_conn,
    };
    let handle: Handle<UnityTray> = match tray.spawn().await {
        Ok(h) => h,
        Err(e) => {
            // No SNI host (e.g. a bare WM with no tray). The GUI still works without the tray.
            eprintln!("tray: no system tray available: {e}");
            return;
        }
    };

    // Connect/disconnect menu clicks → drive the control socket off the ksni callback thread.
    let conn_socket = socket.clone();
    tokio::spawn(async move {
        while let Some(want) = conn_rx.recv().await {
            if let Err(e) = crate::ctl::set_connected(conn_socket.clone(), want).await {
                eprintln!("tray: set_connected failed: {e}");
            }
        }
    });

    // Reflect the mesh's connected state on the icon + toggle label.
    let mut last: Option<bool> = None;
    loop {
        if handle.is_closed() {
            break;
        }
        if let Ok(s) = crate::ctl::fetch_status(socket.clone()).await {
            if last != Some(s.connected) {
                last = Some(s.connected);
                handle
                    .update(move |t: &mut UnityTray| t.connected = s.connected)
                    .await;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
