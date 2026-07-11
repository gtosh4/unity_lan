//! UnityLAN GUI (M4): an unprivileged iced desktop app driving the engine over its control
//! socket. Shows live mesh status (this device + peers) and manages the owner's devices
//! (rename / set-primary / remove). Auto-refreshes every 2s. The mesh keeps running when the
//! window closes — this is a viewer/controller, not the engine.
//!
//! Usage: `unitylan-gui [control.sock]` (default: `control.sock` in the working directory).
//! Scope note: network toggles / expose / OAuth login are deferred until the engine exposes
//! them over the control socket.

mod ctl;

use std::path::PathBuf;
use std::time::Duration;

use common::api::{DeviceInfo, ManageOp, ManageResp};
use common::control::StatusReport;
use iced::widget::{button, column, row, scrollable, text, text_input, Column};
use iced::{Element, Length, Subscription, Task};

fn main() -> iced::Result {
    let socket = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "control.sock".to_string()),
    );
    iced::application("UnityLAN", App::update, App::view)
        .subscription(App::subscription)
        .run_with(move || {
            let app = App::new(socket);
            let init = app.reload();
            (app, init)
        })
}

struct App {
    socket: PathBuf,
    status: Option<StatusReport>,
    devices: Vec<DeviceInfo>,
    rename_input: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
enum Message {
    /// Timer tick → refetch status + device list.
    Tick,
    StatusFetched(Result<StatusReport, String>),
    /// Result of a `List` (or any manage op) → the owner's devices.
    DevicesFetched(Result<ManageResp, String>),
    RenameInput(String),
    RenameSubmit,
    SetPrimary(String),
    Remove(String),
}

impl App {
    fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            status: None,
            devices: Vec::new(),
            rename_input: String::new(),
            error: None,
        }
    }

    /// Fetch status + device list concurrently.
    fn reload(&self) -> Task<Message> {
        Task::batch([
            Task::perform(ctl::fetch_status(self.socket.clone()), Message::StatusFetched),
            Task::perform(
                ctl::manage(self.socket.clone(), ManageOp::List),
                Message::DevicesFetched,
            ),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => return self.reload(),
            Message::StatusFetched(Ok(s)) => {
                self.status = Some(s);
                self.error = None;
            }
            Message::StatusFetched(Err(e)) => self.error = Some(e),
            Message::DevicesFetched(Ok(r)) => {
                self.devices = r.devices;
                self.error = None;
            }
            Message::DevicesFetched(Err(e)) => self.error = Some(e),
            Message::RenameInput(s) => self.rename_input = s,
            Message::RenameSubmit => {
                let name = self.rename_input.trim().to_string();
                if !name.is_empty() {
                    self.rename_input.clear();
                    return Task::perform(
                        ctl::manage(self.socket.clone(), ManageOp::Rename { new_name: name }),
                        Message::DevicesFetched,
                    );
                }
            }
            Message::SetPrimary(device_name) => {
                return Task::perform(
                    ctl::manage(self.socket.clone(), ManageOp::SetPrimary { device_name }),
                    Message::DevicesFetched,
                )
            }
            Message::Remove(device_name) => {
                return Task::perform(
                    ctl::manage(self.socket.clone(), ManageOp::Remove { device_name }),
                    Message::DevicesFetched,
                )
            }
        }
        Task::none()
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(Duration::from_secs(2)).map(|_| Message::Tick)
    }

    fn view(&self) -> Element<'_, Message> {
        let body = column![self.device_section(), self.peers_section(), self.devices_section()]
            .spacing(20)
            .push_maybe(
                self.error
                    .as_ref()
                    .map(|e| text(format!("error: {e}")).size(14)),
            )
            .padding(20);
        scrollable(body).into()
    }

    fn device_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = match self.status.as_ref().and_then(|s| s.device.as_ref())
        {
            Some(d) => {
                let primary = if d.is_primary { "  [primary]" } else { "" };
                column![
                    text(format!("{}  {}{}", d.wg_ip, d.hostname, primary)),
                    text(format!("networks: {}", d.networks.join(", "))).size(14),
                ]
                .spacing(4)
                .into()
            }
            None => text("not joined to any network").into(),
        };
        column![text("this device").size(18), inner].spacing(6).into()
    }

    fn peers_section(&self) -> Element<'_, Message> {
        let peers = self.status.as_ref().map(|s| s.peers.as_slice()).unwrap_or(&[]);
        let mut col = Column::new().spacing(4);
        for p in peers {
            let ep = p
                .endpoint
                .map(|e| e.to_string())
                .unwrap_or_else(|| "-".to_string());
            col = col.push(text(format!("{:<16} {:<40} {}", p.wg_ip, p.hostname, ep)).size(14));
        }
        column![text(format!("peers ({})", peers.len())).size(18), col]
            .spacing(6)
            .into()
    }

    fn devices_section(&self) -> Element<'_, Message> {
        let mut list = Column::new().spacing(6);
        for d in &self.devices {
            let primary = if d.is_primary { "  [primary]" } else { "" };
            let this = if d.is_self { "  (this device)" } else { "" };
            let mut r = row![text(format!("{}{}{}", d.device_name, primary, this)).width(Length::Fill)]
                .spacing(8);
            if !d.is_primary {
                r = r.push(
                    button(text("set primary").size(13))
                        .on_press(Message::SetPrimary(d.device_name.clone())),
                );
            }
            if !d.is_self {
                r = r.push(
                    button(text("remove").size(13)).on_press(Message::Remove(d.device_name.clone())),
                );
            }
            list = list.push(r);
        }

        let rename = row![
            text_input("new name for this device", &self.rename_input)
                .on_input(Message::RenameInput)
                .on_submit(Message::RenameSubmit),
            button(text("rename").size(13)).on_press(Message::RenameSubmit),
        ]
        .spacing(8);

        column![text("devices").size(18), list, rename]
            .spacing(8)
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::control::{DeviceStatus, PeerStatus};
    use std::net::Ipv4Addr;

    fn app() -> App {
        App::new(PathBuf::from("control.sock"))
    }

    #[test]
    fn status_ok_populates_and_clears_error() {
        let mut a = app();
        a.error = Some("stale".into());
        let report = StatusReport {
            device: Some(DeviceStatus {
                wg_ip: Ipv4Addr::new(100, 64, 0, 1),
                hostname: "host-a.alice.lan.internal".into(),
                is_primary: true,
                networks: vec!["mesh".into()],
            }),
            peers: vec![PeerStatus {
                hostname: "host-b.bob.lan.internal".into(),
                wg_ip: Ipv4Addr::new(100, 64, 0, 2),
                endpoint: None,
            }],
        };
        let _ = a.update(Message::StatusFetched(Ok(report)));
        assert!(a.error.is_none());
        assert_eq!(a.status.unwrap().peers.len(), 1);
    }

    #[test]
    fn errors_surface_to_ui() {
        let mut a = app();
        let _ = a.update(Message::StatusFetched(Err("no daemon".into())));
        assert_eq!(a.error.as_deref(), Some("no daemon"));
    }

    #[test]
    fn devices_fetched_replaces_list() {
        let mut a = app();
        let resp = ManageResp {
            message: "ok".into(),
            devices: vec![DeviceInfo {
                device_name: "laptop".into(),
                is_primary: true,
                is_self: true,
            }],
        };
        let _ = a.update(Message::DevicesFetched(Ok(resp)));
        assert_eq!(a.devices.len(), 1);
        assert_eq!(a.devices[0].device_name, "laptop");
    }

    #[test]
    fn empty_rename_is_ignored() {
        let mut a = app();
        a.rename_input = "   ".into();
        let _ = a.update(Message::RenameSubmit);
        // whitespace-only rename: input stays, nothing dispatched
        assert_eq!(a.rename_input, "   ");
    }
}
