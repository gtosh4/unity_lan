//! The App's render half: every `&self -> Element` view method, plus the small formatting helpers
//! only the renderers use. Split out of `main.rs`, which keeps the state + update/subscription half.

use std::cmp::Reverse;

use iced::alignment::Vertical;
use iced::widget::{
    button, checkbox, column, container, horizontal_space, row, scrollable, text, text_input,
    toggler, tooltip, Column, Row,
};
use iced::window;
use iced::{Color, Element, Length};

use common::control::{ExposeScope, ExposedPort, PeerReach, PeerStatus, Proto, RemoveScope};

use crate::widgets::{
    card, collapsible_header, confirm_controls, dot, fmt_bytes, header, modal, muted, peer_menu,
    AMBER, GREEN, LINK, MUTED, RED,
};
use crate::{App, Confirm, Message, PeerGroup, Tab};

impl App {
    pub(crate) fn view(&self, _window: window::Id) -> Element<'_, Message> {
        let sections = match self.status.as_ref() {
            // Engine reachable — it told us its state. Only offer login when the engine itself says
            // we're not enrolled; otherwise show the live mesh/device UI.
            Some(s) => {
                let mut col = Column::new().spacing(12);
                if s.needs_login {
                    col = col.push(card(self.login_section()));
                } else {
                    // A compact status strip (coordinator + mesh health, connect/disconnect) stays
                    // always visible; everything else — including the account/version detail — lives
                    // under tabs so the peers list (which can grow) and rarely-touched controls don't
                    // crowd it. Tab strip + its content share one bordered panel, so the active tab
                    // visibly owns the surface below it (rather than floating between look-alike cards).
                    let panel = container(column![self.tab_bar(), self.tab_body()].spacing(10))
                        .padding(8)
                        .width(Length::Fill)
                        .style(container::bordered_box);
                    col = col.push_maybe(self.status_strip()).push(panel);
                }
                col
            }
            // Engine not reachable (socket down / not started yet): don't show the login button — it
            // can't work without the daemon, and the mesh/device sections have no data. The engine
            // runs elsewhere (resident service in a packaged install, or the dev-run script), so the
            // GUI just waits for it — a plain notice, no process control here.
            None => Column::new().spacing(12).push(card(self.engine_notice())),
        };
        // Error banner pinned above the sections so a failure is visible without scrolling. It's
        // dismissible, and every successful fetch already clears `self.error`.
        let body = Column::new()
            .spacing(12)
            .push_maybe(self.relaunch_banner())
            .push_maybe(self.error.as_deref().map(error_banner))
            .push(sections)
            .padding(20);
        let content = scrollable(body);
        // Blocking acts on a whole user (all their devices), so it confirms in a modal rather than
        // inline on any one peer row.
        match &self.confirm {
            Some(Confirm::BlockPeer { user_id, username }) => modal(
                content,
                self.block_modal(*user_id, username),
                Message::CancelConfirm,
            ),
            // Exposing a service is the other whole-window dialog: rare enough that its form doesn't
            // earn permanent space in the tab, and long enough that inline it would push the mesh
            // list off the fold.
            _ if self.adding_service => modal(
                content,
                self.add_service_modal(),
                Message::AddServiceOpen(false),
            ),
            _ => content.into(),
        }
    }

    /// The block-user confirmation modal: names the owner and lists every device of theirs currently
    /// in the mesh (so the user sees the full blast radius), then confirm/cancel.
    fn block_modal(&self, user_id: u64, username: &str) -> Element<'_, Message> {
        let devices: Vec<&str> = self
            .status
            .as_ref()
            .map(|s| {
                s.peers
                    .iter()
                    .filter(|p| p.user_id == user_id)
                    .map(|p| p.hostname.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let mut list = Column::new().spacing(2);
        for d in &devices {
            list = list.push(muted(format!("• {d}")));
        }
        let devices_block: Element<'_, Message> = if devices.is_empty() {
            muted("They have no devices in the mesh right now.").into()
        } else {
            list.into()
        };
        let dialog = column![
            header("block user"),
            text(format!(
                "Block {username}? This drops all their devices from your mesh and refuses to peer \
                 with them until you un-block. It's local — they aren't notified and stay in your \
                 shared networks."
            ))
            .size(14),
            devices_block,
            row![
                horizontal_space(),
                button(text("cancel").size(13))
                    .style(button::secondary)
                    .on_press(Message::CancelConfirm),
                button(text("block user").size(13))
                    .style(button::danger)
                    .on_press(Message::BlockPeer {
                        user_id,
                        username: username.to_string(),
                    }),
            ]
            .spacing(8)
            .align_y(Vertical::Center),
        ]
        .spacing(14);
        container(dialog)
            .padding(20)
            .max_width(360)
            .style(container::rounded_box)
            .into()
    }

    /// The three-tab selector under the connection header. Active tab is the loud primary style,
    /// the others quiet secondary; buttons butt together into one segmented strip. Each fills a
    /// third of the width.
    fn tab_bar(&self) -> Element<'_, Message> {
        let tab = |label: &'static str, t: Tab| {
            let b = button(
                text(label)
                    .size(14)
                    .align_x(iced::alignment::Horizontal::Center),
            )
            .width(Length::Fill)
            .on_press(Message::SelectTab(t));
            if self.tab == t {
                b
            } else {
                b.style(button::secondary)
            }
        };
        row![
            tab("Networks", Tab::Networks),
            tab("Peers", Tab::Peers),
            tab("Services", Tab::Services),
            tab("Manage", Tab::Manage),
        ]
        .spacing(2)
        .into()
    }

    /// Sections for the active tab, rendered borderless — the enclosing tab panel is the surface,
    /// so sections are separated by spacing alone (no nested cards). Networks = the ACL groups;
    /// Peers = this device + mesh members; Manage = devices → exposed ports.
    fn tab_body(&self) -> Element<'_, Message> {
        let col = match self.tab {
            Tab::Networks => Column::new().push(self.networks_section()),
            Tab::Peers => Column::new()
                .push(self.device_section())
                .push(self.peers_section()),
            // What the mesh is serving comes first: reaching someone else's service is the everyday
            // reason to open this tab, while exposing one of your own is a thing you do once and
            // rarely revisit. Own services stay below, and adding one is a modal off the button
            // there rather than a form permanently occupying the space above the mesh list.
            Tab::Services => Column::new()
                .push(self.mesh_services_section())
                .push(self.my_services_section()),
            Tab::Manage => Column::new()
                .push(self.account_section())
                .push(self.devices_section())
                // A per-device opt-in, like rename and set-primary — and one that has to be on
                // before the per-service "it's a website" tick does anything. In Services it pushed
                // everyone else's services below the fold, which is what people open that tab for.
                .push_maybe(self.certs_section()),
        };
        col.spacing(18).padding([2, 6]).into()
    }

    /// Shown when we have no status: the control socket isn't reachable, so the engine is either
    /// still starting or not running. Distinct from "not logged in" — offering login here would
    /// just fail against a dead socket.
    fn engine_notice(&self) -> Element<'_, Message> {
        let msg = if self.error.is_some() {
            "Engine not reachable — is the UnityLAN engine running? Retrying automatically."
        } else {
            "Connecting to engine…"
        };
        column![header("engine"), muted(msg)].spacing(6).into()
    }

    /// A prominent top-of-window banner shown once the engine is already running a newer version than
    /// this GUI process — the update swapped both binaries on disk but this window is still the old
    /// code, and the control protocol carries no version, so an unknown field reads as a parse error
    /// rather than a clean failure. One click re-execs onto the swapped-in binary ([`Message::Relaunch`]),
    /// so we surface it loudly rather than leave it as a line buried in the Manage tab.
    fn relaunch_banner(&self) -> Option<Element<'_, Message>> {
        let v = self.status.as_ref().map(|s| s.engine_version.as_str())?;
        if v.is_empty() || v == common::VERSION {
            return None;
        }
        let content = row![
            dot(AMBER),
            text(format!(
                "update installed (v{v}) — restart to finish (this window is still v{})",
                common::VERSION
            ))
            .size(14)
            .width(Length::Fill),
            button(text("restart now").size(13)).on_press(Message::Relaunch),
        ]
        .spacing(8)
        .align_y(Vertical::Center);
        Some(
            container(content)
                .padding(12)
                .width(Length::Fill)
                .style(container::bordered_box)
                .into(),
        )
    }

    /// The always-visible compact status strip above the tabs: coordinator + mesh health as two
    /// dotted items, a connect/disconnect toggle, and (when offered) the update button. The verbose
    /// account/version detail lives in the Manage tab's [`account_section`](Self::account_section)
    /// instead, so this stays one line. The toggle drives mesh connect/disconnect over the control
    /// socket: disconnect keeps the engine resident and polling (instant reconnect) but brings the
    /// interface's link administratively down and drops all peers, withdrawing us from co-members'
    /// seed lists; connect brings the link back up. Hidden until we have a status (need the socket)
    /// and only when enrolled (`!needs_login`).
    fn status_strip(&self) -> Option<Element<'_, Message>> {
        let status = self.status.as_ref()?;
        let connected = status.connected;
        let (mesh_state, label, target, mesh_color) = if connected {
            ("mesh: connected", "disconnect", false, GREEN)
        } else {
            ("mesh: disconnected", "connect", true, MUTED)
        };
        // Disconnect is the destructive direction (drops peers, withdraws us from seed lists) →
        // danger style; connect is benign.
        let b = button(text(label).size(13));
        let b = if connected {
            b.style(button::danger)
        } else {
            b
        };
        let b = if self.connect_busy {
            b
        } else {
            b.on_press(Message::SetConnected(target))
        };
        // Coordinator health (the mesh keeps running from cache when it's offline, so it's a health
        // signal, not the mesh state). Shortened here; the offline caveat is in the Manage account.
        let (coord_color, coord) = if status.coordinator_online {
            (GREEN, "coordinator")
        } else {
            (AMBER, "coordinator: offline")
        };
        let mut strip = row![
            dot(coord_color),
            text(coord).size(13),
            dot(mesh_color),
            text(mesh_state).size(13).width(Length::Fill),
        ]
        .spacing(6)
        .align_y(Vertical::Center);
        // Update button rides the strip when a verified, applyable artifact is staged; the account
        // section carries the matching descriptive notice. Nothing staged → no update surface at all.
        if status.update_available.is_some() && status.update_ready {
            strip = strip.push(button(text("update").size(13)).on_press(Message::ApplyUpdate));
        }
        strip = strip.push(b);
        Some(strip.padding([0, 4]).into())
    }

    /// Account detail, tucked into the Manage tab (out of the always-visible strip): who we're
    /// enrolled as with a log-out control, the update-available notice, and the running version.
    fn account_section(&self) -> Element<'_, Message> {
        let status = self.status.as_ref();
        // Who we're enrolled as, with a log out control (tears the mesh down, un-enrolls, and
        // re-keys → back to the login screen). Destructive, so it arms an inline confirm first.
        let logging_out = self.confirm == Some(Confirm::Logout);
        let identity = status.and_then(|s| s.identity.as_deref()).map(|u| {
            let mut r = row![text(format!("signed in as {u}"))
                .size(14)
                .width(Length::Fill)]
            .spacing(8)
            .align_y(Vertical::Center);
            for e in confirm_controls(
                logging_out,
                "log out",
                true,
                Message::AskConfirm(Confirm::Logout),
                "confirm log out",
                Message::Logout,
            ) {
                r = r.push(e);
            }
            r
        });
        // Coordinator-offline caveat (the strip only shows the short form).
        let coord_line = status.filter(|s| !s.coordinator_online).map(|_| {
            row![
                dot(AMBER),
                muted("coordinator offline — mesh running from cache")
            ]
            .spacing(8)
            .align_y(Vertical::Center)
        });
        // The coordinator refused us on wire protocol version. Red, not amber: unlike "coordinator
        // offline" this never resolves on its own — the mesh is running from cache and will keep
        // decaying until someone updates a side. The engine passes the coordinator's own message
        // through because it names which side is stale.
        let proto_line = status.and_then(|s| s.proto_mismatch.as_deref()).map(|why| {
            row![
                dot(RED),
                text(format!("incompatible with the coordinator — {why}"))
                    .size(14)
                    .width(Length::Fill),
            ]
            .spacing(8)
            .align_y(Vertical::Center)
        });
        // The post-update version-skew prompt is now the top-of-window [`relaunch_banner`], not a line
        // buried here — see that method.
        // Update-available signal — only shown when actionable, i.e. a verified, platform-matching
        // artifact is staged (`update_ready`). A coordinator merely running ahead of us without a
        // rolled `[release]` (or with no artifact for this platform) is intentional and leaves the
        // user nothing to do, so we stay silent rather than nag.
        let update_line = status
            .filter(|s| s.update_ready)
            .and_then(|s| {
                s.update_available
                    .as_deref()
                    .map(|v| (v, s.engine_version.clone()))
            })
            .map(|(v, running)| {
                row![
                    dot(AMBER),
                    text(format!("update available: v{v} (running v{running})"))
                        .size(14)
                        .width(Length::Fill),
                    button(text("update").size(13)).on_press(Message::ApplyUpdate),
                ]
                .spacing(8)
                .align_y(Vertical::Center)
            });
        let version_line = status
            .map(|s| s.engine_version.as_str())
            .filter(|v| !v.is_empty())
            .map(|v| muted(format!("UnityLAN v{v}")));
        column![header("account")]
            .push_maybe(identity)
            .push_maybe(proto_line)
            .push_maybe(coord_line)
            .push_maybe(update_line)
            .push_maybe(version_line)
            .spacing(8)
            .into()
    }

    fn device_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = match self.status.as_ref().and_then(|s| s.device.as_ref())
        {
            Some(d) => {
                // Networks are listed (with toggles) in the networks section below — don't repeat
                // them here. Hostname on top, IP as a muted sub-line — same shape as a peer row, so
                // long FQDNs don't get starved into a mid-token wrap by a fixed IP column.
                let primary = if d.is_primary { "  [primary]" } else { "" };
                column![
                    row![
                        dot(GREEN),
                        text(format!("{}{}", d.hostname, primary))
                            .size(14)
                            .width(Length::Fill),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center),
                    muted(d.wg_ip.to_string()),
                ]
                .spacing(2)
                .into()
            }
            None => row![dot(MUTED), muted("not joined to any network")]
                .spacing(8)
                .align_y(Vertical::Center)
                .into(),
        };
        column![header("this device"), inner].spacing(6).into()
    }

    fn peers_section(&self) -> Element<'_, Message> {
        let peers = self
            .status
            .as_ref()
            .map(|s| s.peers.as_slice())
            .unwrap_or(&[]);
        let mut body = Column::new().spacing(14);
        if peers.is_empty() {
            body = body.push(muted(
                "No peers yet — waiting for co-members to come online.",
            ));
        } else {
            // Partition into my devices / online / offline. Own devices carry the synthetic
            // "My devices" tag from the engine, so a peer holding it is one of ours regardless of
            // liveness; the rest split by WG-handshake liveness (`up`). Each group is sorted by
            // shared-network count (desc), then latency (asc), then handle.
            let is_own = |p: &&PeerStatus| {
                p.networks
                    .iter()
                    .any(|n| n.name == common::control::OWN_DEVICES_LABEL)
            };
            let mut mine: Vec<&PeerStatus> = peers.iter().filter(is_own).collect();
            let mut online: Vec<&PeerStatus> =
                peers.iter().filter(|p| !is_own(p) && p.up).collect();
            let mut offline: Vec<&PeerStatus> =
                peers.iter().filter(|p| !is_own(p) && !p.up).collect();
            for v in [&mut mine, &mut online, &mut offline] {
                v.sort_by_key(|p| peer_sort_key(p, self.latency_ewma.get(&p.wg_ip).copied()));
            }
            for (group, list) in [
                (PeerGroup::Mine, mine),
                (PeerGroup::Online, online),
                (PeerGroup::Offline, offline),
            ] {
                if let Some(section) = self.peer_group_section(group, &list) {
                    body = body.push(section);
                }
            }
        }
        // Blocked users: shown as a separate list (a blocked owner never appears as a peer) so they
        // can be un-blocked even while filtered out of the mesh.
        let blocked = self
            .status
            .as_ref()
            .map(|s| s.blocked.as_slice())
            .unwrap_or(&[]);
        let blocked_section: Option<Element<'_, Message>> = if blocked.is_empty() {
            None
        } else {
            let mut list = Column::new().spacing(6);
            for b in blocked {
                list = list.push(
                    row![
                        text(b.username.clone()).size(14).width(Length::Fill),
                        button(text("unblock").size(13))
                            .style(button::secondary)
                            .on_press(Message::UnblockPeer { user_id: b.user_id }),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center),
                );
            }
            Some(
                column![header(format!("blocked ({})", blocked.len())), list]
                    .spacing(8)
                    .into(),
            )
        };

        body.push_maybe(blocked_section).into()
    }

    /// One collapsible peer group (my devices / online / offline): a clickable header with the count,
    /// and — when expanded — the peer rows. `None` when the group is empty (no header for it).
    fn peer_group_section(
        &self,
        group: PeerGroup,
        peers: &[&PeerStatus],
    ) -> Option<Element<'_, Message>> {
        if peers.is_empty() {
            return None;
        }
        let open = !self.collapsed_groups.contains(&group);
        let head = collapsible_header(
            format!("{} ({})", group.title(), peers.len()),
            open,
            Message::TogglePeerGroup(group),
        );
        let mut col = column![head].spacing(8);
        if open {
            let mut rows = Column::new().spacing(8);
            for p in peers {
                rows = rows.push(self.peer_row(p));
            }
            col = col.push(rows);
        }
        Some(col.into())
    }

    /// One peer's row: status dot + hostname (with last-handshake and shared-network hovers) + the
    /// action kebab, then the status label, address, and telemetry lines.
    fn peer_row(&self, p: &common::control::PeerStatus) -> Element<'_, Message> {
        let ep = p
            .endpoint
            .map(|e| e.to_string())
            .unwrap_or_else(|| "—".to_string());
        let (sc, slabel) = peer_status(p.reach, p.up);
        // Status dot + hostname own the first line so a long FQDN gets the full width. The dot's
        // color is the single health signal (green up / amber connecting / red down); hovering it
        // reveals when WG last handshook — the raw fact behind up/down.
        let hover = match p.last_handshake_secs {
            Some(s) => format!("last handshake {} ago", fmt_ago(s)),
            None => "no handshake yet".to_string(),
        };
        // Hostname carries two hovers' worth of context without cluttering the row: the dot shows WG
        // liveness (last handshake), the name shows which shared networks the peer is reachable over
        // (the ACL intersection). The kebab at the end opens the action menu.
        // Own devices carry every network the owner is in (they peer regardless of ACL), so listing
        // them is noise — just say it's one of ours.
        let is_own = p
            .networks
            .iter()
            .any(|n| n.name == common::control::OWN_DEVICES_LABEL);
        let net_hover = if is_own {
            "one of my devices".to_string()
        } else if p.networks.is_empty() {
            "no shared networks".to_string()
        } else {
            format!(
                "shared networks — {}",
                shared_networks_by_community(&p.networks)
            )
        };
        let name_line = row![
            tooltip(dot(sc), muted(hover), tooltip::Position::Right)
                .padding(6)
                .style(container::rounded_box),
            tooltip(
                text(p.hostname.clone()).size(14),
                muted(net_hover),
                tooltip::Position::Bottom,
            )
            .padding(6)
            .style(container::rounded_box),
            horizontal_space(),
            peer_menu(
                p.hostname.clone(),
                p.wg_ip.to_string(),
                p.wg_ip,
                p.user_id,
                p.username.clone(),
                self.menu_open == Some(p.wg_ip),
            ),
        ]
        .spacing(8)
        .align_y(Vertical::Center);
        // Second line: the status label (same color as the dot, never contradicting it). Blocking is
        // chosen from the kebab menu ("block user") — it acts on the owner, not this device, so it
        // opens a user-scoped modal (see `block_modal`) rather than a per-row confirm.
        let status_line = row![text(slabel).size(13).color(sc).width(Length::Fill)]
            .spacing(8)
            .align_y(Vertical::Center);
        // Telemetry line: latency (last ICMP RTT, only meaningful while up) + transfer totals.
        let mut metrics = Row::new().spacing(10).align_y(Vertical::Center);
        if p.up {
            if let Some(ms) = p.latency_ms {
                metrics = metrics.push(muted(format!("{ms} ms")));
            }
        }
        metrics = metrics.push(muted(format!(
            "rx {}  tx {}",
            fmt_bytes(p.rx_bytes),
            fmt_bytes(p.tx_bytes)
        )));
        let ip_line = muted(format!("{}   {}", p.wg_ip, ep));
        column![name_line, status_line, ip_line, metrics]
            .spacing(2)
            .into()
    }

    fn devices_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = if self.devices.is_empty() {
            muted("No devices yet.").into()
        } else {
            let mut list = Column::new().spacing(6);
            for d in &self.devices {
                let primary = if d.is_primary { "  [primary]" } else { "" };
                let this = if d.is_self { "  (this device)" } else { "" };
                // This device's full mesh name, under the row it names — the thing rename changes,
                // and the name a peer types. Detached at the end of the list it read as belonging
                // to no device in particular. Shown while renaming too: that is when what's being
                // changed most needs spelling out.
                let hostname = d
                    .is_self
                    .then(|| {
                        self.status
                            .as_ref()
                            .and_then(|s| s.device.as_ref())
                            .map(|dev| muted(dev.hostname.clone()))
                    })
                    .flatten();
                // This device's row *is* the rename control: armed, the label becomes the field.
                // A detached "new name" box below the list left you matching a box to a row.
                if d.is_self && self.renaming {
                    let field = row![
                        text_input("new name", &self.rename_input)
                            .on_input(Message::RenameInput)
                            .on_submit(Message::RenameSubmit),
                        button(text("save").size(13)).on_press(Message::RenameSubmit),
                        button(text("cancel").size(13))
                            .style(button::secondary)
                            .on_press(Message::CancelRename),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center);
                    list = list.push(column![field].push_maybe(hostname).spacing(2));
                    continue;
                }
                let mut r = row![text(format!("{}{}{}", d.device_name, primary, this))
                    .size(14)
                    .width(Length::Fill)]
                .spacing(8)
                .align_y(Vertical::Center);
                if d.is_self {
                    r = r.push(
                        button(text("rename").size(13))
                            .style(button::secondary)
                            .on_press(Message::StartRename(d.device_name.clone())),
                    );
                }
                if !d.is_primary {
                    r = r.push(
                        button(text("set primary").size(13))
                            .style(button::secondary)
                            .on_press(Message::SetPrimary(d.device_name.clone())),
                    );
                }
                if !d.is_self {
                    // Remove is destructive → arm an inline confirm first (one misclick otherwise
                    // drops the device).
                    let removing =
                        self.confirm == Some(Confirm::RemoveDevice(d.device_name.clone()));
                    for e in confirm_controls(
                        removing,
                        "remove",
                        true,
                        Message::AskConfirm(Confirm::RemoveDevice(d.device_name.clone())),
                        "confirm remove",
                        Message::Remove(d.device_name.clone()),
                    ) {
                        r = r.push(e);
                    }
                }
                // This device's full mesh name, under the row it names — the thing rename changes,
                // and the name a peer types. Detached at the end of the list it read as belonging
                // to no device in particular.
                let hostname = d
                    .is_self
                    .then(|| {
                        self.status
                            .as_ref()
                            .and_then(|s| s.device.as_ref())
                            .map(|dev| muted(dev.hostname.clone()))
                    })
                    .flatten();
                list = list.push(column![r].push_maybe(hostname).spacing(2));
            }
            list.into()
        };

        column![header("devices"), inner].spacing(8).into()
    }

    fn login_section(&self) -> Element<'_, Message> {
        let mut col = column![
            header("Not logged in"),
            muted("Sign in with Discord to join your mesh."),
            button(text("Log in with Discord")).on_press(Message::Login),
        ]
        .spacing(8);
        if let Some(url) = &self.login_url {
            col = col
                .push(muted(
                    "Browser opened — if not, use the buttons below to finish.",
                ))
                .push(
                    row![
                        button(text("Open Discord login").size(13))
                            .on_press(Message::OpenUrl(url.clone())),
                        button(text("Copy link").size(13)).on_press(Message::CopyText(url.clone())),
                    ]
                    .spacing(8),
                );
        }
        col.into()
    }

    /// The networks in the latest status, or empty before the first one lands.
    fn networks(&self) -> &[common::api::NetworkStatus] {
        self.status
            .as_ref()
            .map(|s| s.networks.as_slice())
            .unwrap_or(&[])
    }

    fn networks_section(&self) -> Element<'_, Message> {
        let nets = self.networks();
        // Secure default: newly-discovered networks stay off until enabled here. No status yet
        // (socket not up) → assume the secure posture. Sits at the top of the card: it's a
        // section-wide policy governing the list below, not a per-network control.
        let disable_new = self.status.as_ref().is_none_or(|s| s.disable_new_networks);
        let policy = checkbox("Disable new networks on discovery", disable_new)
            .on_toggle(Message::SetNewNetworkDefault)
            .size(16)
            .text_size(14);
        // Own devices are shown as a special network-style row (same toggler treatment), always
        // present since own-device peering exists regardless of network membership. It leads the
        // list; the real networks follow.
        let own_devices = self.status.as_ref().is_none_or(|s| s.peer_own_devices);
        let own_row = row![
            toggler(own_devices)
                .width(Length::Shrink)
                .on_toggle(Message::SetOwnDevicePeering),
            text(common::control::OWN_DEVICES_LABEL)
                .size(14)
                .width(Length::Fill),
        ]
        .spacing(8)
        .align_y(Vertical::Center);
        let mut list = Column::new().spacing(6).push(own_row);
        if nets.is_empty() {
            list = list.push(muted("No other networks discovered yet."));
        } else {
            // Group by guild the same way the peer hover does (`shared_networks_by_community`), so a
            // network reads the same in both places: a guild heading with its roles beneath. Guilds
            // and roles keep first-seen (coordinator snapshot) order.
            let mut groups: Vec<(&str, Vec<&common::api::NetworkStatus>)> = Vec::new();
            for n in nets {
                match groups.iter_mut().find(|(g, _)| *g == n.guild_name.as_str()) {
                    Some((_, v)) => v.push(n),
                    None => groups.push((n.guild_name.as_str(), vec![n])),
                }
            }
            for (guild, members) in groups {
                let mut roles = Column::new().spacing(6);
                for n in members {
                    // A switch (not a button): flipping it applies immediately, and its position
                    // shows the current state — no separate on/off label needed. Switch on the left
                    // so the controls line up in one column with the policy checkbox above.
                    let (guild_id, role_id) = (n.guild_id, n.role_id);
                    roles = roles.push(
                        row![
                            toggler(n.enabled)
                                .width(Length::Shrink)
                                .on_toggle(move |enabled| {
                                    Message::ToggleNetwork {
                                        guild_id,
                                        role_id,
                                        enabled,
                                    }
                                }),
                            text(n.name.clone()).size(14).width(Length::Fill),
                        ]
                        .spacing(8)
                        .align_y(Vertical::Center),
                    );
                }
                // A guild heading over its indented roles; guildless rows (shouldn't occur for real
                // networks) sit flush like the "My devices" row above.
                if guild.is_empty() {
                    list = list.push(roles);
                } else {
                    list = list.push(
                        column![
                            muted(guild.to_string()),
                            roles.padding(iced::padding::left(16))
                        ]
                        .spacing(6),
                    );
                }
            }
        }
        // No `header("networks")`: the tab strip directly above already says Networks, and
        // repeating it costs a line of a 440px window to say nothing.
        column![policy, list].spacing(8).into()
    }

    /// This device's own named services, plus the form that adds one.
    ///
    /// A service is an exposed port with a name, so this reads the same `exposed` list the Manage
    /// tab does — grouped by name rather than by port, because the name is what a person uses.
    /// The name to *show* for a service.
    ///
    /// A web service is served on 443 by its owner's proxy under a certificate covering the
    /// deployment's public domain — so the `.internal` spelling, however well it resolves, is the
    /// one a browser rejects on a name mismatch. Show the name that works. Everything else, and any
    /// deployment that issues no certificates at all, keeps its mesh name.
    pub(crate) fn browser_name(&self, web: bool, mesh_name: &str) -> String {
        let domain = self
            .status
            .as_ref()
            .and_then(|s| s.cert.domain.as_deref())
            .filter(|_| web);
        domain
            .and_then(|d| common::service::certificate_alias(mesh_name, d))
            .unwrap_or_else(|| mesh_name.to_string())
    }

    /// The service's browser-facing name, as a **link** when it is a web service — the point of
    /// marking one `web` is that a browser opens it, so the name is the thing to click. Anything else
    /// is plain text: there is nothing a click could do with `tcp/25565`.
    ///
    /// The target is the same reach the row already prints, so clicking makes no claim the display
    /// does not: `https://<name>/` where the deployment issues certificates (the proxy serves 443
    /// under that name), else the backend port over plain HTTP on the mesh name, which is what a
    /// device with no certificate actually answers on.
    fn service_link(&self, web: bool, mesh_name: &str, port: Option<u16>) -> Element<'_, Message> {
        let name = self.browser_name(web, mesh_name);
        let certified = self
            .status
            .as_ref()
            .is_some_and(|s| s.cert.domain.is_some());
        match service_url(&name, web, certified, port) {
            // Colored, because a clickable name that looks exactly like the row above it is only
            // discoverable by clicking things at random. Link blue is the one convention every user
            // already knows; the underline iced has no primitive for is not what carries the meaning.
            Some(url) => button(text(name).size(14).color(LINK))
                .style(button::text)
                .padding(0)
                .on_press(Message::OpenUrl(url))
                .into(),
            None => text(name).size(14).into(),
        }
    }

    fn my_services_section(&self) -> Element<'_, Message> {
        // From the *hostname*, not `identity` — that is the Discord handle, which may carry a
        // discriminator or characters DNS refuses, while the `<user>` label was allocated by the
        // coordinator. Composing from the handle prints a name that never resolves.
        let hostname = self
            .status
            .as_ref()
            .and_then(|s| s.device.as_ref())
            .map(|d| d.hostname.clone())
            .unwrap_or_default();
        let mut names: Vec<&str> = self
            .exposed
            .iter()
            .filter_map(|e| e.name.as_deref())
            .collect();
        names.sort_unstable();
        names.dedup();
        // Names someone chose come first. A list led by `port-51820` buries the service they
        // actually named, and the defaulted ones are the entries nobody has been back to.
        names.sort_by_key(|n| common::service::is_default_label(n));

        let inner: Element<'_, Message> = if names.is_empty() {
            muted("Nothing named yet. A name makes a port memorable: `mc`, `jellyfin`.").into()
        } else {
            let mut list = Column::new().spacing(10);
            for name in names {
                let mut chips = Row::new().spacing(6).align_y(Vertical::Center);
                for e in self
                    .exposed
                    .iter()
                    .filter(|e| e.name.as_deref() == Some(name))
                {
                    chips = chips.push(scope_chip(e));
                }
                // Removing a scope is one click on its chip; adding one used to mean retyping the
                // name and port in the form below, where a mistyped port gives the name a second
                // port instead of widening it. So: the same row, the other direction.
                let widen_open = self.widening.as_deref() == Some(name);
                chips = chips.push(
                    button(text(if widen_open { "cancel" } else { "+" }).size(13))
                        .style(button::text)
                        .padding([0, 4])
                        .on_press(Message::WidenOpen((!widen_open).then(|| name.to_string()))),
                );
                // One port per line, however many scopes carry it: the scopes are the chips below,
                // and repeating `tcp/8080` once per scope reads as two services on one name.
                let mut ports: Vec<String> = self
                    .exposed
                    .iter()
                    .filter(|e| e.name.as_deref() == Some(name))
                    .map(|e| format!("{}/{}", e.proto.as_str(), e.port))
                    .collect();
                // Sorted before dedup: `dedup` only drops *consecutive* repeats, and two exposures
                // of one port need not be adjacent in the list.
                ports.sort_unstable();
                ports.dedup();
                let web = self
                    .exposed
                    .iter()
                    .filter(|e| e.name.as_deref() == Some(name))
                    .any(|e| e.kind == common::service::ServiceKind::Web);
                let mesh_name = common::service::service_name(&hostname, name)
                    .unwrap_or_else(|| name.to_string());
                // The exposed port of a web service is the loopback backend the proxy forwards to,
                // so it is not the thing to dial — say what it is instead of printing it alone.
                let detail = if web {
                    format!("https  ·  {} behind it", ports.join(", "))
                } else {
                    ports.join(", ")
                };
                let web_port = self
                    .exposed
                    .iter()
                    .find(|e| {
                        e.name.as_deref() == Some(name)
                            && e.kind == common::service::ServiceKind::Web
                    })
                    .map(|e| e.port);
                let head = row![
                    column![self.service_link(web, &mesh_name, web_port), muted(detail)]
                        .spacing(2)
                        .width(Length::Fill),
                    button(text("remove").size(13))
                        .style(button::secondary)
                        .on_press(Message::RemoveService(name.to_string())),
                ]
                .spacing(8)
                .align_y(Vertical::Center);
                let mut entry = column![head, chips].spacing(4);
                if widen_open {
                    entry = entry.push(self.widen_picker(name));
                }
                list = list.push(entry);
            }
            list.into()
        };

        // Exposing is rare next to reading this list, so the form is a modal off this button rather
        // than a permanent row of inputs.
        let head = row![
            header("my services"),
            horizontal_space(),
            button(text("expose a service").size(13))
                .style(button::secondary)
                .on_press(Message::AddServiceOpen(true)),
        ]
        .spacing(8)
        .align_y(Vertical::Center);
        column![head, inner].spacing(8).into()
    }

    /// The add-a-service form, shown as a modal from the Services tab's "expose a service" button.
    ///
    /// Same drafts the section used inline before, laid out down the dialog rather than across one
    /// row — a modal has the width for a label per field, so `name` / `port` / who-can-reach-it stop
    /// being three placeholder-only boxes.
    fn add_service_modal(&self) -> Element<'_, Message> {
        let name_err = (!self.service_name_input.trim().is_empty()
            && !common::service::valid_label(self.service_name_input.trim()))
        .then(|| common::service::label_error(self.service_name_input.trim()));
        let port_err = (!self.expose_port_input.trim().is_empty())
            .then(|| parse_port(self.expose_port_input.trim()).err())
            .flatten();
        let ready = name_err.is_none()
            && port_err.is_none()
            && common::service::valid_label(self.service_name_input.trim())
            && !self.expose_port_input.trim().is_empty()
            && !self.expose_scopes.is_empty();

        let fields = column![
            column![
                muted("name"),
                text_input("mc", &self.service_name_input)
                    .on_input(Message::ServiceNameInput)
                    .on_submit(Message::ServiceSubmit),
            ]
            .spacing(2),
            column![
                muted("port"),
                row![
                    text_input("25565", &self.expose_port_input)
                        .on_input(Message::ExposePortInput)
                        .on_submit(Message::ServiceSubmit)
                        .width(Length::Fixed(80.0)),
                    proto_toggle(self.expose_proto),
                ]
                .spacing(6)
                .align_y(Vertical::Center),
            ]
            .spacing(2),
            column![muted("who can reach it"), self.scope_picker()].spacing(2),
        ]
        .spacing(12);

        let mut col = column![header("expose a service"), fields].spacing(14);
        // Validation errors and the last action error both belong in here: the top-of-window banner
        // sits on the dimmed base, where the dialog covering it makes it something you can't read.
        for e in [name_err, port_err, self.error.clone()]
            .into_iter()
            .flatten()
        {
            col = col.push(text(e).size(13).color(RED));
        }
        // The web tick only appears where it can do anything: it puts the name in this device's
        // certificate, so it needs a deployment that issues them and the opt-in already on. When the
        // deployment issues them but this device hasn't opted in, say where that lives — the setting
        // lives in Manage, and a tick that is simply absent is a dead end.
        let certs = self.status.as_ref().map(|s| &s.cert);
        if certs.is_some_and(|c| c.domain.is_some() && !c.enabled) {
            col = col.push(muted(
                "To serve this over HTTPS, turn on the certificate for this device in Manage.",
            ));
        }
        if certs.is_some_and(|c| c.domain.is_some() && c.enabled) {
            col = col.push(
                checkbox(
                    "It's a website — put this name in my HTTPS certificate",
                    self.service_web,
                )
                .on_toggle(Message::ServiceWeb)
                .size(16)
                .text_size(13),
            );
            if self.service_web {
                col = col.push(
                    text("Publishes this service's name to public certificate logs, permanently.")
                        .size(12)
                        .color(AMBER),
                );
            }
        }
        col = col.push(
            row![
                horizontal_space(),
                button(text("cancel").size(13))
                    .style(button::secondary)
                    .on_press(Message::AddServiceOpen(false)),
                {
                    let b = button(text("expose").size(13));
                    if ready {
                        b.on_press(Message::ServiceSubmit)
                    } else {
                        b.style(button::secondary)
                    }
                },
            ]
            .spacing(8)
            .align_y(Vertical::Center),
        );
        container(col)
            .padding(20)
            .max_width(360)
            .style(container::rounded_box)
            .into()
    }

    /// What everyone else is serving, grouped by the device serving it — the "what's on this mesh"
    /// view. Per device rather than per person: one owner can serve different names from different
    /// machines, and the header is the thing you'd actually reach.
    ///
    /// Peers announce these directly over the tunnel, so a peer that is offline simply isn't here.
    fn mesh_services_section(&self) -> Element<'_, Message> {
        let peers: Vec<&common::control::PeerStatus> = self
            .status
            .as_ref()
            .map(|s| s.peers.iter().filter(|p| !p.services.is_empty()).collect())
            .unwrap_or_default();

        let inner: Element<'_, Message> = if peers.is_empty() {
            muted("No one else is serving a named service right now.").into()
        } else {
            let mut list = Column::new().spacing(12);
            for peer in peers {
                let mut rows = Column::new().spacing(4);
                for svc in &peer.services {
                    // A shadowed service is running but its name points at another of the owner's
                    // devices — worth saying, since the fix is theirs to make and invisible
                    // otherwise.
                    let web = svc.kind == common::service::ServiceKind::Web;
                    // Their backend port is no more dialable than ours — a web service is reached
                    // through their proxy on 443, so `https` is the whole of what a visitor needs.
                    let reach = if web {
                        "https".to_string()
                    } else {
                        format!("{}/{}", svc.proto.as_str(), svc.port)
                    };
                    let line = row![
                        dot(if svc.shadowed {
                            AMBER
                        } else if peer.up {
                            GREEN
                        } else {
                            RED
                        }),
                        column![
                            self.service_link(web, &svc.hostname, Some(svc.port)),
                            muted(if svc.shadowed {
                                format!("{reach} — name taken by another of their devices")
                            } else {
                                reach
                            }),
                        ]
                        .spacing(2),
                    ]
                    .spacing(8)
                    .align_y(Vertical::Center);
                    rows = rows.push(line);
                }
                // The device, not the owner: every name below already ends in the owner's label, and
                // two of their machines each serving something gave two identical headings with
                // nothing to tell you which held what.
                list = list.push(column![muted(peer.hostname.clone()), rows].spacing(4));
            }
            list.into()
        };
        column![header("on the mesh"), inner].spacing(8).into()
    }

    /// The HTTPS-certificate opt-in: a per-*device* setting, so it lives in Manage beside the other
    /// ones. Which service names go *into* that certificate is the per-service tick in the Services
    /// tab — this is only whether the device holds one at all.
    ///
    /// Hidden unless the deployment issues certificates at all **and** either a port is exposed or
    /// the pref is already on. That second arm matters — without it, closing your last port would
    /// hide the control and strand the pref on with no way to turn it off.
    fn certs_section(&self) -> Option<Element<'_, Message>> {
        let cert = &self.status.as_ref()?.cert;
        cert.domain.as_ref()?;
        if self.exposed.is_empty() && !cert.enabled {
            return None;
        }

        let toggle = checkbox("Get an HTTPS certificate for this device", cert.enabled)
            .on_toggle(Message::SetCertsEnabled)
            .size(16)
            .text_size(14);
        let mut col = column![toggle].spacing(6);
        // The warning sits at the decision, not in the docs: this is the moment the choice is made,
        // and it cannot be walked back.
        col = col.push(
            text(
                "Publishes this device's name to public certificate logs, permanently. \
                 Turning this off later does not remove it.",
            )
            .size(12)
            .color(AMBER),
        );
        if cert.enabled {
            if let Some(path) = &cert.cert_path {
                col = col.push(muted(format!("Certificate: {path}")));
                if let Some(key) = &cert.key_path {
                    col = col.push(muted(format!("Private key: {key}")));
                }
            } else if let Some(why) = &cert.blocked {
                col = col.push(text(why.clone()).size(12).color(AMBER));
            } else {
                col = col.push(muted("Requesting…"));
            }
        }
        Some(column![header("https certificate"), col].spacing(8).into())
    }

    /// The scopes the service called `name` could still be offered to.
    ///
    /// `None` when it is already open to every peer — an exposure made before that stopped being
    /// offered. Nothing is wider, so every scope here would be a click that changes no access while
    /// adding a chip implying a restriction.
    ///
    /// Scopes it already holds are dropped: they are the chips beside the `+`, and re-offering one
    /// is a click that does nothing. All-peers is not in [`Self::selectable_scopes`] at all, so it
    /// cannot be offered here either — widening names a network, like every other kind of sharing.
    pub(crate) fn widenable_scopes(&self, name: &str) -> Option<Vec<(ExposeScope, String)>> {
        let held: Vec<&ExposeScope> = self
            .exposed
            .iter()
            .filter(|e| e.name.as_deref() == Some(name))
            .map(|e| &e.scope)
            .collect();
        if held.contains(&&ExposeScope::AllPeers) {
            return None;
        }
        Some(
            self.selectable_scopes()
                .into_iter()
                .filter(|(scope, _)| !held.contains(&scope))
                .collect(),
        )
    }

    /// One click per network this service could also be offered to. No port to confirm — the engine
    /// takes the ports from the name, which is the whole point of widening this way.
    fn widen_picker(&self, name: &str) -> Element<'_, Message> {
        let Some(scopes) = self.widenable_scopes(name) else {
            return muted("already offered to every peer you mesh with").into();
        };
        if scopes.is_empty() {
            return muted("already offered to every network you're in").into();
        }
        let mut col = Column::new().spacing(4).padding([0, 8]);
        for (scope, label) in scopes {
            let name = name.to_string();
            col = col.push(
                button(text(format!("offer to {label}")).size(13))
                    .style(button::secondary)
                    .on_press(Message::Widen { name, scope }),
            );
        }
        col.into()
    }

    /// The multi-select scope picker. Collapsed it reports the selection; expanded it offers
    /// all-peers, own-devices, and every network this device holds.
    fn scope_picker(&self) -> Element<'_, Message> {
        let summary = match self.expose_scopes.as_slice() {
            [] => "scope".to_string(),
            [one] => self.scope_label(one),
            many => format!("{} scopes", many.len()),
        };
        let toggle = button(text(summary).size(13))
            .style(button::secondary)
            .width(Length::Fill)
            .on_press(Message::ExposeScopeToggleOpen);
        if !self.expose_scope_open {
            return toggle.into();
        }

        let mut opts = Column::new().spacing(4).push(toggle);
        for (scope, label) in self.selectable_scopes() {
            let on = self.expose_scopes.contains(&scope);
            opts = opts.push(
                checkbox(label, on)
                    .size(15)
                    .text_size(13)
                    .on_toggle(move |v| Message::ExposeScopeToggle(scope.clone(), v)),
            );
        }
        opts.into()
    }

    /// Scopes offered in the picker, each with the label to show for it: the owner's own devices,
    /// then every network this device holds. Building the list from held networks is what keeps a
    /// typo — or a network the engine would reject — from being expressible at all.
    ///
    /// **Every peer is not on the list.** It was, and it was the easiest thing to pick: one click,
    /// no thought, and the widest sharing the mesh can express — the wrong shape for a decision
    /// about who reaches a port on your machine. Sharing now names who, every time. An exposure
    /// that already has it keeps working and still shows its chip; there is just no way to choose
    /// it afresh.
    ///
    /// Each network is offered per `(guild_id, role_id)`, never merged by role name: two guilds may
    /// each have an `Engineering`, they are different networks with different members, and
    /// collapsing them into one row would offer a scope that admits both. The name is only ever the
    /// label; the scope the picker emits carries ids.
    pub(crate) fn selectable_scopes(&self) -> Vec<(ExposeScope, String)> {
        let mut out = vec![(
            ExposeScope::OwnDevices,
            ExposeScope::OwnDevices.fallback_label(),
        )];
        for n in self.networks() {
            let scope = ExposeScope::Net {
                guild_id: n.guild_id,
                role_id: n.role_id,
            };
            if !out.iter().any(|(s, _)| s == &scope) {
                let label = if n.guild_name.is_empty() {
                    n.name.clone()
                } else {
                    format!("{} @ {}", n.name, n.guild_name)
                };
                out.push((scope, label));
            }
        }
        out
    }

    /// How to render a scope the picker holds — looked up in the same list the picker was built
    /// from, since the scope itself carries only ids.
    fn scope_label(&self, scope: &ExposeScope) -> String {
        self.selectable_scopes()
            .into_iter()
            .find(|(s, _)| s == scope)
            .map_or_else(|| scope.fallback_label(), |(_, l)| l)
    }
}

/// TCP/UDP as a two-button segmented control — the protocol is a binary choice, not something to
/// spell correctly in a text field.
fn proto_toggle(current: Proto) -> Element<'static, Message> {
    let seg = |p: Proto, label: &str| {
        let b = button(text(label.to_string()).size(13));
        if p == current {
            b.style(button::primary)
        } else {
            b.style(button::secondary).on_press(Message::ExposeProto(p))
        }
    };
    row![seg(Proto::Tcp, "TCP"), seg(Proto::Udp, "UDP")]
        .spacing(4)
        .into()
}

/// One scope of an exposed port, with its own close button. An exposure whose peers are all
/// offline is dimmed and marked — the rule is installed but nothing can currently reach it, and a
/// chip that looked identical to a live one would read as working.
fn scope_chip(e: &ExposedPort) -> Element<'_, Message> {
    // The engine resolves the scope's ids to a name for us; a frontend can't do that lookup itself.
    // An engine older than the `label` field sends none, so fall back to what the scope can say on
    // its own — an unlabelled chip would render as an empty box with a close button.
    let name = if e.label.is_empty() {
        e.scope.fallback_label()
    } else {
        e.label.clone()
    };
    let label = if e.active {
        name
    } else {
        format!("{name} (nobody online)")
    };
    let body = row![
        text(label)
            .size(13)
            .color(if e.active { MUTED } else { AMBER }),
        button(text("x").size(11))
            .style(button::text)
            .padding(0)
            .on_press(Message::Unexpose {
                proto: e.proto,
                port: e.port,
                scope: RemoveScope::Exact(e.scope.clone()),
            }),
    ]
    .spacing(4)
    .align_y(Vertical::Center);
    container(body)
        .padding([2, 6])
        .style(container::bordered_box)
        .into()
}

/// Sort key ordering peers within a group: most shared networks first, then lowest latency, then
/// handle (case-insensitive) as a stable tiebreak. `latency` is the caller's *smoothed* (EWMA) RTT,
/// not the raw per-poll reading, so the order settles instead of flickering; `None` (offline / no
/// reply yet) sorts last.
pub(crate) fn peer_sort_key(
    p: &common::control::PeerStatus,
    latency: Option<u32>,
) -> (Reverse<usize>, u32, String) {
    (
        Reverse(p.networks.len()),
        latency.unwrap_or(u32::MAX),
        p.username.to_lowercase(),
    )
}

/// Status color + short label for a peer's reachability. Free fn so the palette stays in one place.
/// One color axis: green = the tunnel is up (however it's reached), amber = still connecting,
/// red = down. The label carries the path detail (`direct`/`relayed`/`ice`) or the reason it's not
/// up — so the dot never contradicts the word.
fn peer_status(reach: PeerReach, up: bool) -> (Color, &'static str) {
    match (up, reach) {
        (true, PeerReach::Relayed) => (GREEN, "relayed"),
        (true, PeerReach::Ice) => (GREEN, "ice"),
        (true, _) => (GREEN, "direct"),
        (false, PeerReach::Punching) => (AMBER, "connecting"),
        (false, PeerReach::Unreachable) => (RED, "unreachable"),
        (false, _) => (RED, "down"),
    }
}

/// A compact "time since" for the last-handshake hover, e.g. `12s`, `4m`, `2h`, `3d`.
fn fmt_ago(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Render a peer's shared networks grouped by the community (server) each lives in, e.g.
/// `gaming: mesh, raiders · work: staff`. Community is the disambiguator now that it's out of the
/// hostname — a peer met across two servers is one device, so its networks carry the server tag.
/// Communities and networks appear in first-seen order (the coordinator's stable snapshot order).
pub(crate) fn shared_networks_by_community(networks: &[common::api::SharedNetwork]) -> String {
    let mut groups: Vec<(&str, Vec<&str>)> = Vec::new();
    for n in networks {
        match groups.iter_mut().find(|(c, _)| *c == n.community) {
            Some((_, names)) => names.push(&n.name),
            None => groups.push((&n.community, vec![&n.name])),
        }
    }
    groups
        .iter()
        .map(|(community, names)| {
            // The synthetic "My devices" group has no community — show its name bare, no `: ` prefix.
            if community.is_empty() {
                names.join(", ")
            } else {
                format!("{}: {}", community, names.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// A dismissible error banner, pinned above the sections in `view`.
fn error_banner<'a>(e: &str) -> Element<'a, Message> {
    let content = row![
        dot(RED),
        text(format!("error: {e}"))
            .size(14)
            .color(RED)
            .width(Length::Fill),
        button(text("dismiss").size(12)).on_press(Message::DismissError),
    ]
    .spacing(8)
    .align_y(Vertical::Center);
    container(content)
        .padding(12)
        .width(Length::Fill)
        .style(container::bordered_box)
        .into()
}

/// Parse the port field. The protocol is a separate control now, so this is just the number —
/// 1..=65535, since 0 is not a port anything can listen on.
/// Where a service's name should take a browser, or `None` for a row that is not a link.
///
/// Only web services are links, and the target is the reach the row already prints — never a guess:
/// `https://<name>/` once the deployment issues certificates (the proxy serves 443 under that name),
/// otherwise the backend port over plain HTTP, which is what an uncertified device answers on. A web
/// service with neither is left as text rather than pointed somewhere nothing listens.
pub(crate) fn service_url(
    name: &str,
    web: bool,
    certified: bool,
    port: Option<u16>,
) -> Option<String> {
    match (web, certified, port) {
        (false, _, _) => None,
        (true, true, _) => Some(format!("https://{name}/")),
        (true, false, Some(port)) => Some(format!("http://{name}:{port}/")),
        (true, false, None) => None,
    }
}

pub(crate) fn parse_port(s: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("'{s}' is not a port (1-65535)")),
        Ok(p) => Ok(p),
    }
}
