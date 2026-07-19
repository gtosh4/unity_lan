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

use common::control::{PeerReach, PeerStatus, Proto};

use crate::widgets::{
    card, collapsible_header, confirm_controls, dot, fmt_bytes, header, modal, muted, peer_menu,
    AMBER, GREEN, MUTED, RED,
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
            Tab::Manage => Column::new()
                .push(self.account_section())
                .push(self.devices_section())
                .push(self.exposed_section()),
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

    /// Mesh connect/disconnect over the control socket. Disconnect keeps the engine resident and
    /// polling (instant reconnect) but brings the interface's link administratively down and drops
    /// all peers, withdrawing us from co-members' seed lists. Connect brings the link back up.
    /// Hidden until we have a status (need the socket) and only when enrolled (`!needs_login`).
    /// The always-visible compact status strip above the tabs: coordinator + mesh health as two
    /// dotted items, a connect/disconnect toggle, and (when offered) the update button. The verbose
    /// account/version detail lives in the Manage tab's [`account_section`](Self::account_section)
    /// instead, so this stays one line.
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
                v.sort_by_key(|p| peer_sort_key(p));
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
                let mut r = row![text(format!("{}{}{}", d.device_name, primary, this))
                    .size(14)
                    .width(Length::Fill)]
                .spacing(8)
                .align_y(Vertical::Center);
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
                list = list.push(r);
            }
            list.into()
        };

        // Rename this device. Show the current hostname so it's clear what's being changed.
        let current = self
            .status
            .as_ref()
            .and_then(|s| s.device.as_ref())
            .map(|d| muted(format!("current: {}", d.hostname)));
        let rename = row![
            text_input("new name for this device", &self.rename_input)
                .on_input(Message::RenameInput)
                .on_submit(Message::RenameSubmit),
            button(text("rename").size(13))
                .style(button::secondary)
                .on_press(Message::RenameSubmit),
        ]
        .spacing(8);

        column![header("devices"), inner]
            .push_maybe(current)
            .push(rename)
            .spacing(8)
            .into()
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

    fn networks_section(&self) -> Element<'_, Message> {
        let nets = self
            .status
            .as_ref()
            .map(|s| s.networks.as_slice())
            .unwrap_or(&[]);
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
        column![header("networks"), policy, list].spacing(8).into()
    }

    fn exposed_section(&self) -> Element<'_, Message> {
        let inner: Element<'_, Message> = if self.exposed.is_empty() {
            muted("No ports exposed.").into()
        } else {
            let mut list = Column::new().spacing(6);
            for e in &self.exposed {
                let scope = e
                    .net
                    .as_deref()
                    .map(|n| format!("  → net: {n}"))
                    .unwrap_or_default();
                // A scoped port with no online peers is open in the ruleset but unreachable —
                // say so, or the row reads as working.
                let idle = if e.active { "" } else { "  (no peers online)" };
                let r = row![
                    text(format!("{}/{}{}{}", e.proto.as_str(), e.port, scope, idle))
                        .size(14)
                        .width(Length::Fill),
                    button(text("unexpose").size(13)).on_press(Message::Unexpose {
                        proto: e.proto,
                        port: e.port,
                        net: e.net.clone(),
                    }),
                ]
                .spacing(8)
                .align_y(Vertical::Center);
                list = list.push(r);
            }
            list.into()
        };

        // Add row: port (e.g. `25565` or `udp/34197`) + optional network to scope it to.
        let add = row![
            text_input("port (e.g. 25565 or udp/34197)", &self.expose_port_input)
                .on_input(Message::ExposePortInput)
                .on_submit(Message::ExposeSubmit),
            text_input("net (optional)", &self.expose_net_input)
                .on_input(Message::ExposeNetInput)
                .on_submit(Message::ExposeSubmit),
            button(text("expose").size(13))
                .style(button::secondary)
                .on_press(Message::ExposeSubmit),
        ]
        .spacing(8);

        column![
            header("exposed ports"),
            inner,
            add,
            muted("tcp is the default; write udp/34197 for UDP. Leave net blank to expose on all."),
        ]
        .spacing(8)
        .into()
    }
}

/// Status color + short label for a peer's reachability. Free fn so the palette stays in one place.
/// A peer's status as a single health color plus a label. One color axis: green = the tunnel is up
/// (however it's reached), amber = still connecting, red = down. The label carries the path detail
/// (`direct`/`relayed`/`ice`) or the reason it's not up — so the dot never contradicts the word.
/// Sort key ordering peers within a group: most shared networks first, then lowest latency (a peer
/// with no RTT reading — offline / no reply — sorts last), then handle (case-insensitive) as a
/// stable tiebreak.
pub(crate) fn peer_sort_key(p: &common::control::PeerStatus) -> (Reverse<usize>, u32, String) {
    (
        Reverse(p.networks.len()),
        p.latency_ms.unwrap_or(u32::MAX),
        p.username.to_lowercase(),
    )
}

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

/// Parse a port field: `25565` (tcp default) or `tcp/25565` / `udp/34197`.
pub(crate) fn parse_port(s: &str) -> Result<(Proto, u16), String> {
    let (proto, port) = match s.split_once('/') {
        Some((p, n)) => {
            let proto = match p.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                other => return Err(format!("bad protocol '{other}' (use tcp or udp)")),
            };
            (proto, n)
        }
        None => (Proto::Tcp, s),
    };
    port.parse()
        .map(|p| (proto, p))
        .map_err(|_| format!("bad port '{port}'"))
}
