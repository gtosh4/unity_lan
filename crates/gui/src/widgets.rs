//! Reusable, App-independent presentation pieces: the status palette, inline SVG icons, small text
//! helpers, and the widget builders (menus, modal, card, confirm controls) the views compose from.

use std::net::Ipv4Addr;

use iced::alignment::Vertical;
use iced::font::Weight;
use iced::widget::{
    button, center, column, container, mouse_area, opaque, row, stack, svg, text, Text,
};
use iced::{Color, Element, Font, Length, Theme};
use iced_aw::{drop_down, DropDown};

use crate::{Confirm, Message};

// Palette — semantic status colors, tuned for the dark theme. `Color` literals are const.
pub(crate) const GREEN: Color = Color::from_rgb(0.30, 0.78, 0.47); // healthy / connected / direct
pub(crate) const AMBER: Color = Color::from_rgb(0.93, 0.69, 0.22); // in-progress / degraded
pub(crate) const RED: Color = Color::from_rgb(0.90, 0.37, 0.37); // failed / unreachable / destructive
pub(crate) const MUTED: Color = Color::from_rgb(0.74, 0.74, 0.80); // secondary text (IPs, endpoints, hints)

/// A section title: slightly larger and semibold so sections read as a hierarchy above their rows.
pub(crate) fn header<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).size(16).font(Font {
        weight: Weight::Semibold,
        ..Font::DEFAULT
    })
}

/// De-emphasized secondary text (endpoints, hints, current-value notes).
pub(crate) fn muted<'a>(s: impl Into<String>) -> Text<'a> {
    text(s.into()).size(13).color(MUTED)
}

/// Human-readable byte count for the per-peer transfer counters (e.g. `1.2 MB`, `340 KB`).
pub(crate) fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{} B", n as u64)
    } else if n < KB * KB {
        format!("{:.0} KB", n / KB)
    } else if n < KB * KB * KB {
        format!("{:.1} MB", n / (KB * KB))
    } else {
        format!("{:.1} GB", n / (KB * KB * KB))
    }
}

/// A colored status dot to prefix a state line — reads faster than the word alone. Drawn as a
/// small rounded quad rather than a `●` glyph, which the default font (Fira Sans) renders as tofu.
pub(crate) fn dot<'a>(color: Color) -> Element<'a, Message> {
    container(text(""))
        .width(Length::Fixed(9.0))
        .height(Length::Fixed(9.0))
        .style(move |_| container::Style {
            background: Some(iced::Background::Color(color)),
            border: iced::Border {
                radius: 4.5.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
}

/// A vertical "kebab" (⋮) glyph, embedded as SVG. Drawn as an icon rather than a text symbol
/// because the default font renders such codepoints as tofu (same reason as [`dot`]). `fill` uses
/// `currentColor`; the widget tints it via [`svg::Style::color`].
const KEBAB_ICON: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>"##;

/// Disclosure chevrons for a collapsible section header — down when open, right when collapsed.
/// SVG for the same reason as [`dot`]/[`KEBAB_ICON`]: the default font tofus the triangle glyphs.
const CHEVRON_DOWN: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg>"##;
const CHEVRON_RIGHT: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 6l6 6-6 6"/></svg>"##;

/// A collapsible section header: a borderless full-width button showing a disclosure chevron + the
/// title; clicking it sends `msg` to toggle the section open/closed.
pub(crate) fn collapsible_header<'a>(
    title: String,
    open: bool,
    msg: Message,
) -> Element<'a, Message> {
    let icon = svg(svg::Handle::from_memory(if open {
        CHEVRON_DOWN
    } else {
        CHEVRON_RIGHT
    }))
    .width(Length::Fixed(14.0))
    .height(Length::Fixed(14.0))
    .style(|_theme, _status| svg::Style { color: Some(MUTED) });
    button(
        row![icon, header(title)]
            .spacing(6)
            .align_y(Vertical::Center),
    )
    .style(button::text)
    .padding(2)
    .width(Length::Fill)
    .on_press(msg)
    .into()
}

/// The kebab button that opens a peer's action menu — a borderless icon that toggles the dropdown.
/// Keyed by the device's WireGuard IP so it opens only that device's menu (a user can own several).
fn kebab_button<'a>(key: Ipv4Addr) -> Element<'a, Message> {
    let icon = svg(svg::Handle::from_memory(KEBAB_ICON))
        .width(Length::Fixed(16.0))
        .height(Length::Fixed(16.0))
        .style(|_theme, _status| svg::Style { color: Some(MUTED) });
    button(icon)
        .style(button::text)
        .padding(2)
        .on_press(Message::ToggleMenu(key))
        .into()
}

/// One left-aligned, full-width row in a peer's action menu.
fn menu_item<'a>(label: &str, msg: Message) -> Element<'a, Message> {
    button(text(label.to_owned()).size(13))
        .style(button::text)
        .width(Length::Fill)
        .on_press(msg)
        .into()
}

/// Surface style for the floating peer menu: an opaque, bordered card so it reads clearly over the
/// content it overlaps.
fn menu_surface(theme: &Theme) -> container::Style {
    let p = theme.extended_palette();
    container::Style {
        background: Some(p.background.weak.color.into()),
        border: iced::Border {
            radius: 6.0.into(),
            width: 1.0,
            color: p.background.strong.color,
        },
        ..Default::default()
    }
}

/// A peer's action menu: a kebab button that opens a floating dropdown (copy hostname / copy IP /
/// block user). `open` drives whether the overlay is shown; a click outside dismisses it via
/// `CloseMenu`. Copy actions are device-specific (this row's hostname/IP); "block user" acts on the
/// owner (all their devices) and so arms the user-scoped block modal.
pub(crate) fn peer_menu<'a>(
    hostname: String,
    ip: String,
    key: Ipv4Addr,
    user_id: u64,
    username: String,
    open: bool,
) -> Element<'a, Message> {
    let menu = container(
        column![
            menu_item("copy hostname", Message::CopyText(hostname)),
            menu_item("copy IP", Message::CopyText(ip)),
            menu_item(
                "block user",
                Message::AskConfirm(Confirm::BlockPeer { user_id, username })
            ),
        ]
        .spacing(2),
    )
    .padding(4)
    .width(Length::Fill)
    .style(menu_surface);
    // Anchor the menu below the kebab, extending left (right edge at the kebab) so it stays inside
    // the narrow window rather than spilling off the right edge. `width` sizes the overlay itself —
    // without it the overlay defaults to the kebab's width and the labels wrap to one char per line.
    DropDown::new(kebab_button(key), menu, open)
        .on_dismiss(Message::CloseMenu)
        .alignment(drop_down::Alignment::BottomStart)
        .width(Length::Fixed(160.0))
        .into()
}

/// Overlay `content` centered above `base`, dimming the rest of the window. A click on the dimmed
/// backdrop sends `on_blur` (dismiss). Used for the block-user confirmation, which acts on a whole
/// user rather than any single peer row and so doesn't belong inline in the list.
pub(crate) fn modal<'a>(
    base: impl Into<Element<'a, Message>>,
    content: impl Into<Element<'a, Message>>,
    on_blur: Message,
) -> Element<'a, Message> {
    stack![
        base.into(),
        opaque(
            mouse_area(center(opaque(content)).style(|_theme| {
                container::Style {
                    background: Some(
                        Color {
                            a: 0.7,
                            ..Color::BLACK
                        }
                        .into(),
                    ),
                    ..container::Style::default()
                }
            }))
            .on_press(on_blur)
        )
    ]
    .into()
}

/// Wrap a section's contents in a bordered, padded card so sections read as distinct groups
/// instead of one flat stack.
pub(crate) fn card<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(14)
        .width(Length::Fill)
        .style(container::rounded_box)
        .into()
}

/// Inline confirm/cancel controls for a destructive action. When `armed`, returns a danger
/// "confirm" button (running `run_msg`) plus a cancel button; otherwise a single arming button
/// (`arm_label`, danger vs. secondary per `arm_danger`) that sends `arm_msg`. The caller pushes
/// the returned elements onto its row.
pub(crate) fn confirm_controls<'a>(
    armed: bool,
    arm_label: &str,
    arm_danger: bool,
    arm_msg: Message,
    confirm_label: &str,
    run_msg: Message,
) -> Vec<Element<'a, Message>> {
    if armed {
        vec![
            button(text(confirm_label.to_owned()).size(13))
                .style(button::danger)
                .on_press(run_msg)
                .into(),
            button(text("cancel").size(13))
                .on_press(Message::CancelConfirm)
                .into(),
        ]
    } else {
        let b = button(text(arm_label.to_owned()).size(13)).on_press(arm_msg);
        let b = if arm_danger {
            b.style(button::danger)
        } else {
            b.style(button::secondary)
        };
        vec![b.into()]
    }
}
