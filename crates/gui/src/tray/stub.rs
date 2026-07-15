//! Tray backend stub for platforms with no tray implementation yet (i.e. not Linux or Windows —
//! macOS/BSD). The module split is in place so a real backend drops in here; Linux uses `linux.rs`
//! (ksni) and Windows uses `windows.rs` (tray-icon).

use std::path::PathBuf;

use super::TrayMsg;
use tokio::sync::mpsc::UnboundedReceiver;

pub fn spawn(_socket: PathBuf) -> Option<UnboundedReceiver<TrayMsg>> {
    None
}
