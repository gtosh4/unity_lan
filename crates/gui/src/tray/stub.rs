//! Tray backend stub for non-Linux platforms. The module split is in place so a real backend drops
//! in here; Windows will use the `tray-icon` crate (needs a Win32 message-pump integration that
//! can't be built or verified from a Linux host — hence deferred to when Windows is worked).

use std::path::PathBuf;

use super::TrayMsg;
use tokio::sync::mpsc::UnboundedReceiver;

pub fn spawn(_socket: PathBuf) -> Option<UnboundedReceiver<TrayMsg>> {
    None
}
