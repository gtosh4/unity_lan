//! Port-exposure control messages and their backwards-compatible wire encoding.

use serde::{Deserialize, Serialize};

use super::OWN_DEVICES_LABEL;

/// Transport protocol of an exposed port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Who may reach an exposed port. One exposure carries exactly one scope; opening a port to
/// several networks means several exposures (the firewall unions their source sets), which is what
/// lets one scope be closed while the others stay — see [`RemoveScope`].
///
/// A network is `(guild_id, role_id)`, because names are mutable and need not be unique. Human
/// names arrive as [`Unresolved`](ExposeScope::Unresolved), then the engine resolves them to ids.
///
/// The custom wire format preserves legacy `Option<String>` clients: all peers is `null`, an
/// unqualified network is a string, and scopes with no safe legacy spelling use tagged objects.
/// An old engine rejects those objects instead of silently widening access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExposeScope {
    AllPeers,
    OwnDevices,
    Net { guild_id: u64, role_id: u64 },
    Unresolved { guild: Option<String>, name: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ScopeTagged {
    OwnDevices,
    Net { guild_id: u64, role_id: u64 },
    NetNamed { guild: String, name: String },
}

impl ExposeScope {
    /// A display label for callers that do not have the network-name lookup table.
    pub fn fallback_label(&self) -> String {
        match self {
            Self::AllPeers => "all peers".to_string(),
            Self::OwnDevices => OWN_DEVICES_LABEL.to_string(),
            Self::Net { guild_id, role_id } => format!("network {guild_id}/{role_id}"),
            Self::Unresolved { guild: None, name } => name.clone(),
            Self::Unresolved {
                guild: Some(guild),
                name,
            } => format!("{name} @ {guild}"),
        }
    }
}

impl Serialize for ExposeScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::AllPeers => serializer.serialize_none(),
            Self::Unresolved { guild: None, name } => serializer.serialize_some(name),
            Self::OwnDevices => ScopeTagged::OwnDevices.serialize(serializer),
            Self::Net { guild_id, role_id } => ScopeTagged::Net {
                guild_id: *guild_id,
                role_id: *role_id,
            }
            .serialize(serializer),
            Self::Unresolved {
                guild: Some(guild),
                name,
            } => ScopeTagged::NetNamed {
                guild: guild.clone(),
                name: name.clone(),
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ExposeScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Any {
            Legacy(Option<String>),
            Tagged(ScopeTagged),
        }

        Ok(match Any::deserialize(deserializer)? {
            Any::Legacy(None) => Self::AllPeers,
            Any::Legacy(Some(name)) => Self::Unresolved { guild: None, name },
            Any::Tagged(ScopeTagged::OwnDevices) => Self::OwnDevices,
            Any::Tagged(ScopeTagged::Net { guild_id, role_id }) => Self::Net { guild_id, role_id },
            Any::Tagged(ScopeTagged::NetNamed { guild, name }) => Self::Unresolved {
                guild: Some(guild),
                name,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExposeOp {
    List,
    Add {
        proto: Proto,
        port: u16,
        #[serde(rename = "net")]
        scope: ExposeScope,
    },
    Remove {
        proto: Proto,
        port: u16,
        scope: RemoveScope,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoveScope {
    All,
    Exact(ExposeScope),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExposeResp {
    pub message: String,
    pub exposed: Vec<ExposedPort>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExposedPort {
    pub proto: Proto,
    pub port: u16,
    #[serde(rename = "net")]
    pub scope: ExposeScope,
    #[serde(default)]
    pub label: String,
    /// False when a scoped exposure currently has no eligible source peers.
    pub active: bool,
}
