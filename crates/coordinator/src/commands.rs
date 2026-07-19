//! Discord slash commands for admins: `/unitylan network add|remove|list`.
//!
//! Runs a gateway shard, registers guild commands on GUILD_CREATE, and handles interactions
//! by mutating the network registry (design.md §3.1). Manage-Guild gated.

use std::collections::HashSet;
use std::sync::Arc;

use twilight_gateway::{Event, EventTypeFlags, Intents, Shard, ShardId, StreamExt as _};
use twilight_model::application::command::CommandType;
use twilight_model::application::interaction::application_command::{
    CommandData, CommandOptionValue,
};
use twilight_model::application::interaction::{Interaction, InteractionData};
use twilight_model::channel::message::MessageFlags;
use twilight_model::guild::Permissions;
use twilight_model::http::interaction::{InteractionResponse, InteractionResponseType};
use twilight_model::id::marker::{ApplicationMarker, GuildMarker};
use twilight_model::id::Id;
use twilight_util::builder::command::{
    CommandBuilder, RoleBuilder, StringBuilder, SubCommandBuilder, SubCommandGroupBuilder,
};
use twilight_util::builder::InteractionResponseDataBuilder;

use crate::presence::Presence;
use crate::store::{match_device_by_name, DeviceMatch, Store};
use crate::versions::{Scope, Versions};

/// Connect the gateway and handle `/unitylan` interactions + role-revocation events until the
/// process exits. `presence`/`versions` let member-role changes evict presence immediately (and
/// wake the affected guild's parked long-polls), so losing a role cuts a member off without waiting
/// for the TTL.
pub async fn run_gateway(
    token: String,
    store: Arc<Store>,
    presence: Arc<Presence>,
    versions: Arc<Versions>,
) -> anyhow::Result<()> {
    let http = twilight_http::Client::new(token.clone());
    let app_id = http.current_user_application().await?.model().await?.id;
    tracing::info!(%app_id, "gateway: application resolved, slash commands enabled");

    // GUILD_MEMBERS (privileged) is required to receive member add/update/remove events.
    let mut shard = Shard::new(
        ShardId::ONE,
        token,
        Intents::GUILDS | Intents::GUILD_MEMBERS,
    );
    let flags = EventTypeFlags::GUILD_CREATE
        | EventTypeFlags::INTERACTION_CREATE
        | EventTypeFlags::MEMBER_UPDATE
        | EventTypeFlags::MEMBER_REMOVE;

    while let Some(item) = shard.next_event(flags).await {
        let event = match item {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("gateway receive error: {e}");
                continue;
            }
        };
        match event {
            // Register guild commands the moment we see a guild (instant availability).
            Event::GuildCreate(gc) => match register_guild_commands(&http, app_id, gc.id()).await {
                Ok(()) => tracing::info!(guild = %gc.id(), "registered /unitylan commands"),
                Err(e) => tracing::warn!(guild = %gc.id(), "registering commands: {e:#}"),
            },
            Event::InteractionCreate(interaction) => {
                handle_interaction(&http, app_id, &store, &versions, interaction.0).await;
            }
            // A member's roles changed: evict them from any network whose role they no longer hold.
            Event::MemberUpdate(m) => {
                let held: HashSet<u64> = m.roles.iter().map(|r| r.get()).collect();
                revoke(
                    &store,
                    &presence,
                    &versions,
                    m.guild_id.get(),
                    m.user.id.get(),
                    &held,
                )
                .await;
            }
            // A member left the guild: evict them from every network in it.
            Event::MemberRemove(m) => {
                revoke(
                    &store,
                    &presence,
                    &versions,
                    m.guild_id.get(),
                    m.user.id.get(),
                    &HashSet::new(),
                )
                .await;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Evict a member from every registered network in `guild` whose role is not in `held`, bumping
/// that guild's membership version if anything changed so its parked long-polls wake and prune the
/// peer. Scoped to the guild: a revocation here is invisible to every other guild's clients.
async fn revoke(
    store: &Store,
    presence: &Presence,
    versions: &Versions,
    guild_id: u64,
    user_id: u64,
    held: &HashSet<u64>,
) {
    let nets = match store.networks_in_guild(guild_id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!("revoke: listing networks: {e:#}");
            return;
        }
    };
    let mut changed = false;
    for net in nets {
        if !held.contains(&net.role_id) {
            changed |= presence.evict_user(guild_id, net.role_id, user_id);
        }
    }
    if changed {
        versions.bump(Scope::Guild(guild_id));
        tracing::info!(
            guild = guild_id,
            user = user_id,
            "revoked: evicted lost-role presence"
        );
    }
}

fn commands() -> Vec<twilight_model::application::command::Command> {
    let group = SubCommandGroupBuilder::new("network", "Manage UnityLAN networks").subcommands([
        SubCommandBuilder::new("add", "Register a role as a network")
            .option(RoleBuilder::new("role", "The role that grants access").required(true)),
        SubCommandBuilder::new("remove", "Unregister a network")
            .option(RoleBuilder::new("role", "The role to unregister").required(true)),
        SubCommandBuilder::new("list", "List this guild's networks"),
    ]);
    let enroll =
        SubCommandBuilder::new("enroll", "Mint a one-time key to enroll a headless device");
    let primary =
        SubCommandGroupBuilder::new("primary", "Choose your primary device").subcommands([
            SubCommandBuilder::new("list", "List your devices and which is primary"),
            SubCommandBuilder::new("set", "Set your primary device")
                .option(StringBuilder::new("device", "Device name").required(true)),
        ]);
    vec![
        CommandBuilder::new("unitylan", "UnityLAN admin", CommandType::ChatInput)
            .option(group)
            .option(enroll)
            .option(primary)
            .build(),
    ]
}

async fn register_guild_commands(
    http: &twilight_http::Client,
    app_id: Id<ApplicationMarker>,
    guild_id: Id<GuildMarker>,
) -> anyhow::Result<()> {
    http.interaction(app_id)
        .set_guild_commands(guild_id, &commands())
        .await?;
    Ok(())
}

async fn handle_interaction(
    http: &twilight_http::Client,
    app_id: Id<ApplicationMarker>,
    store: &Store,
    versions: &Versions,
    interaction: Interaction,
) {
    let Some(InteractionData::ApplicationCommand(data)) = interaction.data.clone() else {
        return;
    };
    if data.name != "unitylan" {
        return;
    }
    let content = process(http, store, versions, &interaction, &data).await;

    let response = InteractionResponse {
        kind: InteractionResponseType::ChannelMessageWithSource,
        data: Some(
            InteractionResponseDataBuilder::new()
                .content(content)
                .flags(MessageFlags::EPHEMERAL)
                .build(),
        ),
    };
    if let Err(e) = http
        .interaction(app_id)
        .create_response(interaction.id, &interaction.token, &response)
        .await
    {
        tracing::warn!("responding to interaction: {e:#}");
    }
}

async fn process(
    http: &twilight_http::Client,
    store: &Store,
    versions: &Versions,
    interaction: &Interaction,
    data: &CommandData,
) -> String {
    let Some(guild_id) = interaction.guild_id else {
        return "Use this in a server.".to_string();
    };
    let Some(opt) = data.options.first() else {
        return "Unknown command.".to_string();
    };
    match (opt.name.as_str(), &opt.value) {
        // /unitylan network <sub> ... — admin only.
        ("network", CommandOptionValue::SubCommandGroup(subs)) => {
            if !is_admin(interaction) {
                return "You need the Manage Server permission.".to_string();
            }
            handle_network(http, store, versions, guild_id.get(), subs).await
        }
        // /unitylan enroll — any member mints a one-time key for their own headless device.
        ("enroll", CommandOptionValue::SubCommand(_)) => {
            let Some(user) = interaction.author_id() else {
                return "Could not determine your user.".to_string();
            };
            let key = common::crypto::gen_enrollment_key();
            let expires_at = common::now_unix() + common::ENROLLMENT_KEY_TTL_SECS;
            match store
                .create_enrollment_key(&key, user.get(), Some(expires_at))
                .await
            {
                Ok(()) => format!(
                    "Your one-time enrollment key (expires in {} min):\n`{key}`\n\nOn the headless \
                     device, set `enrollment_key = \"{key}\"` in its config (or pass \
                     `--token {key}`). It binds to the first device that registers with it.",
                    common::ENROLLMENT_KEY_TTL_SECS / 60
                ),
                Err(e) => format!("Error: {e}"),
            }
        }
        // /unitylan primary list|set — any member manages their own devices.
        ("primary", CommandOptionValue::SubCommandGroup(subs)) => {
            let Some(user) = interaction.author_id() else {
                return "Could not determine your user.".to_string();
            };
            handle_primary(store, user.get(), subs).await
        }
        _ => "Unknown command.".to_string(),
    }
}

async fn handle_primary(
    store: &Store,
    user_id: u64,
    subs: &[twilight_model::application::interaction::application_command::CommandDataOption],
) -> String {
    let Some(sub) = subs.first() else {
        return "Unknown subcommand.".to_string();
    };
    let CommandOptionValue::SubCommand(opts) = &sub.value else {
        return "Unknown subcommand.".to_string();
    };

    let devices = match store.user_devices(user_id).await {
        Ok(d) => d,
        Err(e) => return format!("Error: {e}"),
    };
    if devices.is_empty() {
        return "You have no enrolled devices yet.".to_string();
    }
    let primary = store.primary_pubkey(user_id).await.ok().flatten();

    match sub.name.as_str() {
        "list" => {
            let mut s = String::from("Your devices:\n");
            for (pk, name) in &devices {
                let star = if primary.as_ref() == Some(pk) {
                    " ⭐ (primary)"
                } else {
                    ""
                };
                s.push_str(&format!("• {name}{star}\n"));
            }
            s
        }
        "set" => {
            let want = opts.iter().find_map(|o| match &o.value {
                CommandOptionValue::String(s) => Some(common::netid::sanitize_label(s)),
                _ => None,
            });
            let Some(want) = want else {
                return "Missing device name.".to_string();
            };
            match match_device_by_name(&devices, &want) {
                DeviceMatch::None => {
                    format!("No device named **{want}**. Use `/unitylan primary list`.")
                }
                DeviceMatch::One(pk) => match store.set_primary(user_id, &pk).await {
                    Ok(()) => format!("Primary device set to **{want}**."),
                    Err(e) => format!("Error: {e}"),
                },
                DeviceMatch::Many => {
                    format!("Multiple devices named **{want}**; rename one first.")
                }
            }
        }
        _ => "Unknown subcommand.".to_string(),
    }
}

/// Whether the interacting member has Manage Guild / Administrator.
fn is_admin(interaction: &Interaction) -> bool {
    interaction
        .member
        .as_ref()
        .and_then(|m| m.permissions)
        .is_some_and(|p| {
            p.contains(Permissions::MANAGE_GUILD) || p.contains(Permissions::ADMINISTRATOR)
        })
}

async fn handle_network(
    http: &twilight_http::Client,
    store: &Store,
    versions: &Versions,
    guild_id: u64,
    subs: &[twilight_model::application::interaction::application_command::CommandDataOption],
) -> String {
    let Some(sub) = subs.first() else {
        return "Unknown subcommand.".to_string();
    };
    let CommandOptionValue::SubCommand(opts) = &sub.value else {
        return "Unknown subcommand.".to_string();
    };
    let role_opt = || {
        opts.iter().find_map(|o| match o.value {
            CommandOptionValue::Role(id) => Some(id),
            _ => None,
        })
    };

    match sub.name.as_str() {
        "add" => {
            let Some(role) = role_opt() else {
                return "Missing role.".to_string();
            };
            // `@everyone` has role id == guild id; it's every member, not an ACL group.
            if role.get() == guild_id {
                return "`@everyone` cannot be a network.".to_string();
            }
            // The network name is always the role's own Discord name (kept in sync by the
            // RoleUpdate handler); fall back to `role-{id}` only if the API lookup fails
            // (e.g. the role was just deleted).
            let name = role_name(http, guild_id, role.get())
                .await
                .unwrap_or_else(|| format!("role-{role}"));
            match store.upsert_network(guild_id, role.get(), &name).await {
                Ok(()) => {
                    // Wake the guild's parked long-polls so its clients pick up the new network
                    // immediately. A member who holds *no* other network in this guild isn't
                    // subscribed to it yet and picks the new one up on its next renewal instead —
                    // acceptable for an admin-rare event, unlike presence churn.
                    versions.bump(Scope::Guild(guild_id));
                    tracing::info!(
                        guild = guild_id,
                        role = role.get(),
                        %name,
                        "network add: upserted + bumped membership version"
                    );
                    format!("Registered <@&{role}> as network **{name}**.")
                }
                Err(e) => format!("Error: {e}"),
            }
        }
        "remove" => {
            let Some(role) = role_opt() else {
                return "Missing role.".to_string();
            };
            match store.remove_network(guild_id, role.get()).await {
                Ok(()) => {
                    // Wake the guild's parked long-polls so its clients drop the network now.
                    versions.bump(Scope::Guild(guild_id));
                    tracing::info!(
                        guild = guild_id,
                        role = role.get(),
                        "network remove: removed + bumped membership version"
                    );
                    format!("Unregistered <@&{role}>.")
                }
                Err(e) => format!("Error: {e}"),
            }
        }
        "list" => match store.networks_in_guild(guild_id).await {
            Ok(nets) if nets.is_empty() => "No networks registered.".to_string(),
            Ok(nets) => {
                let mut s = String::from("Networks:\n");
                for n in nets {
                    s.push_str(&format!("• <@&{}> — {}\n", n.role_id, n.name));
                }
                s
            }
            Err(e) => format!("Error: {e}"),
        },
        _ => "Unknown subcommand.".to_string(),
    }
}

/// The Discord display name of a role in a guild, if the API lookup succeeds. Used to default a
/// network's name to the role name at registration.
async fn role_name(http: &twilight_http::Client, guild_id: u64, role_id: u64) -> Option<String> {
    let roles = http
        .roles(Id::new(guild_id))
        .await
        .ok()?
        .model()
        .await
        .ok()?;
    roles
        .into_iter()
        .find(|r| r.id.get() == role_id)
        .map(|r| r.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use twilight_model::application::interaction::application_command::CommandDataOption;
    use twilight_model::application::interaction::InteractionType;
    use twilight_model::guild::{MemberFlags, PartialMember};
    use twilight_model::oauth::ApplicationIntegrationMap;

    /// An interaction whose invoking member carries `perms` — `None` for a member Discord sent
    /// without a permission field, `member: None` for a DM (no member at all).
    #[allow(deprecated)] // `channel_id` is deprecated upstream but is still a struct field.
    fn interaction(member_perms: Option<Option<Permissions>>) -> Interaction {
        Interaction {
            app_permissions: None,
            application_id: Id::new(1),
            authorizing_integration_owners: ApplicationIntegrationMap {
                guild: None,
                user: None,
            },
            channel: None,
            channel_id: None,
            context: None,
            data: None,
            entitlements: Vec::new(),
            guild: None,
            guild_id: Some(Id::new(42)),
            guild_locale: None,
            id: Id::new(2),
            kind: InteractionType::ApplicationCommand,
            locale: None,
            member: member_perms.map(|permissions| PartialMember {
                avatar: None,
                avatar_decoration_data: None,
                banner: None,
                communication_disabled_until: None,
                deaf: false,
                flags: MemberFlags::empty(),
                joined_at: None,
                mute: false,
                nick: None,
                permissions,
                premium_since: None,
                roles: Vec::new(),
                user: None,
            }),
            message: None,
            token: "t".to_string(),
            user: None,
        }
    }

    /// One `network <name>` subcommand, with the given role option (if any).
    fn sub(name: &str, role: Option<u64>) -> Vec<CommandDataOption> {
        let options = role
            .map(|id| {
                vec![CommandDataOption {
                    name: "role".to_string(),
                    value: CommandOptionValue::Role(Id::new(id)),
                }]
            })
            .unwrap_or_default();
        vec![CommandDataOption {
            name: name.to_string(),
            value: CommandOptionValue::SubCommand(options),
        }]
    }

    /// A `twilight_http::Client` performs no I/O until a request is actually issued, so every path
    /// below (none of which reaches `role_name`) leaves it untouched.
    fn http() -> twilight_http::Client {
        twilight_http::Client::new("token".to_string())
    }

    #[test]
    fn is_admin_accepts_manage_guild_and_administrator() {
        assert!(is_admin(&interaction(Some(Some(
            Permissions::MANAGE_GUILD
        )))));
        assert!(is_admin(&interaction(Some(Some(
            Permissions::ADMINISTRATOR
        )))));
    }

    #[test]
    fn is_admin_rejects_unprivileged_missing_and_absent_members() {
        assert!(
            !is_admin(&interaction(Some(Some(Permissions::SEND_MESSAGES)))),
            "an unrelated permission does not grant network mutation"
        );
        assert!(
            !is_admin(&interaction(Some(None))),
            "a member with no permission field is not an admin"
        );
        assert!(
            !is_admin(&interaction(None)),
            "a DM interaction has no member, so no guild permissions"
        );
    }

    #[tokio::test]
    async fn network_add_rejects_everyone_role() {
        let store = Store::memory().await;
        let versions = Versions::default();
        // `@everyone`'s role id equals the guild id; it is every member, not an ACL group. The
        // guard must fire before the role-name lookup, so this reaches no HTTP call.
        let out = handle_network(&http(), &store, &versions, 42, &sub("add", Some(42))).await;
        assert_eq!(out, "`@everyone` cannot be a network.");
        assert!(store.networks_in_guild(42).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn network_add_and_remove_require_a_role_option() {
        let store = Store::memory().await;
        let versions = Versions::default();
        for name in ["add", "remove"] {
            let out = handle_network(&http(), &store, &versions, 42, &sub(name, None)).await;
            assert_eq!(out, "Missing role.");
        }
    }

    #[tokio::test]
    async fn network_remove_deletes_and_bumps_the_guild_scope() {
        let store = Store::memory().await;
        let versions = Versions::default();
        store.upsert_network(42, 7, "gamers").await.unwrap();
        let scopes: BTreeSet<Scope> = [Scope::Guild(42)].into_iter().collect();
        let before = versions.aggregate(&scopes);

        let out = handle_network(&http(), &store, &versions, 42, &sub("remove", Some(7))).await;

        assert_eq!(out, "Unregistered <@&7>.");
        assert!(store.networks_in_guild(42).await.unwrap().is_empty());
        assert_ne!(
            versions.aggregate(&scopes),
            before,
            "the guild's parked long-polls must wake and drop the network"
        );
    }

    #[tokio::test]
    async fn network_list_renders_empty_and_populated() {
        let store = Store::memory().await;
        let versions = Versions::default();
        let out = handle_network(&http(), &store, &versions, 42, &sub("list", None)).await;
        assert_eq!(out, "No networks registered.");

        store.upsert_network(42, 7, "gamers").await.unwrap();
        store.upsert_network(42, 8, "modders").await.unwrap();
        // A network in another guild must not leak into this guild's listing.
        store.upsert_network(99, 9, "elsewhere").await.unwrap();

        let out = handle_network(&http(), &store, &versions, 42, &sub("list", None)).await;
        assert!(out.starts_with("Networks:\n"));
        assert!(out.contains("• <@&7> — gamers\n"));
        assert!(out.contains("• <@&8> — modders\n"));
        assert!(!out.contains("elsewhere"));
    }

    #[tokio::test]
    async fn network_rejects_unknown_and_empty_subcommands() {
        let store = Store::memory().await;
        let versions = Versions::default();
        let out = handle_network(&http(), &store, &versions, 42, &sub("nope", Some(7))).await;
        assert_eq!(out, "Unknown subcommand.");
        let out = handle_network(&http(), &store, &versions, 42, &[]).await;
        assert_eq!(out, "Unknown subcommand.");
    }
}
