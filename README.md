# ESN Guardian

Discord security, moderation, verification, and ESN SMP bot built with `discord.py` and SQLite.

## Run Locally

1. Install Python 3.11+ dependencies: `python -m pip install .`
2. Copy `.env.example` to `.env` and set `DISCORD_TOKEN`. Set `BOT_OWNER_ID` for owner-only commands.
3. Enable the **Server Members Intent** and **Message Content Intent** in the Discord Developer Portal.
4. Invite the bot with `bot`, `applications.commands`, and only the guild permissions it needs: View Channels, Send Messages, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, Read Message History, and View Audit Log.
5. Start it with `python main.py`.

`DATABASE_PATH` defaults to `data/esn_guardian.db`. Each table scopes settings and cases by guild ID. Keep `.env` and the database volume private and backed up.

## Deployment

Build and run in Docker with a persistent data volume and environment injection:

```sh
docker build -t esn-guardian .
docker run -d --restart unless-stopped --env-file .env -v esn-guardian-data:/app/data esn-guardian
```

Discord reconnects are handled by the library. API failures are caught at action boundaries and written to configured system/security channels when available.

## Command Sync

Guardian syncs slash commands to each connected server on startup. The configured bot owner can run `/synccommands` after a command change; leave `guild_id` empty to refresh every connected server, or provide a connected server's numeric ID to refresh only that server.

## RayNode Setup

1. Use the existing public GitHub repository at `https://github.com/sheldonrocks2022-cmyk/ESNGUARDIAN`. It must contain every project file except `.env`, `.venv`, and `data/`. The required files include `main.py`, `requirements.txt`, `esn_guardian/`, `.gitignore`, and this README.
2. On the GitHub repository page, select **Code**, choose **HTTPS**, and copy the URL ending in `.git`. Use that URL in RayNode's repository field.
3. Use the `main` Git branch unless you deliberately use a different branch.
4. In RayNode, set **APP PY FILE** to `main.py`.
5. Set **REQUIREMENTS FILE** to `requirements.txt`.
6. Leave **GIT USERNAME** blank for a public repository. For a private repository, enter your GitHub username.
7. For a private repository, create a fine-grained GitHub personal access token with access only to this repository and **Contents: Read-only** permission. Paste it only into RayNode's protected Git token field. Do not put it in GitHub files or Discord.
8. Add the RayNode environment variable `DISCORD_TOKEN` with your Discord bot token. Also add `BOT_OWNER_ID` with your numeric Discord user ID. Optionally set `DATABASE_PATH` to `data/esn_guardian.db` and `LOG_LEVEL` to `INFO`.
9. Enable RayNode's automatic restart or keep-alive setting. Disable any web-server, port, or HTTP health-check setting because this is a Discord gateway bot, not a website. Select Python 3.11 or newer.
10. Use the startup command `python main.py`.

RayNode must keep the project folder and `data/` directory between restarts for moderation cases and server settings to persist. If the host provides a persistent-volume setting, mount it at the project `data/` directory.

## Anti-Nuke

Anti-nuke is disabled by default. The server owner can enable it with:

```text
/antinuke setup action_limit:3 window_seconds:15
```

It attributes channel deletions, role creations/deletions, bans, kicks, dangerous role-permission escalations, and dangerous role assignments from Discord audit logs. Dangerous role escalations and assignments are immediately reverted when possible. When a non-trusted, non-owner executor reaches the threshold, Guardian attempts to ban that executor and enables server lockdown. Grant the bot **View Audit Log**, **Ban Members**, **Manage Channels**, and **Manage Roles**. Use `/antinuke trust` only for trusted recovery administrators; inspect the current configuration with `/antinuke status`.

## Advanced AutoMod And Raid Protection

Use `/security thresholds`, `/security links`, and `/security automod` to configure flood, mention, caps, invite, and strict-link enforcement for each server. Strict link mode uses the persisted `/security allow-domain` allowlist. Use `/security raid` to configure join-rate detection, suspicious account age, and a quarantine role. The quarantine role must be below the bot's highest role and should deny access to sensitive channels through your server's role permissions.
### Security hardening

Moderation actions require the caller's matching Discord permission and respect
both the caller's and bot's role hierarchy. The server owner alone can change
anti-nuke enablement and trust. Verification, autoroles and quarantine reject
privileged or managed roles, including configurations whose roles later change.
Verification buttons honor maintenance and guild blacklisting. AutoMod deletes
violating messages on the first strike while retaining warning-first escalation.
Lockdown preserves unrelated channel overwrites and stores the previous
`send_messages` value in SQLite for restoration across restarts; failed restores
remain pending. Unknown audit actors are never guessed or banned; repeated clearly destructive unattributed events can still trigger containment.

Run `python -m pip install -r requirements.txt pytest pytest-asyncio pip-audit`,
then `python -m pytest -q` and `python -m pip_audit -r requirements.txt`.
GitHub Actions runs these checks on pushes and pull requests.
These are offline regression tests; live Discord enforcement still requires
correct bot permissions and a role above the members it needs to moderate.

### Streamlined commands and support tickets

- Use `/smp` for the address, port, and Discord link, and `/status smp` for live
  status and player counts. Redundant `/ip`, `/port`, `/players`, `/joinhelp`,
  manual `/setup`, and basic `/poll` commands were removed.
- Ad-network setup, opt-in/out, status and reporting commands were retired.
  `/smpannounce channel:<channel> message:<text>` remains for staff with Manage
  Server and Manage Messages. The caller must be able to send in the selected
  channel. Announcements suppress mentions and share a persistent per-server
  cooldown (60 minutes by default; existing configured cooldowns are retained).
  Concurrent sends are serialized; failed Discord sends do not consume cooldown.
- `/config` now shows stored server, logging, AutoMod, anti-nuke, raid,
  verification and ticket settings in private responses.
- Staff first use `/ticket-config support_role:<role>` to choose support access.
  `/ticket subject:<text>` creates a private channel for the opener, support role
  and bot. Discord administrators retain their normal access. Each member can
  have one open ticket, with at most 25 open tickets per server and a 60-second
  opening cooldown. Records survive restarts.
- `/ticket-close` works inside an active ticket for its opener, configured support
  staff, or members with Manage Server. It preserves the private channel history
  and makes the opener's channel access read-only; Discord administrators can
  override channel denies. Staff may delete the archived channel when appropriate.
  Changing the configured support role only changes access for new tickets.
- Settings and tables migrate automatically without dropping existing data.
  New commands sync when the bot starts. GitHub's Security checks workflow also
  supports manual runs after any account-level Actions restrictions are resolved.


### ESNG AI

Guardian includes a local, no-API-cost assistant inspired by the ESN Store AI design.
It ignores normal Discord conversation and only responds when a message begins with
`ESNG` (case-insensitive), such as `ESNG security status`, `ESNG anti-nuke`,
`ESNG tickets`, or `ESNG store`.

The assistant reads Guardian's live server configuration for security-status answers,
reports bot uptime/latency, explains verified Guardian features, and refuses to invent
unknown settings or commands. It does not require an OpenAI key or any external AI
service. A per-user cooldown prevents trigger spam.

### Security hardening v2

The hardened security engine retries audit-log attribution, contains bursts of
unattributed destructive actions without guessing an attacker, counts webhook abuse,
channel creation/deletion and channel-permission changes, blocks untrusted bot
additions when anti-nuke is enabled, and watches unbans.

Dangerous link checks now normalize IDN domains and detect common phishing-lookalike
patterns, shorteners, direct-IP URLs, embedded URL credentials and punycode hostnames.
Staff keep their normal nuisance-filter exemption, but dangerous links and configured
link policy still apply; Guardian deletes those messages and logs a staff security case
without automatically escalating a legitimate staff member to kick/ban.

AutoMod escalation uses only the previous 30 days of AutoMod cases. Raid detection
adds a short containment window after a join surge. `/security scan` now checks
Manage Webhooks and reports high-risk roles above Guardian. The server owner can apply
the recommended baseline with `/security harden`. Bot-wide owner commands honor the
configured `BOT_OWNER_ID` in addition to recovery owner IDs.


---

## Install ESN Guardian

**Add ESN Guardian to your Discord server:**  
[Add our security bot ESN Guardian](https://discord.com/oauth2/authorize?client_id=1544503232674664573)

After Discord opens:

1. Choose the server where you have permission to add apps/bots.
2. Review the requested permissions.
3. Authorize ESN Guardian.
4. Put the Guardian bot role **above the roles it needs to moderate**.
5. Make sure Guardian can View Channels, Send Messages, Read Message History, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, and View Audit Log where those features are intended to work.
6. Run \`/help\`, then \`/security scan\` to check the setup.

Guardian uses Discord slash commands. Type \`/\` in Discord and select **ESN Guardian** to see the commands Discord currently exposes to your server.

## Recommended First-Time Setup

A practical setup order is:

1. \`/help\` — open Guardian's built-in guide.
2. \`/security scan\` — check permissions and role hierarchy.
3. \`/security harden\` — server-owner command that applies Guardian's recommended security baseline.
4. \`/antinuke setup\` — enable anti-nuke protection and choose its destructive-action threshold.
5. \`/logs\` — choose channels for Guardian event/security logs.
6. \`/verification setup\` — optional verification system.
7. \`/autorole\` — optional automatic member role.
8. \`/ticket-config\` — optional support-ticket role.
9. \`/welcome\` and \`/goodbye\` — optional join/leave channels.
10. \`/panel\` — post the persistent Guardian staff panel.
11. \`/esnpanel\` — post the persistent ESN community panel.
12. \`/config\` and \`/security status\` — confirm the saved configuration.

### Important role hierarchy rule

Discord does not allow a bot to moderate members or roles that are equal to or higher than the bot's highest role. If a moderation action fails, move **ESN Guardian** higher in **Server Settings → Roles** while keeping the server's ownership/admin structure appropriate.

## Complete Slash Command Guide

The command list below is based on the commands currently implemented in the repository.

### General / community commands

| Command | What it does | Typical access |
| --- | --- | --- |
| \`/help\` | Opens the ESN Guardian setup and command guide. | Everyone |
| \`/health\` | Shows Guardian health and connection status. | Everyone |
| \`/smp\` | Shows ESN SMP connection information. | Everyone |
| \`/discord\` | Shows the ESN SMP Discord link configured in the bot. | Everyone |
| \`/suggest\` | Sends a community suggestion. | Everyone |
| \`/panel\` | Posts the persistent Guardian staff control panel. | Staff |
| \`/esnpanel\` | Posts the persistent ESN community panel. | Everyone |
| \`/config\` | Shows stored server, logging, security, verification, raid, and ticket settings. | Staff |
| \`/welcome\` | Sets the channel for automatic join notices. | Server owner |
| \`/goodbye\` | Sets the channel for automatic leave notices. | Server owner |
| \`/autorole\` | Configures the automatic member role. | Staff |
| \`/logs\` | Sets a detailed event-log channel for a log category. | Staff |
| \`/smpannounce\` | Sends an SMP announcement to a selected channel. Uses the persistent server cooldown. | Staff with Manage Messages |

### ESN status commands

| Command | What it does |
| --- | --- |
| \`/status smp\` | Queries live ESN SMP Bedrock status and player information. |
| \`/status subscribe\` | Subscribes you to ESN SMP or Guardian status notifications. |
| \`/status unsubscribe\` | Removes a status notification subscription. |
| \`/status subscriptions\` | Shows your active status subscriptions. |

### Moderation commands

| Command | What it does |
| --- | --- |
| \`/warn\` | Issues a formal warning and stores a case. |
| \`/warnings\` | Lists active warnings for a member. |
| \`/timeout\` | Times out a member for 1–40320 minutes. |
| \`/untimeout\` | Removes a member timeout. |
| \`/kick\` | Kicks a member. |
| \`/ban\` | Bans a member and can delete up to 7 days of messages. |
| \`/unban\` | Unbans a user by ID. |
| \`/clear\` | Deletes 1–100 recent messages. |
| \`/slowmode\` | Sets channel slowmode from 0–21600 seconds. |
| \`/case\` | Shows a stored moderation case. |
| \`/history\` | Shows moderation history for a member. |
| \`/nickname\` | Changes or clears a member nickname. |
| \`/role\` | Adds or removes one role from a member. |
| \`/massrole\` | Adds or removes a role for all eligible members. |

Guardian also checks the caller's Discord permissions and role hierarchy before moderation actions.

### Channel lockdown commands

| Command | What it does |
| --- | --- |
| \`/lock\` | Locks the current channel for \`@everyone\`. |
| \`/unlock\` | Unlocks the current channel. |
| \`/lockdown\` | Locks all eligible text channels during an incident. |
| \`/unlockdown\` | Restores saved channel send-message settings after lockdown. |

Lockdown restoration is persisted in SQLite so Guardian can keep restoration state across restarts.

### Security / AutoMod commands

| Command | What it does |
| --- | --- |
| \`/security automod\` | Enables or disables automatic message-security enforcement. |
| \`/security thresholds\` | Sets flood, mention, and caps thresholds. |
| \`/security links\` | Configures invite blocking and strict external-link allowlisting. |
| \`/security allow-domain\` | Allows an exact domain and its subdomains in strict-link mode. |
| \`/security remove-domain\` | Removes a domain from the allowlist. |
| \`/security add-word\` | Adds a word or phrase to the blocked-word filter. |
| \`/security remove-word\` | Removes a word or phrase from the blocked-word filter. |
| \`/security words\` | Lists configured blocked words and phrases. |
| \`/security domains\` | Lists domains allowed by strict-link mode. |
| \`/security status\` | Shows the current AutoMod and anti-nuke policy. |
| \`/security scan\` | Checks Guardian's security permissions and role hierarchy. |
| \`/security cases\` | Shows recent AutoMod, anti-nuke, and security cases. |
| \`/security harden\` | Applies Guardian's recommended secure baseline. |
| \`/security raid\` | Configures join-rate detection, account-age checks, and quarantine. |
| \`/security raid-status\` | Shows raid/join-rate/quarantine configuration. |
| \`/security quarantine\` | Assigns the configured quarantine role to a member. |
| \`/security release\` | Removes the configured quarantine role. |
| \`/security member\` | Shows a member's security history, account age, and high-risk roles. |
| \`/security trusted\` | Lists anti-nuke trusted users. |
| \`/security reset-automod\` | Restores secure AutoMod/link defaults. |
| \`/security check-link\` | Checks whether a URL would pass the current strict-link policy. |

Guardian's dangerous-link checks include normalization and checks for suspicious direct-IP URLs, embedded credentials, punycode/IDN patterns, common phishing lookalikes, and known shortening behavior.

### Anti-nuke commands

| Command | What it does |
| --- | --- |
| \`/antinuke setup\` | Enables anti-nuke and sets the destructive-action threshold/window. |
| \`/antinuke enable\` | Enables a previously configured anti-nuke policy. |
| \`/antinuke disable\` | Disables anti-nuke. |
| \`/antinuke trust\` | Adds a trusted recovery administrator who can bypass containment. |
| \`/antinuke untrust\` | Removes trusted status. |
| \`/antinuke status\` | Shows anti-nuke settings and trusted-user count. |

Anti-nuke watches destructive server activity through Discord audit logs. It can react to events such as destructive channel/role operations, bans/kicks, dangerous permission escalations, dangerous role assignments, webhook abuse, unbans, and untrusted bot additions when protection is enabled. Guardian does not intentionally guess an attacker when audit attribution is unknown.

### Verification commands

| Command | What it does |
| --- | --- |
| \`/verification setup\` | Posts/replaces the verification message and configures verified/unverified roles plus optional minimum account age. |
| \`/verification enable\` | Enables verification. |
| \`/verification disable\` | Disables verification. |
| \`/verification reset\` | Clears verification records for one member or the configured scope so members can verify again. |
| \`/verification status\` | Shows verification configuration. |
| \`/verify\` | Starts the member verification flow. |

Guardian rejects privileged or managed roles for verification/autorole/quarantine configurations when they would be unsafe.

### Ticket commands

| Command | What it does |
| --- | --- |
| \`/ticket-config\` | Chooses the support role that can access new tickets. |
| \`/ticket\` | Opens a private support ticket. One active ticket per member. |
| \`/ticket-close\` | Closes the active ticket and preserves its private history as an archived/read-only channel for the opener. |

The implementation also limits open-ticket volume and opening frequency to reduce abuse.

### Bot-owner commands

These commands are restricted to the configured \`BOT_OWNER_ID\`/recognized recovery ownership logic.

| Command | What it does |
| --- | --- |
| \`/botstats\` | Shows bot-wide operational statistics. |
| \`/backupdb\` | Creates a verified SQLite database backup. |
| \`/backupstatus\` | Shows database-backup status. |
| \`/servers\` | Lists servers currently served by Guardian. |
| \`/synccommands\` | Refreshes slash commands for one connected server or all connected servers. |
| \`/globalban\` | Bans a user from every server Guardian serves and records the global ban. |
| \`/globalunban\` | Removes a user from the global-ban list. |
| \`/broadcast\` | Sends an announcement to configured system-log channels. |
| \`/maintenance\` | Enables/disables the maintenance-mode notice. |
| \`/statusupdate\` | Sends a direct status update to subscribers. |
| \`/blacklist\` | Blocks a server from using Guardian. |
| \`/unblacklist\` | Removes a server from the blacklist. |

## ESNG AI

Guardian includes the **ESNG AI** local assistant. It only wakes when the message begins with \`ESNG\` (case-insensitive), which keeps normal server conversation from triggering it.

Examples:

\`\`\`text
ESNG help
ESNG security status
ESNG anti-nuke
ESNG tickets
ESNG verification
ESNG backups
ESNG store
ESNG what can I get for $1
ESNG Website Builder
ESNG Warden checkout
ESNG Discord
ESNG SMP
\`\`\`

ESNG AI can explain Guardian features and ESN information included in the bot's local knowledge. For security-status questions it can read Guardian's current server configuration. It does **not** require an OpenAI API key.

## Persistence, Backups, and Restarts

Guardian stores server configuration, moderation/security cases, ticket records, verification state, lockdown restoration state, and related persistent data in SQLite.

- Default database: \`data/esn_guardian.db\`
- Keep the \`data/\` directory on persistent storage.
- Do **not** commit the live database or \`.env\` secrets to GitHub.
- Use \`/backupdb\` and \`/backupstatus\` for owner-accessible database backup operations.
- A host that deletes the project/data directory on every restart will also erase persistent settings unless a persistent volume is configured.

## Permissions Guardian Needs

Only grant permissions needed for the features you actually use. Common Guardian features depend on:

- View Channels
- Send Messages
- Read Message History
- Manage Messages
- Moderate Members
- Kick Members
- Ban Members
- Manage Nicknames
- Manage Roles
- Manage Channels
- View Audit Log
- Manage Webhooks where webhook security/management requires it

Discord role hierarchy still applies even when the permission exists.

## Troubleshooting

### Slash commands do not appear

1. Confirm the bot was invited with the \`applications.commands\` scope.
2. Restart Guardian.
3. Use \`/synccommands\` from the configured bot owner account.
4. Confirm the bot is actually connected to that server.

### Moderation says it cannot target a member

Move the ESN Guardian role above the target member's highest role. The command caller must also satisfy Guardian's permission and hierarchy checks.

### Anti-nuke is not reacting

Check \`/antinuke status\`, then run \`/security scan\`. Guardian needs **View Audit Log** and the moderation/channel/role permissions required for the containment action.

### Verification or autorole does not assign a role

Check that the configured role is not managed/privileged and is below Guardian's highest role.

### Settings disappear after a restart

The host must preserve the \`data/\` directory and SQLite database. Configure a persistent volume and keep \`DATABASE_PATH\` pointed at persistent storage.

### ESNG AI is not replying

The message must begin with \`ESNG\`. Normal conversation is intentionally ignored. Also verify the bot can view the channel and send messages there.

## Security Notes

- Never share \`DISCORD_TOKEN\`, personal-access tokens, host secrets, or the production SQLite database publicly.
- Keep Guardian's role high enough to do its job, but do not grant unrelated Administrator access just for convenience.
- Use \`/antinuke trust\` only for people who truly need recovery bypass access.
- Review \`/security cases\`, moderation history, and configured log channels during incidents.
- Run the repository test and dependency-audit commands documented above before important releases.
