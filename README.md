# ESN Guardian

ESN Guardian is the Discord security and moderation bot for ES Network.

This build is intentionally focused on **Discord protection, moderation, verification, tickets, logging, recovery, and owner operations**. Website/store/status information that already exists on the ESN website is no longer duplicated as bot commands.

Official ESN website: https://esnoffical.com  
Official ESN Discord: https://discord.gg/3gxA66KZ8

## Current Security Stack

### External-app zero tolerance
- Detects user-installed/external app activity that Discord exposes to bots.
- Immediately bans the invoking member.
- Permanently stores the detected application ID.
- Bans the app's bot account if it exists in the server.
- Removes matching server integrations when possible.
- Re-bans blocked application bots if they later join.
- `/security harden` disables the **Use External Apps** permission on manageable roles and explicit channel allows.

Discord can still keep some external-app responses private/ephemeral. Those private interactions are not visible to other bots.

### Automatic rollback
Guardian keeps recovery snapshots and automatically attempts to repair unauthorized destructive changes:
- deleted channels and categories
- deleted roles
- channel permission/name/position changes
- role permission escalation
- dangerous role assignments
- Guardian role tampering

Snapshots include role/member assignments, channel/category relationships, and channel permission overwrites.

### Bot approval
New bots must be approved before joining.

1. Run `/guardian approve-bot bot_id:<ID>`.
2. Add the bot.
3. If an unapproved bot joins, Guardian bans it and contains the person who added it when that actor is not trusted.

Use `/guardian unapprove-bot` to remove an approval.

### Webhook and integration guard
- Existing trusted webhooks/integrations are saved in the recovery baseline.
- New webhooks created by untrusted actors are deleted.
- Unknown integrations are removed.
- Trusted owner/recovery changes can be accepted into the baseline.

### Compromised-admin containment
Guardian tracks destructive actions in a short window. When a non-owner account suddenly performs multiple destructive actions, Guardian attempts to:
- remove manageable high-risk roles
- apply a 24-hour timeout
- ban the actor if timeout containment is impossible
- record a critical security case

This applies even when the account previously had powerful permissions.

### Credential leak detector
Guardian deletes messages matching high-confidence credential patterns such as:
- Discord-style bot tokens
- GitHub personal access tokens
- AWS access keys
- private key headers
- common `sk-...` API-secret formats

The sender is temporarily contained and the incident is logged.

### Raid escalation
The existing raid system:
- detects rapid join surges
- detects very new accounts
- quarantines suspicious joins
- enables temporary raid containment
- triggers server lockdown at the configured threshold

`/security harden` enables the recommended secure baseline.

### PANIC mode
`/guardian panic enabled:true` performs maximum emergency containment:
- saves a recovery snapshot
- disables external-app permission exposure
- bans unapproved bots
- deletes unapproved webhooks
- removes unapproved integrations
- enables strict AutoMod and anti-nuke thresholds
- locks text channels

Release it with:

`/guardian panic enabled:false`

Core protections remain enabled after PANIC is released.

## Recommended First Setup

1. Give Guardian:
   - View Channels
   - Send Messages
   - Read Message History
   - Manage Messages
   - Moderate Members
   - Kick Members
   - Ban Members
   - Manage Roles
   - Manage Channels
   - Manage Webhooks
   - View Audit Log
2. Put the Guardian role above every role it must protect or manage.
3. Run `/security harden`.
4. Run `/guardian audit`.
5. Configure `/logs`.
6. Configure verification/tickets if your server uses them.
7. Before adding a new bot, run `/guardian approve-bot`.

## Security Commands

### `/guardian`
| Command | Purpose |
| --- | --- |
| `/guardian audit` | Full security scoreboard: permissions, risky roles, bot approvals, external-app exposure and advanced guards. |
| `/guardian status` | Shows advanced protection state and last snapshot. |
| `/guardian snapshot` | Saves a trusted recovery baseline and approves the bots/webhooks/integrations currently present. |
| `/guardian approve-bot` | Approves a bot/application ID before it joins. |
| `/guardian unapprove-bot` | Removes a bot approval. |
| `/guardian panic` | Enables or releases emergency containment. |

### `/security`
Core commands retained:
- `/security harden`
- `/security status`
- `/security scan`
- `/security cases`
- `/security automod`
- `/security thresholds`
- `/security links`
- `/security allow-domain`
- `/security remove-domain`
- `/security add-word`
- `/security remove-word`
- `/security words`
- `/security domains`
- `/security check-link`
- `/security reset-automod`
- `/security raid`
- `/security raid-status`
- `/security quarantine`
- `/security release`
- `/security member`

### `/antinuke`
- `/antinuke setup`
- `/antinuke enable`
- `/antinuke disable`
- `/antinuke status`
- `/antinuke trust`
- `/antinuke untrust`

Only the Discord server owner can change anti-nuke trust or disable the core anti-nuke controls.

## Moderation Commands

Guardian keeps commands that directly perform Discord moderation work:

- `/warn`
- `/warnings`
- `/timeout`
- `/untimeout`
- `/kick`
- `/ban`
- `/unban`
- `/clear`
- `/slowmode`
- `/case`
- `/history`
- `/nickname`
- `/role`
- `/massrole`
- `/lock`
- `/unlock`
- `/lockdown`
- `/unlockdown`

Role hierarchy and caller permissions are enforced.

## Verification and Tickets

Verification:
- `/verification setup`
- `/verification enable`
- `/verification disable`
- `/verification reset`
- `/verification status`
- `/verify`

Tickets:
- `/ticket-config`
- `/ticket`
- `/ticket-close`

## Server Configuration and Community Utilities

Kept because they perform real Discord-side actions:
- `/help`
- `/panel`
- `/config`
- `/welcome`
- `/goodbye`
- `/autorole`
- `/logs`
- `/suggest`
- `/smpannounce`

## Bot-owner Operations

- `/botstats`
- `/backupdb`
- `/backupstatus`
- `/servers`
- `/synccommands`
- `/globalban`
- `/globalunban`
- `/broadcast`
- `/maintenance`
- `/blacklist`
- `/unblacklist`

These are restricted to the configured `BOT_OWNER_ID`.

## Commands Removed

The following were retired because the ESN website already handles that information better, or because they were unnecessary duplication:

- `/smp`
- `/status smp`
- `/status subscribe`
- `/status unsubscribe`
- `/status subscriptions`
- `/discord`
- `/health`
- `/esnpanel`
- `/statusupdate`
- the ESNG website/store AI message system

The Discord bot is now more focused on **security and server operations** instead of copying website features.

## Persistence and Backups

Guardian uses SQLite and stores persistent configuration such as:
- security cases
- anti-nuke settings
- raid configuration
- verification
- tickets
- blocked external applications
- bot approvals
- webhook/integration baselines
- Guardian recovery snapshots
- lockdown restoration state

Default database:

`data/esn_guardian.db`

Keep the `data/` directory on persistent host storage.

Guardian creates verified database backups at startup/shutdown and on its scheduled backup cycle.

## Development

Install:

`python -m pip install -r requirements.txt pytest pytest-asyncio pip-audit`

Run tests:

`python -m pytest -q`

Audit dependencies:

`python -m pip_audit -r requirements.txt`

GitHub Actions runs both automatically on pushes and pull requests.

## Important Discord Limits

Guardian can only act on data Discord exposes through its API.

For user-installed external apps, Discord may force responses to be private/ephemeral when **Use External Apps** is disabled. Other bots cannot see those private interactions, so no Discord bot can truthfully promise to detect every private external-app use.

Guardian therefore combines:
- Discord permission hardening
- visible external-app detection
- permanent application-ID blocking
- bot/integration removal
- anti-nuke
- automatic rollback
- audit-log attribution
- emergency containment

That is the strongest enforceable approach available from a normal Discord bot.
