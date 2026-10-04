# ESN Guardian

ESN Guardian is ES Network's Discord security, moderation, recovery, verification, ticketing, logging, and server-protection bot.

## Primary runtime

**Python is the live and primary Guardian runtime.**

Entrypoint:

```bash
python main.py
```

Recommended runtime: **Python 3.11-3.13**.

Install:

```bash
pip install -r requirements.txt
python main.py
```

Required environment variables:

```
DISCORD_TOKEN=
BOT_OWNER_ID=
DATABASE_PATH=data/esn_guardian.db
LOG_LEVEL=INFO
```

The older Node conversion is retained only as a legacy/reference build on the `node-hosting` branch. Main development and deployment now target Python. Protection v6 is loaded by default on the Python runtime.

## Guardian v6 MAX

Guardian v6 MAX combines:

- Anti-nuke destructive-action tracking, containment, and automatic lockdown
- Adaptive per-member threat scoring using account age, case history, dangerous roles, verification failures, external-app signals, and raid clustering
- Compromised-staff detection that correlates destructive actions even when the actor has legitimate staff permissions
- Emergency privilege stripping for manageable dangerous roles before normal anti-nuke thresholds are reached
- Multi-step attack-chain scoring across channels, roles, bans, webhooks, integrations, bots, commands, external apps, and tamper events
- Owner-safe containment: Guardian never attempts to ban the server owner; it instead locks manageable attack surfaces, removes unapproved integrations/webhooks, preserves evidence, and raises a critical incident
- Permission firewall with remembered role-permission baselines and automatic rollback of unauthorized high-risk permission grants
- Automatic server healing for modified channels/roles plus existing deleted channel/role recovery
- Multiple rolling recovery checkpoints with owner-triggered recovery passes
- Webhook fingerprinting for approved webhook identity/change detection
- Bot-installation firewall that blocks bots not present in the approved baseline
- Raid fingerprinting using join timing, account age clusters, and username-pattern clusters
- Adaptive verification: suspicious members can be forced through a human check or held for staff review
- Composite scam/phishing detection for gift/verification/QR/link indicators in server messages, plus safety warnings for suspicious messages sent directly to Guardian
- Sensitive Guardian-command abuse shield with burst blocking
- Priority security-action queue so critical containment runs before non-critical v6 work
- Automatic PANIC mode when attack-chain scores cross critical thresholds
- Post-attack forensic incident records with actor, signal, target, timing, and event summaries
- Self-protection watchdog for lost Guardian permissions, deleted configured log channels, and disabled core protection layers
- Fail-safe in-memory protection when persistence temporarily fails
- Fast raid detection, young-account burst detection, quarantine, and bounded kick workers
- Zero-tolerance external-app detection where Discord exposes interaction metadata
- Blocked-application persistence, bot blocking, webhook guard, and integration guard
- Dangerous role-permission escalation rollback
- Credential/phishing link defense, punycode checks, hidden-Unicode detection, invite/link policy, flood protection, mention spam, repeated-message detection, caps control, and blocked words
- Sentinel anomaly signals, subject behavior profiles, and multi-step incident correlation
- Overwatch posture scoring, policy drift detection, incident sessions, trends, and tamper-evident case verification
- Resilience self-health with SQLite integrity checks, gateway latency, event-loop lag, permission/module checks, backup freshness, recovery snapshots, and automatic recovery backups
- WAL-backed SQLite persistence with serialized writes, integrity-checked backups, automatic corruption recovery, WAL checkpointing, and optimized cache settings
- Verification with account-age rules, optional human-check codes, retry throttling, persistent verified-member records, and verification cases/logs
- Moderation with role-hierarchy safeguards and bounded mass-role concurrency
- Rate-bounded Guardian logging so heavy incidents do not flood the event loop
- Scheduled database backups every 3 hours plus startup/shutdown and resilience-triggered backups
- ESNG Intelligence v6 MAX using live Guardian security, runtime, database, backup, Sentinel, Overwatch, and Resilience state

## Main command families

Security:

- `/guardian`
- `/security`
- `/antinuke`
- `/overwatch`
- `/resilience`
- `/sentinel`
- `/protection`

Moderation:

- `/warn`, `/warnings`
- `/timeout`, `/untimeout`
- `/kick`, `/ban`, `/unban`
- `/clear`, `/slowmode`
- `/case`, `/history`
- `/nickname`, `/role`, `/massrole`
- `/lock`, `/unlock`, `/lockdown`, `/unlockdown`

Verification and tickets:

- `/verification setup|enable|disable|reset|status`
- `/verify`
- `/ticket-config`, `/ticket`, `/ticket-close`

Community/setup:

- `/help`, `/panel`, `/config`
- `/welcome`, `/goodbye`, `/autorole`, `/logs`
- `/suggest`, `/smpannounce`

Bot-owner operations:

- `/botstats`, `/backupdb`, `/backupstatus`
- `/servers`, `/synccommands`
- `/globalban`, `/globalunban`
- `/broadcast`, `/maintenance`
- `/blacklist`, `/unblacklist`

## ESNG Intelligence v6 MAX

Messages beginning with `ESNG` wake the Guardian intelligence system.

Examples:

- `ESNG protection v6`
- `ESNG highest risk member`
- `ESNG v6 forensics`
- `ESNG full security report`
- `ESNG runtime health`
- `ESNG threat report`
- `ESNG sentinel status`
- `ESNG explain signal #3`
- `ESNG explain case #12`
- `ESNG analyze subject 123456789012345678`
- `ESNG recovery readiness`
- `ESNG backup freshness`

ESNG chat does not silently disable protection or execute privileged emergency controls. Those actions stay behind permission-checked slash commands.

## Discord permissions

Guardian should have the permissions required by the protections you enable, including:

- View Audit Log
- Manage Messages
- Moderate Members
- Kick Members
- Ban Members
- Manage Roles
- Manage Channels
- Manage Webhooks

Guardian's role must be above roles and members it needs to manage. Discord does not allow a bot to ban the server owner, and Guardian records that limitation explicitly when external-app enforcement encounters it.

## Persistence and backups

Default database:

```
data/esn_guardian.db
```

Keep the entire `data/` directory on persistent host storage.

Guardian uses SQLite WAL mode, serialized write operations, integrity checks, automatic recovery from valid backups, and verified backup rotation. Do not delete `data/esn_guardian.db` when updating Guardian.

## CI and deployment

Main branch:

- Python 3.11, 3.12, and 3.13 compile/test CI
- Automatic Python deployment ZIP artifact

Legacy Node checks only run against `node-hosting`.
