# ESN Guardian

ESN Guardian is ES Network's Python Discord security, moderation, verification, recovery, logging, and incident-response platform.

## Primary runtime

Python is the live Guardian runtime.

Production entrypoint:

```bash
python bot.py
```

`bot.py` performs release-integrity checks and startup rollback protection before loading Guardian. `main.py` remains the direct development entrypoint.

Recommended Python: **3.11-3.13**.

```bash
pip install -r requirements.txt
python bot.py
```

Never delete `data/` during an update. It contains the persistent Guardian database, backups, release guard state, status data, and last-known-good release snapshot.

## Guardian MAX integrated layer

Guardian MAX sits above the existing v6/v7 stack and turns the remaining optional hardening features into one coordinated protection layer.

It adds:

- Verification v2 MAX with automatic verified/unverified roles, a dedicated verification channel, human challenges, account-age rules, adaptive risk review, and quarantine escalation
- Quarantine MAX with timed containment, dangerous-role stripping, automatic expiry, and safe role restoration
- Link & Scam Protection MAX with composite phishing scoring, punycode/shortener/IP-link checks, zero-width text detection, QR-bait detection, and dangerous attachment screening
- Raid Engine v4 identity-cluster detection using account age, default-avatar signals, username similarity, and coordinated join bursts
- Anti-Nuke v2 slow-chain detection across five-minute audit-log windows, designed to catch attacks that deliberately stay below the fast anti-nuke threshold
- Sentinel v2 duplicate-safe signal processing and correlation
- Guardian AI Security Analyst server/member explanations through `/guardianmax analyst` and ESNG
- Automatic six-hour encrypted off-host replication when the existing v7 backup endpoint/key are configured
- Local MAX heartbeat JSON plus optional external heartbeat push
- Full `/guardianmax self-test`
- `/guardianmax setup-max` safe baseline automation
- Interactive `/guardianmax center` security center

Main Guardian MAX commands:

- `/guardianmax status`
- `/guardianmax setup-max`
- `/guardianmax self-test`
- `/guardianmax center`
- `/guardianmax quarantine`
- `/guardianmax release`
- `/guardianmax analyst`
- `/guardianmax backup`
- `/guardianmax watchdog`

`/guardianmax setup-max` intentionally affects **new-member access only** through the Guardian Unverified role. Existing members are not bulk-assigned that role.

## Guardian Protection v7 MAX

v7 builds on the v6 anti-nuke, raid, rollback, Sentinel, Overwatch, Resilience, and adaptive-containment systems.

Protection now includes:

- Predictive security state machine: NORMAL → ELEVATED → HIGH → CRITICAL → PANIC
- Adaptive containment thresholds that tighten automatically as risk rises
- Per-member adaptive risk scoring
- Compromised-staff behavior baselines using action, command, channel, and time patterns
- Trust-graph reporting and privilege-escalation path detection
- Permission-change simulation before dangerous permissions are granted
- Two-person approval for selected catastrophic actions
- Protected channels, roles, bots, log channels, and sealed security settings
- Canary/honeypot channel and role support
- Permission firewall and dangerous-role rollback
- Automatic channel/role healing and rolling recovery checkpoints
- Webhook fingerprinting and unknown-webhook destruction
- Unapproved bot-installation firewall
- Raid fingerprinting using account age, timing, and name clusters
- Adaptive verification challenges and high-risk review
- Composite phishing, fake-gift, suspicious-link, QR, hidden-Unicode, and credential defense
- Sensitive command abuse protection
- Priority emergency security queue and duplicate-event suppression
- Automatic PANIC escalation
- Emergency minimal mode that preserves core security when the host/database is degraded
- Cryptographically chained incident evidence
- Incident replay and post-attack forensics
- Response/ingest latency metrics
- Application, bot, and webhook reputation
- False-positive review and live-risk recalibration
- Privacy-preserving optional cross-server threat-intelligence federation
- Auditable global-ban confidence/source/evidence metadata
- Policy profiles: Community, High Security, Maximum Lockdown, and custom thresholds
- Temporary/JIT staff-role grants with automatic expiry
- Trusted recovery-team approvals without permission to disable Guardian
- Owner-safe containment for situations Discord does not allow a bot to punish directly
- Encrypted optional off-host database backup replication
- Authenticated read-only status/dashboard API plus local status JSON
- Standalone external watchdog support
- Startup file-integrity verification
- Optional signed deployment manifests
- Automatic rollback after repeated failed starts
- Dependency vulnerability auditing in CI
- Safe non-destructive chaos tests and protection benchmarks
- ESNG Intelligence v7 MAX awareness of v7 state, trust graph, privilege paths, replay, benchmark, and chaos-test results

## Fast log setup

To send **every Guardian log type to one channel at once**:

```
/logs-all channel:#your-log-channel
```

This sets moderation, security, member, message, verification, system, guild, voice, invite, role, and command logs to the same channel and automatically marks that channel as a v7 protected asset.

You can still route one type separately with:

```
/logs category:<type> channel:#channel
```

## Main security commands

Core security:

- `/security`
- `/antinuke`
- `/guardian`
- `/sentinel`
- `/overwatch`
- `/resilience`
- `/protection` — v6 adaptive containment
- `/shield` — v7 predictive defense

Important v7 commands:

- `/shield status`
- `/shield profile`
- `/shield custom-policy`
- `/shield approve`
- `/shield protect-channel`
- `/shield protect-role`
- `/shield protect-bot`
- `/shield protect-settings`
- `/shield canary`
- `/shield simulate-role`
- `/shield privilege-paths`
- `/shield trust-graph`
- `/shield benchmark`
- `/shield chaos-test`
- `/shield replay`
- `/shield reputation`
- `/shield recovery-add`
- `/shield recovery-remove`
- `/shield temp-role`
- `/shield review`
- `/shield integrity`
- `/shield backup-offhost`

Moderation:

- `/warn`, `/warnings`
- `/timeout`, `/untimeout`
- `/kick`, `/ban`, `/unban`
- `/clear`, `/slowmode`
- `/case`, `/history`
- `/nickname`, `/role`, `/massrole`
- `/lock`, `/unlock`, `/lockdown`, `/unlockdown`

Verification/tickets:

- `/verification setup|enable|disable|reset|status`
- `/verify`
- `/ticket-config`, `/ticket`, `/ticket-close`

Operations:

- `/botstats`, `/backupdb`, `/backupstatus`
- `/servers`, `/synccommands`
- `/globalban`, `/globalunban`
- `/broadcast`, `/maintenance`
- `/blacklist`, `/unblacklist`

## ESNG Intelligence v7 MAX

Messages beginning with `ESNG` wake the Guardian intelligence system.

Examples:

- `ESNG guardian v7`
- `ESNG trust graph`
- `ESNG privilege paths`
- `ESNG incident replay`
- `ESNG protection benchmark`
- `ESNG chaos test`
- `ESNG full security report`
- `ESNG highest risk member`
- `ESNG runtime health`
- `ESNG explain case #12`

ESNG does not silently execute privileged emergency controls from normal chat messages.

## Required Discord permissions

Enable the permissions required by the protections you use:

- View Audit Log
- Manage Messages
- Moderate Members
- Kick Members
- Ban Members
- Manage Roles
- Manage Channels
- Manage Webhooks

Guardian's role must remain above roles and members it needs to contain or restore. Discord does not allow bots to ban the server owner; Guardian uses owner-safe containment instead.

## Persistence and recovery

Default database:

```
data/esn_guardian.db
```

Guardian uses SQLite WAL mode, serialized writes, integrity checks, verified backup rotation, startup/shutdown backups, recovery checkpoints, and a last-known-good release snapshot.

After a healthy startup, the release guard saves a local last-known-good Python runtime. Repeated failed starts can automatically restore it.

## Optional v7 external services

All external integrations are disabled unless you configure them.

Authenticated dashboard/watchdog:

```
GUARDIAN_DASHBOARD_PORT=
GUARDIAN_DASHBOARD_TOKEN=
GUARDIAN_STATUS_URL=
GUARDIAN_ALERT_WEBHOOK=
GUARDIAN_EXPECTED_GUILD_IDS=
GUARDIAN_WATCHDOG_HEARTBEAT_URL=
GUARDIAN_WATCHDOG_HEARTBEAT_TOKEN=
```

Encrypted off-host backups:

```
GUARDIAN_BACKUP_ENDPOINT=
GUARDIAN_BACKUP_TOKEN=
GUARDIAN_BACKUP_ENCRYPTION_KEY=
```

`GUARDIAN_BACKUP_ENCRYPTION_KEY` must be a valid Fernet key. Guardian will not upload a database backup if the encryption key is absent or invalid.

Privacy-preserving threat-intelligence federation:

```
GUARDIAN_THREAT_INTEL_ENDPOINT=
GUARDIAN_THREAT_INTEL_TOKEN=
GUARDIAN_INTEL_SALT=
```

Only hashed subject identifiers and reputation/evidence counts are shared by the v7 federation path.

Signed release verification:

```
GUARDIAN_RELEASE_HMAC_KEY=
```

When this key is configured on the host, Guardian requires a matching signed `guardian_manifest.sig`.

## External watchdog

`watchdog.py` is intentionally a separate process/service. Run it somewhere independent from Guardian so a Guardian host outage cannot take down the watchdog too.

```bash
python watchdog.py
```

It can alert when Guardian goes offline, enters emergency minimal mode, reaches CRITICAL/PANIC, or disappears from an expected server.

## CI and deployment

The main branch runs:

- Python 3.11, 3.12, and 3.13 compile/tests
- dependency vulnerability audit
- deployment package generation
- runtime checksum manifest generation
- optional HMAC release signing when the repository signing secret is configured

The older Node conversion remains legacy/reference code; production Guardian development targets Python.
