# ESN Guardian

ESN Guardian is the Discord security, moderation, recovery, verification, ticketing, logging, and server-protection bot for ES Network.

## Runtime

**Node.js 24+ is now the primary runtime.** The current entrypoint is:

```
src/index.js
```

Install and run:

```bash
npm install
npm start
```

Required environment variables:

```
DISCORD_TOKEN=
BOT_OWNER_ID=
DATABASE_PATH=data/esn_guardian.db
LOG_LEVEL=INFO
```

## Main protection systems

- Anti-nuke destructive-action tracking and containment
- Raid/join burst detection and quarantine
- Zero-tolerance external-app detection where Discord exposes the interaction
- Unapproved bot blocking
- Webhook and integration guard
- Credential leak detection
- Automatic channel/role recovery from trusted snapshots
- PANIC lockdown mode
- Persistent SQLite configuration and cases
- Scheduled/startup/shutdown database backups
- Sentinel security signal history
- Overwatch policy baseline/integrity checks
- Resilience readiness checks and recovery planning

## Commands

Security families:

- `/guardian`
- `/security`
- `/antinuke`
- `/overwatch`
- `/resilience`
- `/sentinel`

Moderation:

- `/warn`, `/warnings`, `/timeout`, `/untimeout`
- `/kick`, `/ban`, `/unban`
- `/clear`, `/slowmode`, `/case`, `/history`
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

## ESNG AI

Messages beginning with `ESNG` receive Guardian help for security, anti-nuke, raids, verification, tickets, backups, moderation, and ES Network links.

## Discord permissions

Guardian should have the permissions needed for the protections you enable, including View Audit Log, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, and Manage Webhooks. Its role must be above roles and members it needs to manage.

## Persistence

The default database path is:

```
data/esn_guardian.db
```

Keep the `data/` directory on persistent host storage. The Node edition uses SQLite directly through Node's built-in `node:sqlite` API.

The older Python source remains in the repository as migration/reference material, but CogitHost and new deployments should run the Node.js entrypoint.
