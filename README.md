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

## RayNode Setup

1. Create a new private GitHub repository, then upload every project file except `.env`, `.venv`, and `data/`. The required files include `main.py`, `requirements.txt`, `esn_guardian/`, `.gitignore`, and this README.
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

Anti-nuke is disabled by default. A server administrator can enable it with:

```text
/antinuke setup action_limit:3 window_seconds:15
```

It attributes channel deletions, role creations/deletions, bans, kicks, dangerous role-permission escalations, and dangerous role assignments from Discord audit logs. Dangerous role escalations and assignments are immediately reverted when possible. When a non-trusted, non-owner executor reaches the threshold, Guardian attempts to ban that executor and enables server lockdown. Grant the bot **View Audit Log**, **Ban Members**, **Manage Channels**, and **Manage Roles**. Use `/antinuke trust` only for trusted recovery administrators; inspect the current configuration with `/antinuke status`.

## Advanced AutoMod And Raid Protection

Use `/security thresholds`, `/security links`, and `/security automod` to configure flood, mention, caps, invite, and strict-link enforcement for each server. Strict link mode uses the persisted `/security allow-domain` allowlist. Use `/security raid` to configure join-rate detection, suspicious account age, and a quarantine role. The quarantine role must be below the bot's highest role and should deny access to sensitive channels through your server's role permissions.