'use strict'

const crypto = require('node:crypto')
const {
  AuditLogEvent,
  Events,
  PermissionFlagsBits
} = require('discord.js')
const {
  auditActor,
  canLockChannel,
  dangerousRole,
  extractDomains,
  logEvent
} = require('./utils')

const actionWindows = new Map()
const joinWindows = new Map()
const messageWindows = new Map()
const rollbackGuard = new Set()

const CREDENTIAL_PATTERNS = [
  /(?:mfa\.[\w-]{20,}|[\w-]{23,28}\.[\w-]{6}\.[\w-]{25,})/i,
  /gh[pousr]_[A-Za-z0-9_]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/
]

function bigintString(v) {
  try { return BigInt(v).toString() } catch { return String(v ?? '0') }
}

function jsonHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

function snapshotGuild(guild) {
  return {
    guildId: guild.id,
    createdAt: new Date().toISOString(),
    roles: guild.roles.cache
      .filter(role => role.id !== guild.id)
      .map(role => ({
        id: role.id,
        name: role.name,
        color: role.color,
        hoist: role.hoist,
        mentionable: role.mentionable,
        permissions: role.permissions.bitfield.toString(),
        position: role.position,
        managed: role.managed
      })),
    channels: guild.channels.cache.map(channel => ({
      id: channel.id,
      name: channel.name,
      type: channel.type,
      parentId: channel.parentId,
      position: channel.rawPosition,
      topic: 'topic' in channel ? channel.topic : null,
      nsfw: 'nsfw' in channel ? channel.nsfw : false,
      rateLimitPerUser: 'rateLimitPerUser' in channel ? channel.rateLimitPerUser : 0,
      permissionOverwrites: channel.permissionOverwrites?.cache?.map(o => ({
        id: o.id,
        type: o.type,
        allow: o.allow.bitfield.toString(),
        deny: o.deny.bitfield.toString()
      })) || []
    }))
  }
}

function saveSnapshot(db, guild) {
  const data = snapshotGuild(guild)
  db.run(
    'INSERT INTO guardian_snapshots (guild_id,data,created_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET data=excluded.data, created_at=CURRENT_TIMESTAMP',
    BigInt(guild.id), JSON.stringify(data)
  )
  for (const member of guild.members.cache.values()) {
    if (member.user.bot) {
      db.run(
        'INSERT OR IGNORE INTO approved_bots (guild_id,bot_id,added_by_id) VALUES (?,?,?)',
        BigInt(guild.id), BigInt(member.id), BigInt(guild.ownerId)
      )
    }
  }
  return data
}

function getSnapshot(db, guildId) {
  const row = db.get('SELECT data FROM guardian_snapshots WHERE guild_id=?', BigInt(guildId))
  if (!row?.data) return null
  try { return JSON.parse(row.data) } catch { return null }
}

function trustedUser(db, guild, userId) {
  if (!userId) return true
  if (String(userId) === String(guild.ownerId)) return true
  const row = db.get(
    'SELECT 1 AS ok FROM anti_nuke_trusted_users WHERE guild_id=? AND user_id=?',
    BigInt(guild.id), BigInt(userId)
  )
  return Boolean(row)
}

function isApprovedBot(db, guildId, botId) {
  return Boolean(db.get(
    'SELECT 1 AS ok FROM approved_bots WHERE guild_id=? AND bot_id=?',
    BigInt(guildId), BigInt(botId)
  ))
}

async function createSecurityCase(db, guild, actorId, action, reason, details = {}) {
  return db.createCase(guild.id, actorId, null, action, reason, null, details)
}

async function containActor(db, guild, actor, reason) {
  if (!actor || actor.id === guild.ownerId || actor.id === guild.members.me?.id) return false
  if (trustedUser(db, guild, actor.id)) return false

  const member = await guild.members.fetch(actor.id).catch(() => null)
  if (!member) return false

  const removable = member.roles.cache.filter(role =>
    role.id !== guild.id &&
    role.editable &&
    dangerousRole(role)
  )

  for (const role of removable.values()) {
    await member.roles.remove(role, `ESN Guardian containment: ${reason}`).catch(() => {})
  }

  let contained = false
  if (member.moderatable) {
    await member.timeout(24 * 60 * 60 * 1000, `ESN Guardian containment: ${reason}`).then(() => {
      contained = true
    }).catch(() => {})
  }

  if (!contained && member.bannable) {
    await member.ban({ reason: `ESN Guardian containment: ${reason}` }).then(() => {
      contained = true
    }).catch(() => {})
  }

  await createSecurityCase(db, guild, actor.id, 'SECURITY_CONTAINMENT', reason, {
    removedRoles: removable.map(role => role.id),
    contained
  })

  await logEvent(
    db,
    guild,
    'security_log_channel_id',
    'Guardian containment',
    `Actor: <@${actor.id}> (${actor.id})\nReason: ${reason}\nDangerous roles removed: ${removable.size}\nContainment applied: ${contained ? 'yes' : 'no'}`
  )
  return contained
}

async function registerDestructiveAction(db, guild, actor, action, targetId) {
  if (!actor || actor.bot || actor.id === guild.members.me?.id || trustedUser(db, guild, actor.id)) return
  db.ensureGuild(guild.id)
  const cfg = db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(guild.id))
  if (!cfg || !Number(cfg.enabled)) return

  const limit = Number(cfg.action_limit || 3)
  const windowMs = Number(cfg.window_seconds || 15) * 1000
  const key = `${guild.id}:${actor.id}`
  const now = Date.now()
  const history = (actionWindows.get(key) || []).filter(ts => now - ts < windowMs)
  history.push(now)
  actionWindows.set(key, history)

  await createSecurityCase(db, guild, actor.id, `ANTINUKE_${action}`, `Destructive action detected: ${action}`, { targetId })

  if (history.length >= limit) {
    actionWindows.set(key, [])
    await containActor(db, guild, actor, `Anti-nuke threshold reached: ${history.length} destructive actions within ${Math.round(windowMs / 1000)} seconds`)
  }
}

async function lockdownGuild(db, guild, reason = 'Security lockdown') {
  let changed = 0
  for (const channel of guild.channels.cache.values()) {
    if (!canLockChannel(channel)) continue
    try {
      const current = channel.permissionOverwrites.cache.get(guild.id)
      const send = current?.allow?.has(PermissionFlagsBits.SendMessages)
        ? 1
        : current?.deny?.has(PermissionFlagsBits.SendMessages)
          ? 0
          : null
      db.run(
        'INSERT OR REPLACE INTO lockdown_overwrites (guild_id,channel_id,send_messages) VALUES (?,?,?)',
        BigInt(guild.id), BigInt(channel.id), send
      )
      await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: false }, { reason })
      changed++
    } catch {}
  }
  db.updateSetting(guild.id, 'lockdown_active', 1)
  return changed
}

async function unlockdownGuild(db, guild, reason = 'Security lockdown released') {
  const rows = db.all('SELECT * FROM lockdown_overwrites WHERE guild_id=?', BigInt(guild.id))
  let changed = 0
  for (const row of rows) {
    const channel = guild.channels.cache.get(String(row.channel_id))
    if (!channel || !canLockChannel(channel)) continue
    try {
      let value = null
      if (row.send_messages === 1 || row.send_messages === 1n) value = true
      if (row.send_messages === 0 || row.send_messages === 0n) value = false
      await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: value }, { reason })
      changed++
    } catch {}
  }
  db.run('DELETE FROM lockdown_overwrites WHERE guild_id=?', BigInt(guild.id))
  db.updateSetting(guild.id, 'lockdown_active', 0)
  return changed
}

async function hardenGuild(db, guild) {
  db.ensureGuild(guild.id)
  db.run(
    'UPDATE security_config SET automod_enabled=1,flood_limit=6,flood_window_seconds=10,max_mentions=6,caps_percentage=80,block_invites=1 WHERE guild_id=?',
    BigInt(guild.id)
  )
  db.run(
    'UPDATE anti_nuke_config SET enabled=1,action_limit=3,window_seconds=15 WHERE guild_id=?',
    BigInt(guild.id)
  )
  db.run(
    'UPDATE raid_config SET enabled=1,join_limit=10,join_window_seconds=60,min_account_age_days=3 WHERE guild_id=?',
    BigInt(guild.id)
  )

  let rolesChanged = 0
  for (const role of guild.roles.cache.values()) {
    if (role.id === guild.id || !role.editable) continue
    if (role.permissions.has(PermissionFlagsBits.UseExternalApps)) {
      const next = role.permissions.remove(PermissionFlagsBits.UseExternalApps)
      try {
        await role.setPermissions(next, 'ESN Guardian /security harden')
        rolesChanged++
      } catch {}
    }
  }

  saveSnapshot(db, guild)
  return { rolesChanged }
}

async function panicGuild(db, guild, enabled) {
  db.setStateEnabled(`panic:${guild.id}`, enabled)
  if (!enabled) {
    const restored = await unlockdownGuild(db, guild, 'Guardian PANIC released')
    return { enabled: false, restored }
  }

  saveSnapshot(db, guild)
  await hardenGuild(db, guild)

  let botsRemoved = 0
  for (const member of guild.members.cache.values()) {
    if (!member.user.bot || member.id === guild.members.me?.id) continue
    if (isApprovedBot(db, guild.id, member.id)) continue
    if (member.bannable) {
      await member.ban({ reason: 'ESN Guardian PANIC: unapproved bot' }).then(() => botsRemoved++).catch(() => {})
    }
  }

  const locked = await lockdownGuild(db, guild, 'ESN Guardian PANIC')
  return { enabled: true, botsRemoved, locked }
}

async function restoreDeletedChannel(db, guild, deleted) {
  const key = `channel:${guild.id}:${deleted.id}`
  if (rollbackGuard.has(key)) return
  const snapshot = getSnapshot(db, guild.id)
  const saved = snapshot?.channels?.find(item => String(item.id) === String(deleted.id))
  if (!saved) return

  rollbackGuard.add(key)
  try {
    const options = {
      name: saved.name,
      type: saved.type,
      reason: 'ESN Guardian automatic rollback'
    }
    if (saved.parentId && guild.channels.cache.has(String(saved.parentId))) options.parent = String(saved.parentId)
    if (saved.topic != null) options.topic = saved.topic
    if (saved.nsfw != null) options.nsfw = Boolean(saved.nsfw)
    if (saved.rateLimitPerUser != null) options.rateLimitPerUser = Number(saved.rateLimitPerUser)
    if (saved.permissionOverwrites?.length) {
      options.permissionOverwrites = saved.permissionOverwrites.map(o => ({
        id: String(o.id),
        type: Number(o.type),
        allow: BigInt(o.allow),
        deny: BigInt(o.deny)
      }))
    }
    const recreated = await guild.channels.create(options)
    if (Number.isFinite(saved.position)) await recreated.setPosition(saved.position).catch(() => {})
  } catch {}
  finally {
    setTimeout(() => rollbackGuard.delete(key), 3000)
  }
}

async function restoreDeletedRole(db, guild, deleted) {
  const key = `role:${guild.id}:${deleted.id}`
  if (rollbackGuard.has(key)) return
  const snapshot = getSnapshot(db, guild.id)
  const saved = snapshot?.roles?.find(item => String(item.id) === String(deleted.id))
  if (!saved || saved.managed) return

  rollbackGuard.add(key)
  try {
    const role = await guild.roles.create({
      name: saved.name,
      color: Number(saved.color || 0),
      hoist: Boolean(saved.hoist),
      mentionable: Boolean(saved.mentionable),
      permissions: BigInt(saved.permissions || '0'),
      reason: 'ESN Guardian automatic rollback'
    })
    if (Number.isFinite(saved.position)) await role.setPosition(saved.position).catch(() => {})
  } catch {}
  finally {
    setTimeout(() => rollbackGuard.delete(key), 3000)
  }
}

async function applyAutomod(db, message) {
  if (!message.guild || message.author.bot) return false
  db.ensureGuild(message.guild.id)
  const cfg = db.get('SELECT * FROM security_config WHERE guild_id=?', BigInt(message.guild.id))
  if (!cfg || !Number(cfg.automod_enabled)) return false

  const text = message.content || ''
  const lower = text.toLowerCase()

  for (const pattern of CREDENTIAL_PATTERNS) {
    if (pattern.test(text)) {
      await message.delete().catch(() => {})
      await message.member?.timeout(10 * 60 * 1000, 'ESN Guardian credential leak containment').catch(() => {})
      const caseId = db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'CREDENTIAL_LEAK', 'High-confidence credential pattern detected', message.channel.id)
      await logEvent(db, message.guild, 'security_log_channel_id', `Credential leak | Case #${caseId}`, `Sender: <@${message.author.id}>\nChannel: <#${message.channel.id}>\nMessage was deleted and the sender was temporarily contained.`)
      return true
    }
  }

  const blockedWords = db.all('SELECT word FROM bad_words WHERE guild_id=?', BigInt(message.guild.id))
  if (blockedWords.some(row => lower.includes(String(row.word).toLowerCase()))) {
    await message.delete().catch(() => {})
    db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_WORD', 'Blocked word or phrase', message.channel.id)
    return true
  }

  const mentionCount = message.mentions.users.size + message.mentions.roles.size
  if (mentionCount > Number(cfg.max_mentions || 6)) {
    await message.delete().catch(() => {})
    await message.member?.timeout(5 * 60 * 1000, 'ESN Guardian mention spam').catch(() => {})
    db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_MENTIONS', `Mention count ${mentionCount}`, message.channel.id)
    return true
  }

  const letters = text.replace(/[^a-z]/gi, '')
  if (letters.length >= 12) {
    const capitals = letters.replace(/[^A-Z]/g, '').length
    const pct = Math.round((capitals / letters.length) * 100)
    if (pct >= Number(cfg.caps_percentage || 80)) {
      await message.delete().catch(() => {})
      db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_CAPS', `Caps percentage ${pct}%`, message.channel.id)
      return true
    }
  }

  const key = `${message.guild.id}:${message.author.id}`
  const now = Date.now()
  const windowMs = Number(cfg.flood_window_seconds || 10) * 1000
  const messages = (messageWindows.get(key) || []).filter(ts => now - ts <= windowMs)
  messages.push(now)
  messageWindows.set(key, messages)
  if (messages.length > Number(cfg.flood_limit || 6)) {
    await message.delete().catch(() => {})
    await message.member?.timeout(5 * 60 * 1000, 'ESN Guardian flood protection').catch(() => {})
    db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_FLOOD', `${messages.length} messages in ${Math.round(windowMs / 1000)} seconds`, message.channel.id)
    messageWindows.set(key, [])
    return true
  }

  if (Number(cfg.block_invites) && /(?:discord\.gg|discord(?:app)?\.com\/invite)\//i.test(text)) {
    await message.delete().catch(() => {})
    db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_INVITE', 'Discord invite blocked', message.channel.id)
    return true
  }

  if (Number(cfg.strict_links)) {
    const domains = extractDomains(text)
    if (domains.length) {
      const allowed = new Set(db.all('SELECT domain FROM allowed_domains WHERE guild_id=?', BigInt(message.guild.id)).map(r => String(r.domain)))
      const denied = domains.filter(domain => ![...allowed].some(base => domain === base || domain.endsWith(`.${base}`)))
      if (denied.length) {
        await message.delete().catch(() => {})
        db.createCase(message.guild.id, message.author.id, message.client.user?.id, 'AUTOMOD_LINK', `Blocked domains: ${denied.join(', ')}`, message.channel.id)
        return true
      }
    }
  }

  return false
}

async function detectExternalApp(db, message) {
  if (!message.guild) return false
  const appId = message.applicationId || message.interactionMetadata?.applicationId || message.interaction?.applicationId
  if (!appId) return false

  const invoker = message.interactionMetadata?.user || message.interaction?.user || null
  const invokerId = invoker?.id
  if (!invokerId || invokerId === message.client.user?.id) return false

  db.run(
    'INSERT INTO blocked_external_apps (guild_id,application_id,reason,last_detected_at) VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id,application_id) DO UPDATE SET reason=excluded.reason,last_detected_at=CURRENT_TIMESTAMP',
    BigInt(message.guild.id), BigInt(appId), 'Zero-tolerance external app use detected'
  )

  const member = await message.guild.members.fetch(invokerId).catch(() => null)
  let banned = false
  if (member?.bannable && member.id !== message.guild.ownerId) {
    await member.ban({ reason: `Zero-tolerance external app use; application_id=${appId}` }).then(() => banned = true).catch(() => {})
  }

  const appMember = message.guild.members.cache.get(String(appId))
  if (appMember?.user.bot && appMember.bannable) {
    await appMember.ban({ reason: 'Blocked external application' }).catch(() => {})
  }

  const caseId = db.createCase(
    message.guild.id,
    invokerId,
    message.client.user?.id,
    banned ? 'EXTERNAL_APP_BAN' : 'EXTERNAL_APP_BAN_FAILED',
    `Zero-tolerance external app use detected; application_id=${appId}`,
    message.channel.id,
    { applicationId: String(appId), banned }
  )

  await logEvent(
    db,
    message.guild,
    'security_log_channel_id',
    `External app security | Case #${caseId}`,
    `Target: <@${invokerId}> (${invokerId})\nApplication ID: ${appId}\nBan result: ${banned ? 'success' : 'failed'}`
  )
  return true
}

function attachSecurity(client, db) {
  client.on(Events.MessageCreate, async message => {
    try {
      if (await detectExternalApp(db, message)) return
      if (await applyAutomod(db, message)) return

      if (!message.guild || message.author.bot || !message.content?.toUpperCase().startsWith('ESNG')) return
      const q = message.content.slice(4).trim().toLowerCase()
      let answer = 'ESN Guardian is online. Ask me about security, anti-nuke, raids, verification, tickets, backups, moderation, or ESN services.'
      if (/security|protect|safe/.test(q)) answer = 'Guardian protects against destructive actions, raid bursts, suspicious bots, credential leaks, dangerous links, external apps, webhook/integration abuse, and supports recovery snapshots.'
      else if (/raid/.test(q)) answer = 'Raid protection watches join bursts and account age, can quarantine suspicious joins, and escalates to lockdown when thresholds are reached.'
      else if (/anti.?nuke|nuke/.test(q)) answer = 'Anti-nuke attributes destructive channel/role actions through the audit log, counts them inside a short window, and contains untrusted actors when the configured threshold is reached.'
      else if (/verify/.test(q)) answer = 'Use /verification setup to configure roles and the verification panel, then /verification enable. Members can press VERIFY or run /verify.'
      else if (/ticket/.test(q)) answer = 'Use /ticket-config to choose a support role. Members open tickets with /ticket and close them with /ticket-close.'
      else if (/backup|recover|snapshot/.test(q)) answer = 'Guardian keeps its SQLite state on persistent storage and supports /backupdb, /guardian snapshot, /overwatch backup, and automatic recovery baselines.'
      else if (/website|store|esn/.test(q)) answer = 'ES Network website: https://esnoffical.com — Discord: https://discord.gg/3gxA66KZ8'
      await message.reply({ content: answer, allowedMentions: { repliedUser: false } }).catch(() => {})
    } catch (error) {
      console.error('[Guardian] message security error', error)
    }
  })

  client.on(Events.GuildMemberAdd, async member => {
    try {
      db.ensureGuild(member.guild.id)

      const global = db.globalBanReason(member.id)
      if (global && member.bannable) {
        await member.ban({ reason: `ESN Guardian global ban: ${global}` }).catch(() => {})
        return
      }

      if (member.user.bot && member.id !== client.user.id && !isApprovedBot(db, member.guild.id, member.id)) {
        if (member.bannable) await member.ban({ reason: 'ESN Guardian: unapproved bot' }).catch(() => {})
        await logEvent(db, member.guild, 'security_log_channel_id', 'Unapproved bot blocked', `Bot: <@${member.id}> (${member.id})`)
        return
      }

      const settings = db.setting(member.guild.id)
      if (settings.autorole_id) {
        const role = member.guild.roles.cache.get(String(settings.autorole_id))
        if (role?.editable) await member.roles.add(role, 'ESN Guardian autorole').catch(() => {})
      }

      if (settings.welcome_channel_id) {
        const channel = member.guild.channels.cache.get(String(settings.welcome_channel_id))
        if (channel?.isTextBased()) await channel.send({ content: `Welcome ${member} to **${member.guild.name}**.`, allowedMentions: { users: [member.id] } }).catch(() => {})
      }
      await logEvent(db, member.guild, 'member_log_channel_id', 'Member joined', `Member: <@${member.id}> (${member.id})\nAccount created: <t:${Math.floor(member.user.createdTimestamp / 1000)}:F>`)

      const raid = db.get('SELECT * FROM raid_config WHERE guild_id=?', BigInt(member.guild.id))
      if (!raid || !Number(raid.enabled) || member.user.bot) return
      const now = Date.now()
      const windowMs = Number(raid.join_window_seconds || 60) * 1000
      const history = (joinWindows.get(member.guild.id) || []).filter(ts => now - ts <= windowMs)
      history.push(now)
      joinWindows.set(member.guild.id, history)
      const accountAge = now - member.user.createdTimestamp
      const suspiciousAge = accountAge < Number(raid.min_account_age_days || 3) * 86400000

      if (suspiciousAge && raid.quarantine_role_id) {
        const role = member.guild.roles.cache.get(String(raid.quarantine_role_id))
        if (role?.editable) await member.roles.add(role, 'ESN Guardian suspicious account quarantine').catch(() => {})
      }

      if (history.length >= Number(raid.join_limit || 10)) {
        await lockdownGuild(db, member.guild, 'ESN Guardian raid containment')
        db.createCase(member.guild.id, null, client.user?.id, 'RAID_CONTAINMENT', `${history.length} joins in ${Math.round(windowMs / 1000)} seconds`)
        await logEvent(db, member.guild, 'security_log_channel_id', 'RAID CONTAINMENT ACTIVE', `${history.length} joins detected inside ${Math.round(windowMs / 1000)} seconds. Text channels were locked.`)
        joinWindows.set(member.guild.id, [])
      }
    } catch (error) {
      console.error('[Guardian] member join security error', error)
    }
  })

  client.on(Events.GuildMemberRemove, async member => {
    await logEvent(db, member.guild, 'member_log_channel_id', 'Member left', `Member: ${member.user.tag} (${member.id})`).catch(() => {})
  })

  const destructive = [
    [Events.ChannelDelete, AuditLogEvent.ChannelDelete, 'CHANNEL_DELETE'],
    [Events.GuildRoleDelete, AuditLogEvent.RoleDelete, 'ROLE_DELETE']
  ]
  for (const [event, auditType, action] of destructive) {
    client.on(event, async target => {
      try {
        const guild = target.guild
        const actor = await auditActor(guild, auditType, target.id)
        await registerDestructiveAction(db, guild, actor, action, target.id)
        if (actor && !trustedUser(db, guild, actor.id) && actor.id !== client.user?.id) {
          if (action === 'CHANNEL_DELETE') await restoreDeletedChannel(db, guild, target)
          if (action === 'ROLE_DELETE') await restoreDeletedRole(db, guild, target)
        }
      } catch (error) {
        console.error('[Guardian] destructive action handler error', error)
      }
    })
  }

  client.on(Events.ChannelUpdate, async (before, after) => {
    try {
      const actor = await auditActor(after.guild, AuditLogEvent.ChannelUpdate, after.id)
      await registerDestructiveAction(db, after.guild, actor, 'CHANNEL_UPDATE', after.id)
      await logEvent(db, after.guild, 'guild_log_channel_id', 'Channel updated', `Channel: <#${after.id}>\nActor: ${actor ? `<@${actor.id}>` : 'Unknown'}`)
    } catch {}
  })

  client.on(Events.GuildRoleUpdate, async (before, after) => {
    try {
      const actor = await auditActor(after.guild, AuditLogEvent.RoleUpdate, after.id)
      await registerDestructiveAction(db, after.guild, actor, 'ROLE_UPDATE', after.id)
      await logEvent(db, after.guild, 'role_log_channel_id', 'Role updated', `Role: <@&${after.id}>\nActor: ${actor ? `<@${actor.id}>` : 'Unknown'}`)
    } catch {}
  })

  client.on(Events.GuildRoleCreate, async role => {
    try {
      const actor = await auditActor(role.guild, AuditLogEvent.RoleCreate, role.id)
      if (dangerousRole(role)) await registerDestructiveAction(db, role.guild, actor, 'DANGEROUS_ROLE_CREATE', role.id)
      await logEvent(db, role.guild, 'role_log_channel_id', 'Role created', `Role: <@&${role.id}>\nActor: ${actor ? `<@${actor.id}>` : 'Unknown'}`)
    } catch {}
  })

  client.on(Events.ChannelCreate, async channel => {
    try {
      const actor = await auditActor(channel.guild, AuditLogEvent.ChannelCreate, channel.id)
      await logEvent(db, channel.guild, 'guild_log_channel_id', 'Channel created', `Channel: <#${channel.id}>\nActor: ${actor ? `<@${actor.id}>` : 'Unknown'}`)
    } catch {}
  })

  client.on(Events.GuildMemberUpdate, async (before, after) => {
    try {
      const added = after.roles.cache.filter(role => !before.roles.cache.has(role.id))
      const dangerous = added.filter(dangerousRole)
      if (dangerous.size) {
        const actor = await auditActor(after.guild, AuditLogEvent.MemberRoleUpdate, after.id)
        await registerDestructiveAction(db, after.guild, actor, 'DANGEROUS_ROLE_ASSIGNMENT', after.id)
      }
    } catch {}
  })

  client.on(Events.WebhooksUpdate, async channel => {
    try {
      const actor = await auditActor(channel.guild, AuditLogEvent.WebhookCreate, null)
      if (actor) await registerDestructiveAction(db, channel.guild, actor, 'WEBHOOK_CHANGE', channel.id)
      await logEvent(db, channel.guild, 'security_log_channel_id', 'Webhook configuration changed', `Channel: <#${channel.id}>\nActor: ${actor ? `<@${actor.id}>` : 'Unknown'}`)
    } catch {}
  })
}

function securityAudit(db, guild) {
  db.ensureGuild(guild.id)
  const me = guild.members.me
  const missing = []
  const required = [
    ['View Audit Log', PermissionFlagsBits.ViewAuditLog],
    ['Manage Roles', PermissionFlagsBits.ManageRoles],
    ['Manage Channels', PermissionFlagsBits.ManageChannels],
    ['Manage Webhooks', PermissionFlagsBits.ManageWebhooks],
    ['Ban Members', PermissionFlagsBits.BanMembers],
    ['Kick Members', PermissionFlagsBits.KickMembers],
    ['Moderate Members', PermissionFlagsBits.ModerateMembers],
    ['Manage Messages', PermissionFlagsBits.ManageMessages]
  ]
  for (const [name, bit] of required) if (!me?.permissions.has(bit)) missing.push(name)

  const riskyRoles = guild.roles.cache.filter(role => role.id !== guild.id && dangerousRole(role))
  const unapprovedBots = guild.members.cache.filter(member => member.user.bot && member.id !== me?.id && !isApprovedBot(db, guild.id, member.id))
  const externalEnabled = guild.roles.cache.filter(role => role.permissions.has(PermissionFlagsBits.UseExternalApps))
  const anti = db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(guild.id))
  const raid = db.get('SELECT * FROM raid_config WHERE guild_id=?', BigInt(guild.id))

  return {
    missing,
    riskyRoles: riskyRoles.size,
    unapprovedBots: unapprovedBots.size,
    externalEnabled: externalEnabled.size,
    antiNuke: Boolean(anti && Number(anti.enabled)),
    raid: Boolean(raid && Number(raid.enabled)),
    snapshot: Boolean(getSnapshot(db, guild.id))
  }
}

module.exports = {
  attachSecurity,
  saveSnapshot,
  getSnapshot,
  hardenGuild,
  panicGuild,
  lockdownGuild,
  unlockdownGuild,
  containActor,
  securityAudit,
  trustedUser,
  isApprovedBot,
  jsonHash
}
