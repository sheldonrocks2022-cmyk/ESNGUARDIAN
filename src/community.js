'use strict'

const dgram = require('node:dgram')
const crypto = require('node:crypto')
const {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  Events,
  AuditLogEvent,
  PermissionFlagsBits
} = require('discord.js')
const { embed, logEvent, auditActor, dangerousRole } = require('./utils')

const BEDROCK_MAGIC = Buffer.from('00ffff00fefefefefdfdfdfd12345678', 'hex')
const MC_HOST = process.env.MC_HOST?.trim() || 'esn.ggwp.cc'
const MC_PORT = Number(process.env.MC_PORT || 17429)
const DISCORD_URL = 'https://discord.gg/3gxA66KZ8'

const HELP_GUIDES = {
  setup:
    '**ESN Guardian Setup**\n' +
    '1. Give Guardian View Channels, Send Messages, Manage Messages, Moderate Members, Kick Members, Ban Members, Manage Roles, Manage Channels, Manage Webhooks, Read Message History, and View Audit Log.\n' +
    '2. Put Guardian above every role it must protect.\n' +
    '3. Run `/security harden` to enable the secure baseline, external-app lock, recovery snapshot, bot approval, webhook/integration guards, credential protection, and rollback.\n' +
    '4. Set log routes with `/logs`.\n' +
    '5. Configure verification and tickets if your server uses them.\n' +
    '6. Run `/guardian audit` and keep the security score clean.\n\n' +
    'Use `/help section:<category>` for the command catalogue.',
  moderation:
    '**Moderation Commands**\n' +
    '`/warn`, `/warnings`, `/timeout`, `/untimeout`, `/kick`, `/ban`, `/unban`\n' +
    '`/clear`, `/slowmode`, `/nickname`, `/role`, `/massrole`\n' +
    '`/case`, `/history`, `/lockdown`, `/unlockdown`\n\n' +
    'Staff permission is required. Every moderation action creates a case ID and can be sent to the moderation log channel.',
  security:
    '**Security Commands**\n' +
    'Core: `/security harden`, `/security status`, `/security scan`, `/security cases`\n' +
    'AutoMod: `/security automod`, `/security thresholds`, `/security links`, `/security allow-domain`, `/security remove-domain`, `/security add-word`, `/security remove-word`, `/security words`, `/security domains`, `/security check-link`, `/security reset-automod`\n' +
    'Raid: `/security raid`, `/security raid-status`, `/security quarantine`, `/security release`, `/security member`\n' +
    'Anti-nuke: `/antinuke setup`, `/antinuke enable`, `/antinuke disable`, `/antinuke status`, `/antinuke trust`, `/antinuke untrust`\n' +
    'Advanced: `/guardian audit`, `/guardian status`, `/guardian snapshot`, `/guardian approve-bot`, `/guardian unapprove-bot`, `/guardian panic`\n\n' +
    'Use `/security harden` first, then `/guardian audit`.',
  verification:
    '**Verification Commands**\n' +
    '`/verification setup` posts the persistent VERIFY button and stores its message.\n' +
    '`/verification enable` and `/verification disable` control access.\n' +
    '`/verification status` shows roles and account-age settings.\n' +
    '`/verification reset` clears verification records for one member or the whole server.\n' +
    '`/verify` lets a member run the same checks without using the button.\n\n' +
    'Put the verified role below the bot\'s highest role; configure the unverified role with restricted channel permissions.',
  community:
    '**Community Commands**\n' +
    'Configuration: `/config`, `/welcome`, `/goodbye`, `/autorole`, `/logs`, `/panel`\n' +
    'Community: `/ticket`, `/ticket-close`, `/ticket-config`, `/suggest`\n' +
    'Staff utility: `/smpannounce`\n\n' +
    'Website information, live ESN status, SMP connection details, store information, and general ESN links stay on the ESN website instead of duplicating them inside Guardian.',
  owner:
    '**Owner Commands**\n' +
    '`/botstats`, `/backupdb`, `/backupstatus`, `/servers`, `/synccommands`, `/broadcast`, `/maintenance`, `/blacklist`, `/unblacklist`\n\n' +
    'Only the configured bot owner can use these operational commands.'
}

function discordTimestamp(ms) {
  return ms ? '<t:' + Math.floor(ms / 1000) + ':F>' : 'Unknown'
}

function formatMemberDetails(member) {
  if (!member?.guild) {
    const user = member?.user || member
    const created = user?.createdTimestamp ? discordTimestamp(user.createdTimestamp) : 'Unknown'
    return [
      'User: ' + (user?.toString?.() || user?.username || 'Unknown') + ' (' + (user?.id || 'Unknown') + ')',
      'Username: ' + (user?.username || 'Unknown'),
      'Global name: ' + (user?.globalName || 'None'),
      'Timezone: Unknown (Discord does not expose a user timezone via the API)',
      'Account created: ' + created
    ].join('\n')
  }

  const roles = member.roles.cache
    .filter(role => role.id !== member.guild.id)
    .sort((a, b) => b.position - a.position)
    .map(role => role.toString())
    .join(', ') || 'No roles'
  const flags = []
  if (member.user.bot) flags.push('Bot')
  if (member.premiumSinceTimestamp) flags.push('Server booster')
  if (member.communicationDisabledUntilTimestamp) flags.push('Timed out until ' + discordTimestamp(member.communicationDisabledUntilTimestamp))
  if (member.pending) flags.push('Pending member')
  const status = member.presence?.status ? String(member.presence.status).replace(/^./, c => c.toUpperCase()) : 'Unknown'

  return [
    'User: ' + member.toString() + ' (' + member.id + ')',
    'Username: ' + member.user.username,
    'Global name: ' + (member.user.globalName || 'None'),
    'Display name: ' + member.displayName,
    'Nickname: ' + (member.nickname || 'None'),
    'Bot account: ' + (member.user.bot ? 'Yes' : 'No'),
    'Status: ' + status,
    'Timezone: Unknown (Discord does not expose a user timezone via the API)',
    'Account created: ' + discordTimestamp(member.user.createdTimestamp),
    'Joined server: ' + discordTimestamp(member.joinedTimestamp),
    'Top role: ' + (member.roles.highest?.toString?.() || 'None'),
    'Roles: ' + roles,
    'Flags: ' + (flags.join(' | ') || 'None')
  ].join('\n').slice(0, 4096)
}

async function sendMemberNotice(channel, member, title) {
  const details = formatMemberDetails(member)
  const messageEmbed = embed(details, title).setThumbnail(member.displayAvatarURL())
  try {
    return await channel.send({ embeds: [messageEmbed], allowedMentions: { parse: [] } })
  } catch {
    return channel.send({
      content: ('**' + title + '**\n' + details).slice(0, 2000),
      allowedMentions: { parse: [] }
    }).catch(() => null)
  }
}

function actorText(actor, missingAudit = false) {
  if (actor?.id) return '<@' + actor.id + '> (' + actor.id + ')'
  return missingAudit ? 'Unknown (missing View Audit Log permission)' : 'Unknown'
}

function panelComponents() {
  const buttons = [
    ['Security', 'security'],
    ['AutoMod', 'automod'],
    ['Verification', 'verification'],
    ['Logs', 'logs'],
    ['Settings', 'settings'],
    ['Lockdown', 'lockdown'],
    ['Statistics', 'statistics'],
    ['Help', 'help']
  ]
  const rows = []
  for (let index = 0; index < buttons.length; index += 4) {
    const row = new ActionRowBuilder()
    for (const [label, action] of buttons.slice(index, index + 4)) {
      row.addComponents(
        new ButtonBuilder()
          .setLabel(label)
          .setCustomId('esn_guardian:control:' + action)
          .setStyle(action === 'lockdown' ? ButtonStyle.Danger : ButtonStyle.Secondary)
      )
    }
    rows.push(row)
  }
  return rows
}

async function postPanel(db, interaction) {
  if (!interaction.channel?.isTextBased?.()) throw new Error('This command requires a text channel.')
  const message = await interaction.channel.send({
    embeds: [embed('', 'ESN GUARDIAN CONTROL PANEL')],
    components: panelComponents(),
    allowedMentions: { parse: [] }
  })
  db.run(
    "INSERT OR REPLACE INTO panel_messages (guild_id,panel_type,channel_id,message_id) VALUES (?,'panel',?,?)",
    BigInt(interaction.guildId),
    BigInt(message.channel.id),
    BigInt(message.id)
  )
  return message
}

function raknetPing(host = MC_HOST, port = MC_PORT, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4')
    const timer = setTimeout(() => {
      socket.close()
      reject(new Error('timeout'))
    }, timeout)
    const payload = Buffer.alloc(33)
    payload[0] = 0x01
    payload.writeBigInt64BE(BigInt(Date.now()), 1)
    BEDROCK_MAGIC.copy(payload, 9)
    crypto.randomBytes(8).copy(payload, 25)

    socket.once('error', error => {
      clearTimeout(timer)
      socket.close()
      reject(error)
    })
    socket.once('message', data => {
      clearTimeout(timer)
      socket.close()
      try {
        if (data.length < 35 || data[0] !== 0x1c || !data.subarray(17, 33).equals(BEDROCK_MAGIC)) throw new Error('invalid pong')
        const length = data.readUInt16BE(33)
        const fields = data.subarray(35, 35 + length).toString('utf8').split(';')
        if (fields.length < 6 || fields[0] !== 'MCPE') throw new Error('invalid MCPE pong')
        resolve(fields)
      } catch (error) {
        reject(error)
      }
    })
    socket.send(payload, port, host)
  })
}

function smpInfo() {
  return '**Minecraft Bedrock**\nServer: **ESN SMP**\nIP: `' + MC_HOST + '`\nPort: `' + MC_PORT + '`\nDiscord: ' + DISCORD_URL
}

async function bedrockStatus() {
  try {
    const fields = await raknetPing()
    return {
      online: true,
      fields,
      text: 'Online: yes\nPlayers: ' + fields[4] + '/' + fields[5] + '\nMOTD: ' + fields[1] + '\n' + smpInfo()
    }
  } catch {
    return {
      online: false,
      fields: null,
      text: 'Online: unavailable\nThe Bedrock server did not respond to a status query.\n' + smpInfo()
    }
  }
}

async function handleButton(interaction) {
  if (!interaction.customId?.startsWith('esn_guardian:control:')) return false
  const action = interaction.customId.split(':')[2]

  if (action === 'lockdown') {
    const allowed = interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild)
    const content = allowed
      ? 'Use `/lockdown` to confirm the incident reason and lock channels.'
      : 'Staff permission is required.'
    await interaction.reply({ embeds: [embed(content)], ephemeral: true, allowedMentions: { parse: [] } })
    return true
  }

  const responses = {
    security: 'Security controls:  `/lockdown`, `/unlockdown`.',
    automod: 'AutoMod is actively monitoring flood, mention, duplicate, caps, links, and configured blocked words.',
    verification: 'Configure with `/verification setup`, then `/verification enable`.',
    logs: 'Set each route with `/logs category:<name> channel:<channel>`.',
    settings: 'Use `/config` to inspect current server settings.',
    statistics: 'Serving ' + interaction.client.guilds.cache.size + ' servers.',
    help: 'Use `/help` for setup instructions and the full command guide.'
  }
  await interaction.reply({
    embeds: [embed(responses[action] || 'Guardian control panel.')],
    ephemeral: true,
    allowedMentions: { parse: [] }
  })
  return true
}

function attachCommunity(client, db) {
  let smpOnline = null
  client.guardianCommunity = {
    postPanel: interaction => postPanel(db, interaction),
    handleButton,
    bedrockStatus,
    helpGuides: HELP_GUIDES,
    smpInfo
  }

  client.on(Events.GuildMemberAdd, async member => {
    try {
      if (client.guardianSecurity?.isRaidModeActive?.(member.guild.id) && !member.user.bot) return
      const settings = db.setting(member.guild.id)
      if (settings.autorole_id) {
        const role = member.guild.roles.cache.get(String(settings.autorole_id))
        const safe = role &&
          role.id !== member.guild.id &&
          !role.managed &&
          role.comparePositionTo(member.guild.members.me?.roles.highest) < 0 &&
          !dangerousRole(role)
        if (safe) {
          const ok = await member.roles.add(role, 'ESN Guardian autorole').then(() => true).catch(() => false)
          if (!ok) {
            await logEvent(
              db,
              member.guild,
              'system_log_channel_id',
              'Autorole failure',
              'Could not assign <@&' + role.id + '> to <@' + member.id + '>.'
            )
          }
        }
      }
      const channel = settings.welcome_channel_id
        ? member.guild.channels.cache.get(String(settings.welcome_channel_id))
        : null
      if (channel?.isTextBased()) await sendMemberNotice(channel, member, 'Member joined')
      await logEvent(db, member.guild, 'member_log_channel_id', 'Member joined', formatMemberDetails(member))
    } catch (error) {
      console.error('[Guardian] community join handler failed', error)
    }
  })

  client.on(Events.GuildMemberRemove, async member => {
    try {
      if (client.guardianSecurity?.isInternalRemoval?.(member.guild.id, member.id)) return
      const settings = db.setting(member.guild.id)
      const channel = settings.goodbye_channel_id
        ? member.guild.channels.cache.get(String(settings.goodbye_channel_id))
        : null
      if (channel?.isTextBased()) await sendMemberNotice(channel, member, 'Member left')
      await logEvent(db, member.guild, 'member_log_channel_id', 'Member left', formatMemberDetails(member))
    } catch {}
  })

  client.on(Events.GuildMemberUpdate, async (before, after) => {
    try {
      if (before.nickname !== after.nickname) {
        await logEvent(
          db,
          after.guild,
          'member_log_channel_id',
          'Member nickname changed',
          'User: <@' + after.id + '> (' + after.id + ')\n' +
          'Before: ' + (before.nickname || 'None') + '\n' +
          'After: ' + (after.nickname || 'None') + '\n' +
          'Timezone: Unknown (Discord does not expose a user timezone via the API)'
        )
      }
      const added = after.roles.cache.filter(role => !before.roles.cache.has(role.id))
      const removed = before.roles.cache.filter(role => !after.roles.cache.has(role.id))
      if (added.size || removed.size) {
        const actor = await auditActor(after.guild, AuditLogEvent.MemberRoleUpdate, after.id)
        await logEvent(
          db,
          after.guild,
          'member_log_channel_id',
          'Member roles updated',
          'User: <@' + after.id + '> (' + after.id + ')\n' +
          'Added: ' + (added.map(role => role.toString()).join(', ') || 'None') + '\n' +
          'Removed: ' + (removed.map(role => role.toString()).join(', ') || 'None') + '\n' +
          'Updated by: ' + actorText(actor)
        )
      }
      if (before.communicationDisabledUntilTimestamp !== after.communicationDisabledUntilTimestamp) {
        await logEvent(
          db,
          after.guild,
          'member_log_channel_id',
          'Member timeout updated',
          'User: <@' + after.id + '> (' + after.id + ')\n' +
          'Before: ' + (before.communicationDisabledUntilTimestamp ? new Date(before.communicationDisabledUntilTimestamp).toISOString() : 'None') + '\n' +
          'After: ' + (after.communicationDisabledUntilTimestamp ? new Date(after.communicationDisabledUntilTimestamp).toISOString() : 'None')
        )
      }
    } catch {}
  })

  client.on(Events.UserUpdate, async (before, after) => {
    if (before.username === after.username && before.globalName === after.globalName) return
    for (const guild of client.guilds.cache.values()) {
      const member = guild.members.cache.get(after.id)
      if (!member) continue
      await logEvent(
        db,
        guild,
        'member_log_channel_id',
        'User profile updated',
        'User: <@' + member.id + '> (' + member.id + ')\n' +
        'Username: ' + before.username + ' -> ' + after.username + '\n' +
        'Global name: ' + (before.globalName || 'None') + ' -> ' + (after.globalName || 'None') + '\n' +
        'Timezone: Unknown (Discord does not expose a user timezone via the API)'
      )
    }
  })

  client.on(Events.VoiceStateUpdate, async (before, after) => {
    if (
      before.channelId === after.channelId &&
      before.serverMute === after.serverMute &&
      before.serverDeaf === after.serverDeaf &&
      before.selfMute === after.selfMute &&
      before.selfDeaf === after.selfDeaf
    ) return
    const guild = after.guild || before.guild
    const userId = after.id || before.id
    await logEvent(
      db,
      guild,
      'voice_log_channel_id',
      'Voice state updated',
      'User: <@' + userId + '> (' + userId + ')\n' +
      'Before: ' + (before.channelId ? '<#' + before.channelId + '>' : 'No voice channel') + '\n' +
      'After: ' + (after.channelId ? '<#' + after.channelId + '>' : 'No voice channel') + '\n' +
      'Mute: ' + before.serverMute + ' -> ' + after.serverMute + '\n' +
      'Deaf: ' + before.serverDeaf + ' -> ' + after.serverDeaf + '\n' +
      'Self mute: ' + before.selfMute + ' -> ' + after.selfMute + '\n' +
      'Self deaf: ' + before.selfDeaf + ' -> ' + after.selfDeaf + '\n' +
      'Timezone: Unknown (Discord does not expose a user timezone via the API)'
    )
  })

  client.on(Events.ChannelCreate, async channel => {
    if (!channel.guild) return
    const actor = await auditActor(channel.guild, AuditLogEvent.ChannelCreate, channel.id)
    await logEvent(
      db,
      channel.guild,
      'guild_log_channel_id',
      'Channel created',
      'Channel: <#' + channel.id + '>\nType: ' + channel.type + '\nCreated by: ' + actorText(actor)
    )
  })

  client.on(Events.ChannelDelete, async channel => {
    if (!channel.guild) return
    const actor = await auditActor(channel.guild, AuditLogEvent.ChannelDelete, channel.id)
    await logEvent(
      db,
      channel.guild,
      'guild_log_channel_id',
      'Channel deleted',
      'Channel: #' + channel.name + '\nType: ' + channel.type + '\nDeleted by: ' + actorText(actor)
    )
  })

  client.on(Events.ChannelUpdate, async (before, after) => {
    if (!after.guild || (before.name === after.name && before.rawPosition === after.rawPosition)) return
    const actor = await auditActor(after.guild, AuditLogEvent.ChannelUpdate, after.id)
    await logEvent(
      db,
      after.guild,
      'guild_log_channel_id',
      'Channel updated',
      'Channel: #' + before.name + ' -> #' + after.name + '\nType: ' + after.type + '\nPosition: ' + before.rawPosition + ' -> ' + after.rawPosition + '\nUpdated by: ' + actorText(actor)
    )
  })

  client.on(Events.GuildRoleCreate, async role => {
    const actor = await auditActor(role.guild, AuditLogEvent.RoleCreate, role.id)
    await logEvent(
      db,
      role.guild,
      'role_log_channel_id',
      'Role created',
      'Role: <@&' + role.id + '>\nName: ' + role.name + '\nColor: ' + role.hexColor + '\nPermissions: ' + role.permissions.bitfield + '\nCreated by: ' + actorText(actor)
    )
  })

  client.on(Events.GuildRoleDelete, async role => {
    const actor = await auditActor(role.guild, AuditLogEvent.RoleDelete, role.id)
    await logEvent(
      db,
      role.guild,
      'role_log_channel_id',
      'Role deleted',
      'Role: ' + role.name + '\nColor: ' + role.hexColor + '\nPermissions: ' + role.permissions.bitfield + '\nDeleted by: ' + actorText(actor)
    )
  })

  client.on(Events.GuildRoleUpdate, async (before, after) => {
    if (before.name === after.name && before.color === after.color && before.permissions.bitfield === after.permissions.bitfield) return
    const actor = await auditActor(after.guild, AuditLogEvent.RoleUpdate, after.id)
    await logEvent(
      db,
      after.guild,
      'role_log_channel_id',
      'Role updated',
      'Role: <@&' + after.id + '>\nBefore: ' + before.name + ' | ' + before.hexColor + ' | ' + before.permissions.bitfield +
      '\nAfter: ' + after.name + ' | ' + after.hexColor + ' | ' + after.permissions.bitfield +
      '\nUpdated by: ' + actorText(actor)
    )
  })

  client.on(Events.InviteCreate, async invite => {
    if (!invite.guild) return
    const creator = invite.inviter || invite.guild.owner || null
    await logEvent(
      db,
      invite.guild,
      'invite_log_channel_id',
      'Invite created',
      'Code: ' + invite.code +
      '\nChannel: ' + (invite.channelId ? '<#' + invite.channelId + '>' : 'Unknown') +
      '\nCreated by: ' + (creator ? '<@' + creator.id + '>' : 'Unknown') +
      '\nCreator ID: ' + (creator?.id || 'Unknown') +
      '\nMax age: ' + invite.maxAge + 's' +
      '\nMax uses: ' + invite.maxUses +
      '\nTemporary: ' + invite.temporary
    )
  })

  client.on(Events.InviteDelete, async invite => {
    if (!invite.guild) return
    await logEvent(
      db,
      invite.guild,
      'invite_log_channel_id',
      'Invite deleted',
      'Code: ' + invite.code +
      '\nChannel: ' + (invite.channelId ? '<#' + invite.channelId + '>' : 'Unknown') +
      '\nTemporary: ' + invite.temporary +
      '\nUses: ' + invite.uses
    )
  })

  client.on(Events.MessageDelete, async message => {
    if (!message.guild || !message.author || message.author.bot) return
    const attachments = message.attachments?.map(item => item.url).join(', ') || 'None'
    await logEvent(
      db,
      message.guild,
      'message_log_channel_id',
      'Message deleted',
      'User: <@' + message.author.id + '> (' + message.author.id + ')\n' +
      'Channel: <#' + message.channelId + '>\n' +
      'Message ID: ' + message.id + '\n' +
      'Content: ' + (message.content || '[no text]') + '\n' +
      'Attachments: ' + attachments + '\n' +
      'Jump URL: ' + (message.url || 'Unavailable')
    )
  })

  client.on(Events.MessageBulkDelete, async messages => {
    const first = messages.first()
    if (!first?.guild) return
    const authors = [...new Set(messages.filter(message => message.author && !message.author.bot).map(message => message.author.id))].sort()
    await logEvent(
      db,
      first.guild,
      'message_log_channel_id',
      'Bulk messages deleted',
      'Count: ' + messages.size + '\nChannel: <#' + first.channelId + '>\nAuthor IDs: ' + (authors.join(', ') || 'No non-bot authors')
    )
  })

  client.on(Events.MessageUpdate, async (before, after) => {
    if (!after.guild || !after.author || after.author.bot || before.content === after.content) return
    await logEvent(
      db,
      after.guild,
      'message_log_channel_id',
      'Message edited',
      'User: <@' + after.author.id + '> (' + after.author.id + ')\n' +
      'Channel: <#' + after.channelId + '>\n' +
      'Message ID: ' + after.id + '\n' +
      'Before: ' + (before.content || '[no text]') + '\n' +
      'After: ' + (after.content || '[no text]') + '\n' +
      'Jump URL: ' + (after.url || 'Unavailable')
    )
  })

  const monitor = setInterval(async () => {
    const status = await bedrockStatus()
    if (smpOnline === null) {
      smpOnline = status.online
      console.log('[Guardian] Initial ESN SMP status: ' + (status.online ? 'online' : 'unavailable'))
      return
    }
    if (smpOnline === status.online) return

    smpOnline = status.online
    let delivered = 0
    const message = status.online && status.fields
      ? 'ESN SMP is online. Players: ' + status.fields[4] + '/' + status.fields[5] + '\nMOTD: ' + status.fields[1] + '\n' + smpInfo()
      : 'ESN SMP is currently unavailable. The server did not respond to a status query.\n' + smpInfo()

    for (const userId of db.statusSubscriberIds('smp')) {
      const user = await client.users.fetch(String(userId)).catch(() => null)
      if (!user) continue
      const ok = await user.send({ content: message, allowedMentions: { parse: [] } }).then(() => true).catch(() => false)
      if (ok) delivered++
    }
    console.log('[Guardian] ESN SMP status changed to ' + (status.online ? 'online' : 'unavailable') + '; notified ' + delivered + ' subscriber(s)')
  }, 180000)
  monitor.unref?.()
}

module.exports = {
  attachCommunity,
  formatMemberDetails,
  bedrockStatus,
  postPanel,
  handleButton,
  HELP_GUIDES,
  smpInfo
}
