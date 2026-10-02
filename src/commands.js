'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs')
const {
  ChannelType,
  PermissionFlagsBits,
  SlashCommandBuilder
} = require('discord.js')
const {
  embed,
  respond,
  isStaff,
  isGuildOwner,
  isBotOwner,
  memberManageable,
  safeRole,
  logEvent,
  normalizeDomain,
  channelMention,
  roleMention,
  userMention
} = require('./utils')
const {
  saveSnapshot,
  hardenGuild,
  panicGuild,
  lockdownGuild,
  unlockdownGuild,
  securityAudit,
  trustedUser,
  isApprovedBot,
  jsonHash
} = require('./security')

const LOG_CHOICES = [
  ['Moderation', 'moderation'],
  ['Security', 'security'],
  ['Member', 'member'],
  ['Message', 'message'],
  ['Verification', 'verification'],
  ['System', 'system'],
  ['Guild', 'guild'],
  ['Voice', 'voice'],
  ['Invite', 'invite'],
  ['Role', 'role'],
  ['Command', 'command']
]

const LOG_FIELDS = {
  moderation: 'moderation_log_channel_id',
  security: 'security_log_channel_id',
  member: 'member_log_channel_id',
  message: 'message_log_channel_id',
  verification: 'verification_log_channel_id',
  system: 'system_log_channel_id',
  guild: 'guild_log_channel_id',
  voice: 'voice_log_channel_id',
  invite: 'invite_log_channel_id',
  role: 'role_log_channel_id',
  command: 'command_log_channel_id'
}

function addReason(builder, required = false) {
  return builder.addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(required).setMaxLength(1000))
}

function definitions() {
  const defs = []

  defs.push(addReason(
    new SlashCommandBuilder().setName('warn').setDescription('Issue a formal warning.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)),
    true
  ))

  defs.push(new SlashCommandBuilder().setName('warnings').setDescription('List active warnings for a member.')
    .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)))

  defs.push(addReason(
    new SlashCommandBuilder().setName('timeout').setDescription('Timeout a member.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
      .addIntegerOption(o => o.setName('minutes').setDescription('Minutes').setRequired(true).setMinValue(1).setMaxValue(40320)),
    true
  ))

  defs.push(addReason(
    new SlashCommandBuilder().setName('untimeout').setDescription('Remove a member timeout.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)),
    false
  ))

  defs.push(addReason(
    new SlashCommandBuilder().setName('kick').setDescription('Kick a member.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)),
    true
  ))

  defs.push(
    new SlashCommandBuilder().setName('ban').setDescription('Ban a member.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(true).setMaxLength(1000))
      .addIntegerOption(o => o.setName('delete_message_days').setDescription('Delete recent message days').setRequired(false).setMinValue(0).setMaxValue(7))
  )

  defs.push(
    new SlashCommandBuilder().setName('unban').setDescription('Unban a user by ID.')
      .addStringOption(o => o.setName('user_id').setDescription('Discord user ID').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false).setMaxLength(1000))
  )

  defs.push(new SlashCommandBuilder().setName('clear').setDescription('Delete recent messages.')
    .addIntegerOption(o => o.setName('amount').setDescription('Messages').setRequired(true).setMinValue(1).setMaxValue(100)))

  defs.push(new SlashCommandBuilder().setName('slowmode').setDescription('Set channel slowmode in seconds.')
    .addIntegerOption(o => o.setName('seconds').setDescription('Seconds').setRequired(true).setMinValue(0).setMaxValue(21600)))

  defs.push(new SlashCommandBuilder().setName('case').setDescription('Show a moderation case.')
    .addIntegerOption(o => o.setName('case_id').setDescription('Case ID').setRequired(true).setMinValue(1)))

  defs.push(new SlashCommandBuilder().setName('history').setDescription('Show moderation history for a member.')
    .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)))

  defs.push(new SlashCommandBuilder().setName('nickname').setDescription('Change a member nickname.')
    .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
    .addStringOption(o => o.setName('nickname').setDescription('New nickname; omit to clear').setRequired(false).setMaxLength(32))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false).setMaxLength(1000)))

  defs.push(new SlashCommandBuilder().setName('role').setDescription('Add or remove a role from a member.')
    .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
    .addRoleOption(o => o.setName('role').setDescription('Role').setRequired(true))
    .addBooleanOption(o => o.setName('remove').setDescription('Remove instead of add').setRequired(false))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false).setMaxLength(1000)))

  defs.push(new SlashCommandBuilder().setName('massrole').setDescription('Add or remove a role for eligible members.')
    .addRoleOption(o => o.setName('role').setDescription('Role').setRequired(true))
    .addBooleanOption(o => o.setName('remove').setDescription('Remove instead of add').setRequired(false))
    .addBooleanOption(o => o.setName('include_bots').setDescription('Include bots').setRequired(false)))

  defs.push(new SlashCommandBuilder().setName('lock').setDescription('Lock the current channel for @everyone.')
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('unlock').setDescription('Unlock the current channel for @everyone.')
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('lockdown').setDescription('Lock all text channels during an incident.')
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('unlockdown').setDescription('Restore channels after a lockdown.')
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))

  defs.push(new SlashCommandBuilder().setName('help').setDescription('Show the ESN Guardian setup and command guide.')
    .addStringOption(o => o.setName('section').setDescription('Guide section').setRequired(false)
      .addChoices(
        { name: 'Security', value: 'security' },
        { name: 'Moderation', value: 'moderation' },
        { name: 'Verification', value: 'verification' },
        { name: 'Tickets', value: 'tickets' },
        { name: 'Owner', value: 'owner' }
      )))

  defs.push(new SlashCommandBuilder().setName('panel').setDescription('Post the ESN Guardian staff control panel.'))
  defs.push(new SlashCommandBuilder().setName('config').setDescription('Show configured server settings.'))
  defs.push(new SlashCommandBuilder().setName('welcome').setDescription('Set the channel for automatic join notices.')
    .addChannelOption(o => o.setName('channel').setDescription('Welcome channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('goodbye').setDescription('Set the channel for automatic leave notices.')
    .addChannelOption(o => o.setName('channel').setDescription('Goodbye channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('autorole').setDescription('Configure the automatic member role.')
    .addRoleOption(o => o.setName('role').setDescription('Role; omit to disable').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('logs').setDescription('Set a detailed event log channel.')
    .addStringOption(o => o.setName('category').setDescription('Log category').setRequired(true).addChoices(...LOG_CHOICES.map(([name, value]) => ({ name, value }))))
    .addChannelOption(o => o.setName('channel').setDescription('Log channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('suggest').setDescription('Submit a suggestion.')
    .addStringOption(o => o.setName('suggestion').setDescription('Suggestion').setRequired(true).setMaxLength(1800)))
  defs.push(new SlashCommandBuilder().setName('smpannounce').setDescription('Send an SMP announcement with cooldown.')
    .addChannelOption(o => o.setName('channel').setDescription('Announcement channel').setRequired(true).addChannelTypes(ChannelType.GuildText, ChannelType.GuildAnnouncement))
    .addStringOption(o => o.setName('message').setDescription('Announcement').setRequired(true).setMaxLength(2000)))

  const verification = new SlashCommandBuilder().setName('verification').setDescription('Configure member verification.')
    .addSubcommand(s => s.setName('setup').setDescription('Post or replace the verification message.')
      .addChannelOption(o => o.setName('channel').setDescription('Verification channel').setRequired(true).addChannelTypes(ChannelType.GuildText))
      .addRoleOption(o => o.setName('verified_role').setDescription('Verified role').setRequired(true))
      .addRoleOption(o => o.setName('unverified_role').setDescription('Unverified role').setRequired(false))
      .addIntegerOption(o => o.setName('minimum_account_age_days').setDescription('Minimum account age').setRequired(false).setMinValue(0).setMaxValue(365)))
    .addSubcommand(s => s.setName('enable').setDescription('Enable verification.'))
    .addSubcommand(s => s.setName('disable').setDescription('Disable verification.'))
    .addSubcommand(s => s.setName('reset').setDescription('Clear verification records.')
      .addUserOption(o => o.setName('member').setDescription('One member; omit for all').setRequired(false)))
    .addSubcommand(s => s.setName('status').setDescription('Show verification configuration.'))
  defs.push(verification)
  defs.push(new SlashCommandBuilder().setName('verify').setDescription('Verify yourself using server verification rules.'))

  defs.push(new SlashCommandBuilder().setName('ticket-config').setDescription('Choose the role that can access new support tickets.')
    .addRoleOption(o => o.setName('support_role').setDescription('Support role').setRequired(true)))
  defs.push(new SlashCommandBuilder().setName('ticket').setDescription('Open a private support ticket.')
    .addStringOption(o => o.setName('subject').setDescription('Ticket subject').setRequired(true).setMaxLength(200)))
  defs.push(new SlashCommandBuilder().setName('ticket-close').setDescription('Close this Guardian ticket.'))

  const guardian = new SlashCommandBuilder().setName('guardian').setDescription('Emergency recovery and advanced Guardian protection.')
    .addSubcommand(s => s.setName('snapshot').setDescription('Save a trusted recovery snapshot.'))
    .addSubcommand(s => s.setName('approve-bot').setDescription('Approve a bot ID before it joins.')
      .addStringOption(o => o.setName('bot_id').setDescription('Bot/application ID').setRequired(true)))
    .addSubcommand(s => s.setName('unapprove-bot').setDescription('Remove a bot approval.')
      .addStringOption(o => o.setName('bot_id').setDescription('Bot/application ID').setRequired(true)))
    .addSubcommand(s => s.setName('panic').setDescription('Enable or release maximum containment.')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enable PANIC').setRequired(false)))
    .addSubcommand(s => s.setName('audit').setDescription('Run full security audit.'))
    .addSubcommand(s => s.setName('status').setDescription('Show advanced protection status.'))
  defs.push(guardian)

  const security = new SlashCommandBuilder().setName('security').setDescription('Configure advanced server security.')
    .addSubcommand(s => s.setName('harden').setDescription('Apply the recommended secure baseline.'))
    .addSubcommand(s => s.setName('status').setDescription('Show current AutoMod and anti-nuke policy.'))
    .addSubcommand(s => s.setName('scan').setDescription('Check permissions and role hierarchy.'))
    .addSubcommand(s => s.setName('cases').setDescription('Show recent security cases.')
      .addIntegerOption(o => o.setName('limit').setDescription('Results').setRequired(false).setMinValue(1).setMaxValue(25)))
    .addSubcommand(s => s.setName('automod').setDescription('Enable or disable message security.')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enabled').setRequired(true)))
    .addSubcommand(s => s.setName('thresholds').setDescription('Set flood, mention, and caps thresholds.')
      .addIntegerOption(o => o.setName('flood_limit').setDescription('Flood message limit').setRequired(true).setMinValue(3).setMaxValue(20))
      .addIntegerOption(o => o.setName('flood_window_seconds').setDescription('Flood window seconds').setRequired(true).setMinValue(5).setMaxValue(120))
      .addIntegerOption(o => o.setName('max_mentions').setDescription('Maximum mentions').setRequired(true).setMinValue(2).setMaxValue(30))
      .addIntegerOption(o => o.setName('caps_percentage').setDescription('Caps threshold percent').setRequired(true).setMinValue(50).setMaxValue(100)))
    .addSubcommand(s => s.setName('links').setDescription('Configure invite blocking and strict links.')
      .addBooleanOption(o => o.setName('block_invites').setDescription('Block Discord invites').setRequired(true))
      .addBooleanOption(o => o.setName('strict_links').setDescription('Only allow approved domains').setRequired(true)))
    .addSubcommand(s => s.setName('allow-domain').setDescription('Allow a domain in strict-link mode.')
      .addStringOption(o => o.setName('domain').setDescription('Domain').setRequired(true)))
    .addSubcommand(s => s.setName('remove-domain').setDescription('Remove an allowed domain.')
      .addStringOption(o => o.setName('domain').setDescription('Domain').setRequired(true)))
    .addSubcommand(s => s.setName('add-word').setDescription('Add a blocked word or phrase.')
      .addStringOption(o => o.setName('word').setDescription('Word or phrase').setRequired(true)))
    .addSubcommand(s => s.setName('remove-word').setDescription('Remove a blocked word or phrase.')
      .addStringOption(o => o.setName('word').setDescription('Word or phrase').setRequired(true)))
    .addSubcommand(s => s.setName('words').setDescription('List blocked words and phrases.'))
    .addSubcommand(s => s.setName('domains').setDescription('List allowed domains.'))
    .addSubcommand(s => s.setName('trusted').setDescription('List anti-nuke trusted users.'))
    .addSubcommand(s => s.setName('check-link').setDescription('Check whether a URL is allowed.')
      .addStringOption(o => o.setName('url').setDescription('URL').setRequired(true)))
    .addSubcommand(s => s.setName('reset-automod').setDescription('Restore secure AutoMod defaults.'))
    .addSubcommand(s => s.setName('raid').setDescription('Configure join-rate raid detection.')
      .addBooleanOption(o => o.setName('enabled').setDescription('Enabled').setRequired(true))
      .addIntegerOption(o => o.setName('join_limit').setDescription('Join limit').setRequired(true).setMinValue(3).setMaxValue(100))
      .addIntegerOption(o => o.setName('join_window_seconds').setDescription('Window seconds').setRequired(true).setMinValue(10).setMaxValue(3600))
      .addIntegerOption(o => o.setName('minimum_account_age_days').setDescription('Minimum account age').setRequired(true).setMinValue(0).setMaxValue(365))
      .addRoleOption(o => o.setName('quarantine_role').setDescription('Quarantine role').setRequired(false)))
    .addSubcommand(s => s.setName('raid-status').setDescription('Show live raid configuration.'))
    .addSubcommand(s => s.setName('quarantine').setDescription('Assign the quarantine role to a member.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))
    .addSubcommand(s => s.setName('release').setDescription('Remove the quarantine role from a member.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true))
      .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(false)))
    .addSubcommand(s => s.setName('member').setDescription('Show a member security history.')
      .addUserOption(o => o.setName('member').setDescription('Member').setRequired(true)))
  defs.push(security)

  const antinuke = new SlashCommandBuilder().setName('antinuke').setDescription('Configure protection against destructive actions.')
    .addSubcommand(s => s.setName('setup').setDescription('Enable anti-nuke with threshold.')
      .addIntegerOption(o => o.setName('action_limit').setDescription('Destructive action limit').setRequired(false).setMinValue(2).setMaxValue(10))
      .addIntegerOption(o => o.setName('window_seconds').setDescription('Window seconds').setRequired(false).setMinValue(5).setMaxValue(120)))
    .addSubcommand(s => s.setName('enable').setDescription('Enable anti-nuke.'))
    .addSubcommand(s => s.setName('disable').setDescription('Disable anti-nuke.'))
    .addSubcommand(s => s.setName('status').setDescription('Show anti-nuke configuration.'))
    .addSubcommand(s => s.setName('trust').setDescription('Trust a recovery administrator.')
      .addUserOption(o => o.setName('user').setDescription('User').setRequired(true)))
    .addSubcommand(s => s.setName('untrust').setDescription('Remove anti-nuke trust.')
      .addUserOption(o => o.setName('user').setDescription('User').setRequired(true)))
  defs.push(antinuke)

  const overwatch = new SlashCommandBuilder().setName('overwatch').setDescription('Guardian defense posture and integrity.')
    .addSubcommand(s => s.setName('status').setDescription('Show full live defense posture.'))
    .addSubcommand(s => s.setName('integrity').setDescription('Verify policy baseline integrity.'))
    .addSubcommand(s => s.setName('incidents').setDescription('Show recent incident sessions.'))
    .addSubcommand(s => s.setName('seal').setDescription('Seal current security configuration.'))
    .addSubcommand(s => s.setName('backup').setDescription('Create immediate verified database backup.'))
  defs.push(overwatch)

  const resilience = new SlashCommandBuilder().setName('resilience').setDescription('Guardian recovery readiness.')
    .addSubcommand(s => s.setName('status').setDescription('Show recovery readiness and self-health.'))
    .addSubcommand(s => s.setName('drill').setDescription('Run a non-destructive readiness drill.'))
    .addSubcommand(s => s.setName('recovery-plan').setDescription('Generate a recovery readiness plan.'))
  defs.push(resilience)

  const sentinel = new SlashCommandBuilder().setName('sentinel').setDescription('Guardian behavioral threat intelligence.')
    .addSubcommand(s => s.setName('status').setDescription('Show Sentinel live status.'))
    .addSubcommand(s => s.setName('signals').setDescription('Show recent anomaly signals.'))
    .addSubcommand(s => s.setName('subject').setDescription('Show behavioral profile for a subject ID.')
      .addStringOption(o => o.setName('subject_id').setDescription('Subject ID').setRequired(true)))
    .addSubcommand(s => s.setName('explain').setDescription('Explain why a signal received its score.')
      .addIntegerOption(o => o.setName('signal_id').setDescription('Signal ID').setRequired(true).setMinValue(1)))
  defs.push(sentinel)

  defs.push(new SlashCommandBuilder().setName('botstats').setDescription('Show bot-wide operational statistics.'))
  defs.push(new SlashCommandBuilder().setName('backupdb').setDescription('Create a verified Guardian database backup.'))
  defs.push(new SlashCommandBuilder().setName('backupstatus').setDescription('Show database backup status.'))
  defs.push(new SlashCommandBuilder().setName('servers').setDescription('List servers currently served by the bot.'))
  defs.push(new SlashCommandBuilder().setName('synccommands').setDescription('Refresh slash commands.')
    .addStringOption(o => o.setName('guild_id').setDescription('One guild ID; omit for all connected servers').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('globalban').setDescription('Ban a user from every served server.')
    .addStringOption(o => o.setName('user_id').setDescription('Discord user ID').setRequired(true))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(true).setMaxLength(1000)))
  defs.push(new SlashCommandBuilder().setName('globalunban').setDescription('Remove a user from the global-ban list.')
    .addStringOption(o => o.setName('user_id').setDescription('Discord user ID').setRequired(true)))
  defs.push(new SlashCommandBuilder().setName('broadcast').setDescription('Send an announcement to configured system log channels.')
    .addStringOption(o => o.setName('message').setDescription('Message').setRequired(true).setMaxLength(1800)))
  defs.push(new SlashCommandBuilder().setName('maintenance').setDescription('Enable or disable maintenance mode.')
    .addBooleanOption(o => o.setName('enabled').setDescription('Enabled').setRequired(true)))
  defs.push(new SlashCommandBuilder().setName('blacklist').setDescription('Block a server from using Guardian.')
    .addStringOption(o => o.setName('guild_id').setDescription('Server ID').setRequired(true))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(true).setMaxLength(1000)))
  defs.push(new SlashCommandBuilder().setName('unblacklist').setDescription('Remove a server from Guardian blacklist.')
    .addStringOption(o => o.setName('guild_id').setDescription('Server ID').setRequired(true)))

  return defs
}

function asJson() {
  return definitions().map(d => d.toJSON())
}

async function registerGuild(guild) {
  return guild.commands.set(asJson())
}

async function requireGuild(interaction, db, settings) {
  if (!interaction.inGuild()) {
    await respond(interaction, 'This command can only be used in a server.')
    return false
  }
  if (db.isGuildBlacklisted(interaction.guildId) && !isBotOwner(interaction, settings)) {
    await respond(interaction, 'ESN Guardian is unavailable in this server.')
    return false
  }
  if (db.stateEnabled('maintenance') && !isBotOwner(interaction, settings)) {
    await respond(interaction, 'ESN Guardian is currently in maintenance mode.')
    return false
  }
  db.ensureGuild(interaction.guildId)
  return true
}

async function requireStaff(interaction, db, settings) {
  if (!await requireGuild(interaction, db, settings)) return false
  if (!isStaff(interaction)) {
    await respond(interaction, 'You need Manage Server permission to use this command.', true, 'Access denied')
    return false
  }
  return true
}

async function requireBotOwner(interaction, settings) {
  if (!isBotOwner(interaction, settings)) {
    await respond(interaction, 'This command is restricted to the ESN Guardian bot owner.', true, 'Access denied')
    return false
  }
  return true
}

async function moderationCase(db, interaction, target, action, reason) {
  return db.createCase(interaction.guildId, target?.id || null, interaction.user.id, action, reason, interaction.channelId)
}

async function logCase(db, interaction, caseId, target, action, reason) {
  await logEvent(db, interaction.guild, 'moderation_log_channel_id', `${action} | Case #${caseId}`, `Target: ${target ? `<@${target.id}>` : 'N/A'}\nModerator: <@${interaction.user.id}>\nReason: ${reason}`)
  if (target?.send) {
    await target.send({ content: `Moderation notice from **${interaction.guild.name}** (${interaction.guild.id})\nAction: ${action}\nCase #${caseId}\nReason: ${reason}` }).catch(() => {})
  }
}

async function doVerify(interaction, db) {
  if (!await requireGuild(interaction, db, interaction.client.guardianSettings)) return
  const cfg = db.get('SELECT * FROM verification_config WHERE guild_id=?', BigInt(interaction.guildId))
  if (!cfg || !Number(cfg.enabled)) return respond(interaction, 'Verification is not enabled here.')
  const existing = db.get('SELECT 1 AS ok FROM verified_members WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(interaction.user.id))
  if (existing) return respond(interaction, 'You are already verified.')

  const minDays = Number(cfg.min_account_age_days || 0)
  const accountAgeDays = (Date.now() - interaction.user.createdTimestamp) / 86400000
  if (accountAgeDays < minDays) return respond(interaction, `Your account must be at least ${minDays} days old.`)

  const member = await interaction.guild.members.fetch(interaction.user.id)
  const verifiedRole = cfg.verified_role_id ? interaction.guild.roles.cache.get(String(cfg.verified_role_id)) : null
  const unverifiedRole = cfg.unverified_role_id ? interaction.guild.roles.cache.get(String(cfg.unverified_role_id)) : null
  if (!verifiedRole || !safeRole(interaction.guild, interaction.guild.members.me, verifiedRole)) return respond(interaction, 'Verification is incomplete: staff need to configure a manageable verified role.')

  await member.roles.add(verifiedRole, 'ESN Guardian verification').catch(() => null)
  if (unverifiedRole && member.roles.cache.has(unverifiedRole.id) && unverifiedRole.editable) {
    await member.roles.remove(unverifiedRole, 'ESN Guardian verification').catch(() => {})
  }
  db.run('INSERT OR IGNORE INTO verified_members (guild_id,user_id) VALUES (?,?)', BigInt(interaction.guildId), BigInt(member.id))
  const caseId = db.createCase(interaction.guildId, member.id, interaction.client.user?.id, 'VERIFY', 'Member verified', interaction.channelId)
  await logEvent(db, interaction.guild, 'verification_log_channel_id', `Verified | Case #${caseId}`, `Member: <@${member.id}> (${member.id})`)
  return respond(interaction, 'You are verified. Access has been updated.')
}

async function handleButton(interaction, db) {
  if (interaction.customId === 'esn_guardian:verify') return doVerify(interaction, db)
}

async function handleCommand(interaction, db, settings) {
  const name = interaction.commandName
  const client = interaction.client

  try {
    if (['botstats','backupdb','backupstatus','servers','synccommands','globalban','globalunban','broadcast','maintenance','blacklist','unblacklist'].includes(name)) {
      if (!await requireBotOwner(interaction, settings)) return

      if (name === 'botstats') {
        const uptime = Math.floor(process.uptime())
        return respond(interaction, `Servers: ${client.guilds.cache.size}\nUsers cached: ${client.users.cache.size}\nUptime: ${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m\nNode: ${process.version}\nMemory RSS: ${Math.round(process.memoryUsage().rss / 1024 / 1024)} MB`)
      }
      if (name === 'backupdb') {
        const file = db.backup('owner')
        return respond(interaction, file ? `Verified database backup created: \`${file}\`` : 'Database backup could not be created.')
      }
      if (name === 'backupstatus') {
        const info = db.backupInfo()
        return respond(interaction, `Database: \`${info.database}\`\nBackups: ${info.count}\nLatest: ${info.latest || 'none'}\nDirectory: \`${info.directory}\``)
      }
      if (name === 'servers') {
        const text = client.guilds.cache.map(g => `${g.name} — ${g.id} — ${g.memberCount} members`).join('\n') || 'No servers.'
        return respond(interaction, text)
      }
      if (name === 'synccommands') {
        await interaction.deferReply({ ephemeral: true })
        const guildId = interaction.options.getString('guild_id')
        if (guildId) {
          const guild = await client.guilds.fetch(guildId).catch(() => null)
          if (!guild) return interaction.editReply('I am not in that server.')
          const commands = await registerGuild(guild)
          return interaction.editReply(`Synced ${commands.size} commands in **${guild.name}**.`)
        }
        let count = 0
        for (const guild of client.guilds.cache.values()) {
          await registerGuild(guild).then(() => count++).catch(() => {})
        }
        return interaction.editReply(`Synced commands in ${count} server(s).`)
      }
      if (name === 'globalban') {
        const userId = interaction.options.getString('user_id', true)
        const reason = interaction.options.getString('reason', true)
        if (!/^\d{15,22}$/.test(userId)) return respond(interaction, 'Provide a valid Discord user ID.')
        db.run('INSERT INTO global_bans (user_id,reason,banned_by_id) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason,banned_by_id=excluded.banned_by_id', BigInt(userId), reason, BigInt(interaction.user.id))
        let banned = 0
        for (const guild of client.guilds.cache.values()) {
          await guild.members.ban(userId, { reason: `ESN Guardian global ban: ${reason}` }).then(() => banned++).catch(() => {})
        }
        return respond(interaction, `Global ban stored. Ban request succeeded in ${banned} server(s).`)
      }
      if (name === 'globalunban') {
        const userId = interaction.options.getString('user_id', true)
        if (!/^\d{15,22}$/.test(userId)) return respond(interaction, 'Provide a valid Discord user ID.')
        db.run('DELETE FROM global_bans WHERE user_id=?', BigInt(userId))
        return respond(interaction, `Removed <@${userId}> from Guardian's global-ban list.`)
      }
      if (name === 'broadcast') {
        const message = interaction.options.getString('message', true)
        let sent = 0
        for (const guild of client.guilds.cache.values()) {
          const cfg = db.setting(guild.id)
          const channel = cfg.system_log_channel_id ? guild.channels.cache.get(String(cfg.system_log_channel_id)) : null
          if (channel?.isTextBased()) await channel.send({ embeds: [embed(message, 'ESN Guardian Broadcast')] }).then(() => sent++).catch(() => {})
        }
        return respond(interaction, `Broadcast sent to ${sent} configured server(s).`)
      }
      if (name === 'maintenance') {
        const enabled = interaction.options.getBoolean('enabled', true)
        db.setStateEnabled('maintenance', enabled)
        return respond(interaction, `Maintenance mode ${enabled ? 'enabled' : 'disabled'}.`)
      }
      if (name === 'blacklist') {
        const guildId = interaction.options.getString('guild_id', true)
        const reason = interaction.options.getString('reason', true)
        if (!/^\d{15,22}$/.test(guildId)) return respond(interaction, 'Provide a valid server ID.')
        db.run('INSERT INTO guild_blacklist (guild_id,reason) VALUES (?,?) ON CONFLICT(guild_id) DO UPDATE SET reason=excluded.reason', BigInt(guildId), reason)
        const guild = client.guilds.cache.get(guildId)
        if (guild) await guild.leave().catch(() => {})
        return respond(interaction, `Server ${guildId} blacklisted.`)
      }
      if (name === 'unblacklist') {
        const guildId = interaction.options.getString('guild_id', true)
        db.run('DELETE FROM guild_blacklist WHERE guild_id=?', BigInt(guildId))
        return respond(interaction, `Server ${guildId} removed from the blacklist.`)
      }
    }

    if (!await requireGuild(interaction, db, settings)) return

    if (name === 'verify') return doVerify(interaction, db)

    if (name === 'help') {
      const section = interaction.options.getString('section') || 'all'
      const guides = {
        security: '**Security:** /security harden, /security status, /security raid, /antinuke, /guardian audit, /guardian snapshot, /guardian panic, /overwatch, /resilience, /sentinel',
        moderation: '**Moderation:** /warn, /warnings, /timeout, /untimeout, /kick, /ban, /unban, /clear, /slowmode, /case, /history, /nickname, /role, /massrole, /lock, /unlock, /lockdown',
        verification: '**Verification:** /verification setup, /verification enable, /verification disable, /verification reset, /verification status, /verify',
        tickets: '**Tickets:** /ticket-config, /ticket, /ticket-close',
        owner: '**Owner:** /botstats, /backupdb, /backupstatus, /servers, /synccommands, /globalban, /globalunban, /broadcast, /maintenance, /blacklist'
      }
      return respond(interaction, section === 'all' ? Object.values(guides).join('\n\n') : guides[section] || Object.values(guides).join('\n\n'), true, 'ESN Guardian Guide')
    }

    if (name === 'ticket') {
      await interaction.deferReply({ ephemeral: true })
      const subject = interaction.options.getString('subject', true)
      const guild = interaction.guild
      db.ensureGuild(guild.id)
      const cfg = db.get('SELECT support_role_id FROM ticket_config WHERE guild_id=?', BigInt(guild.id))
      const support = cfg?.support_role_id ? guild.roles.cache.get(String(cfg.support_role_id)) : null
      if (!support) return interaction.editReply('Staff must configure a support role with /ticket-config first.')
      const previous = db.get('SELECT * FROM tickets WHERE guild_id=? AND user_id=?', BigInt(guild.id), BigInt(interaction.user.id))
      if (previous?.channel_id && guild.channels.cache.has(String(previous.channel_id))) return interaction.editReply(`You already have a ticket: <#${previous.channel_id}>.`)
      if (previous && Date.now() / 1000 - Number(previous.opened_at) < 60) return interaction.editReply('Wait one minute between opening tickets.')
      const count = db.get('SELECT COUNT(*) AS count FROM tickets WHERE guild_id=? AND channel_id IS NOT NULL', BigInt(guild.id))
      if (Number(count?.count || 0) >= 25) return interaction.editReply('The server has 25 open tickets. Staff need to close one first.')
      const channel = await guild.channels.create({
        name: `ticket-${interaction.user.id}`,
        type: ChannelType.GuildText,
        topic: `Ticket: ${subject}`,
        permissionOverwrites: [
          { id: guild.id, deny: [PermissionFlagsBits.ViewChannel] },
          { id: interaction.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
          { id: support.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
          { id: guild.members.me.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ManageChannels, PermissionFlagsBits.ReadMessageHistory] }
        ],
        reason: 'Guardian support ticket'
      }).catch(() => null)
      if (!channel) return interaction.editReply('I could not create the ticket. Check my Manage Channels permission.')
      db.run('INSERT OR REPLACE INTO tickets (guild_id,user_id,channel_id,opened_at) VALUES (?,?,?,?)', BigInt(guild.id), BigInt(interaction.user.id), BigInt(channel.id), Date.now() / 1000)
      return interaction.editReply(`Ticket created: <#${channel.id}>. Use /ticket-close inside it when finished.`)
    }

    if (name === 'ticket-close') {
      await interaction.deferReply({ ephemeral: true })
      const row = db.get('SELECT * FROM tickets WHERE guild_id=? AND channel_id=?', BigInt(interaction.guildId), BigInt(interaction.channelId))
      if (!row) return interaction.editReply('Run this inside an active Guardian ticket.')
      const cfg = db.get('SELECT support_role_id FROM ticket_config WHERE guild_id=?', BigInt(interaction.guildId))
      const member = interaction.member
      const authorized = String(row.user_id) === interaction.user.id || isStaff(interaction) || (cfg?.support_role_id && member.roles.cache.has(String(cfg.support_role_id)))
      if (!authorized) return interaction.editReply('Only the ticket opener or support staff can close this ticket.')
      const openerId = String(row.user_id)
      await interaction.channel.permissionOverwrites.edit(openerId, { SendMessages: false, SendMessagesInThreads: false, CreatePublicThreads: false, CreatePrivateThreads: false }, { reason: `Ticket closed by ${interaction.user.id}` }).catch(() => {})
      await interaction.channel.setName(`closed-${openerId}`).catch(() => {})
      db.run('UPDATE tickets SET channel_id=NULL WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(openerId))
      return interaction.editReply('Ticket closed. The channel remains private and its history is preserved.')
    }

    if (name === 'suggest') {
      const suggestion = interaction.options.getString('suggestion', true)
      await logEvent(db, interaction.guild, 'system_log_channel_id', 'New suggestion', `From: <@${interaction.user.id}>\n${suggestion}`)
      return respond(interaction, 'Suggestion submitted. Thank you.')
    }

    const staffCommands = new Set([
      'warn','warnings','timeout','untimeout','kick','ban','unban','clear','slowmode','case','history','nickname','role','massrole',
      'lock','unlock','lockdown','unlockdown','panel','config','welcome','goodbye','autorole','logs','smpannounce',
      'ticket-config','verification','guardian','security','antinuke','overwatch','resilience','sentinel'
    ])
    if (staffCommands.has(name) && !await requireStaff(interaction, db, settings)) return

    if (name === 'warn') {
      const member = interaction.options.getMember('member')
      const reason = interaction.options.getString('reason', true)
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot target that member.')
      const caseId = await moderationCase(db, interaction, member, 'WARN', reason)
      db.run('INSERT INTO warnings (case_id,guild_id,user_id) VALUES (?,?,?)', caseId, BigInt(interaction.guildId), BigInt(member.id))
      await logCase(db, interaction, caseId, member.user, 'WARN', reason)
      return respond(interaction, `Warned <@${member.id}>. Case #${caseId}.`)
    }

    if (name === 'warnings') {
      const member = interaction.options.getMember('member')
      const rows = db.all('SELECT c.case_id,c.reason,c.created_at FROM warnings w JOIN cases c ON c.case_id=w.case_id WHERE w.guild_id=? AND w.user_id=? AND w.active=1 ORDER BY c.case_id DESC', BigInt(interaction.guildId), BigInt(member.id))
      return respond(interaction, rows.length ? rows.map(r => `#${r.case_id} — ${r.reason} (${r.created_at})`).join('\n') : 'No active warnings.')
    }

    if (name === 'timeout' || name === 'untimeout' || name === 'kick' || name === 'ban') {
      const member = interaction.options.getMember('member')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot target that member.')
      const reason = interaction.options.getString('reason') || (name === 'untimeout' ? 'Timeout removed' : 'No reason provided')
      const action = name.toUpperCase()
      const caseId = await moderationCase(db, interaction, member, action, reason)
      if (name === 'timeout') await member.timeout(interaction.options.getInteger('minutes', true) * 60000, `Case #${caseId}: ${reason}`)
      if (name === 'untimeout') await member.timeout(null, `Case #${caseId}: ${reason}`)
      if (name === 'kick') await member.kick(`Case #${caseId}: ${reason}`)
      if (name === 'ban') await member.ban({ reason: `Case #${caseId}: ${reason}`, deleteMessageSeconds: (interaction.options.getInteger('delete_message_days') || 0) * 86400 })
      await logCase(db, interaction, caseId, member.user, action, reason)
      return respond(interaction, `${action} completed for <@${member.id}>. Case #${caseId}.`)
    }

    if (name === 'unban') {
      const userId = interaction.options.getString('user_id', true)
      const reason = interaction.options.getString('reason') || 'Unbanned'
      const user = await client.users.fetch(userId).catch(() => null)
      if (!user) return respond(interaction, 'Provide a valid Discord user ID.')
      const caseId = await moderationCase(db, interaction, user, 'UNBAN', reason)
      await interaction.guild.members.unban(userId, `Case #${caseId}: ${reason}`)
      await logCase(db, interaction, caseId, user, 'UNBAN', reason)
      return respond(interaction, `Unbanned ${user.tag}. Case #${caseId}.`)
    }

    if (name === 'clear') {
      if (!interaction.channel?.bulkDelete) return respond(interaction, 'This command requires a text channel.')
      await interaction.deferReply({ ephemeral: true })
      const amount = interaction.options.getInteger('amount', true)
      const deleted = await interaction.channel.bulkDelete(amount, true)
      const caseId = await moderationCase(db, interaction, null, 'CLEAR', `Deleted ${deleted.size} messages`)
      await logCase(db, interaction, caseId, null, 'CLEAR', `Deleted ${deleted.size} messages in <#${interaction.channelId}>`)
      return interaction.editReply(`Deleted ${deleted.size} messages. Case #${caseId}.`)
    }

    if (name === 'slowmode') {
      const seconds = interaction.options.getInteger('seconds', true)
      if (!interaction.channel?.setRateLimitPerUser) return respond(interaction, 'This command requires a text channel.')
      const caseId = await moderationCase(db, interaction, null, 'SLOWMODE', `Set to ${seconds} seconds`)
      await interaction.channel.setRateLimitPerUser(seconds, `Case #${caseId}`)
      return respond(interaction, `Slowmode set to ${seconds}s. Case #${caseId}.`)
    }

    if (name === 'case') {
      const caseId = interaction.options.getInteger('case_id', true)
      const row = db.get('SELECT * FROM cases WHERE case_id=? AND guild_id=?', caseId, BigInt(interaction.guildId))
      if (!row) return respond(interaction, 'Case not found.')
      return respond(interaction, `Case #${row.case_id} | ${row.action}\nTarget: ${userMention(row.target_id)}\nModerator: ${userMention(row.moderator_id)}\nReason: ${row.reason}\nAt: ${row.created_at}`)
    }

    if (name === 'history') {
      const member = interaction.options.getMember('member')
      const rows = db.all('SELECT case_id,action,reason,created_at FROM cases WHERE guild_id=? AND target_id=? ORDER BY case_id DESC LIMIT 20', BigInt(interaction.guildId), BigInt(member.id))
      return respond(interaction, rows.length ? rows.map(r => `#${r.case_id} ${r.action}: ${r.reason}`).join('\n') : 'No cases found.')
    }

    if (name === 'nickname') {
      const member = interaction.options.getMember('member')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot target that member.')
      const nickname = interaction.options.getString('nickname')
      const reason = interaction.options.getString('reason') || 'Nickname changed'
      const caseId = await moderationCase(db, interaction, member, 'NICKNAME', reason)
      await member.setNickname(nickname, `Case #${caseId}: ${reason}`)
      return respond(interaction, `Nickname updated. Case #${caseId}.`)
    }

    if (name === 'role') {
      const member = interaction.options.getMember('member')
      const role = interaction.options.getRole('role')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot target that member.')
      if (!safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'That role is privileged, managed, or above the allowed hierarchy.')
      const remove = interaction.options.getBoolean('remove') || false
      const reason = interaction.options.getString('reason') || 'Role updated'
      const caseId = await moderationCase(db, interaction, member, remove ? 'ROLE_REMOVE' : 'ROLE_ADD', reason)
      await (remove ? member.roles.remove(role, `Case #${caseId}: ${reason}`) : member.roles.add(role, `Case #${caseId}: ${reason}`))
      return respond(interaction, `Role updated for <@${member.id}>. Case #${caseId}.`)
    }

    if (name === 'massrole') {
      const role = interaction.options.getRole('role')
      if (!safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'That role cannot be assigned by Guardian.')
      const remove = interaction.options.getBoolean('remove') || false
      const includeBots = interaction.options.getBoolean('include_bots') || false
      await interaction.deferReply({ ephemeral: true })
      let changed = 0
      for (const member of interaction.guild.members.cache.values()) {
        if (member.user.bot && !includeBots) continue
        if (!memberManageable(interaction.guild, interaction.member, member)) continue
        await (remove ? member.roles.remove(role, `Mass role by ${interaction.user.tag}`) : member.roles.add(role, `Mass role by ${interaction.user.tag}`)).then(() => changed++).catch(() => {})
      }
      const caseId = await moderationCase(db, interaction, null, 'MASSROLE', `${remove ? 'Removed' : 'Added'} ${role.name} for ${changed} members`)
      return interaction.editReply(`Updated ${changed} members. Case #${caseId}.`)
    }

    if (name === 'lock' || name === 'unlock') {
      const reason = interaction.options.getString('reason') || (name === 'lock' ? 'Channel locked' : 'Channel unlocked')
      await interaction.channel.permissionOverwrites.edit(interaction.guild.roles.everyone, { SendMessages: name === 'lock' ? false : null }, { reason })
      return respond(interaction, `Channel ${name === 'lock' ? 'locked' : 'unlocked'}.`)
    }

    if (name === 'lockdown') {
      const count = await lockdownGuild(db, interaction.guild, interaction.options.getString('reason') || 'Manual lockdown')
      return respond(interaction, `Lockdown enabled across ${count} channel(s).`)
    }
    if (name === 'unlockdown') {
      const count = await unlockdownGuild(db, interaction.guild, interaction.options.getString('reason') || 'Manual lockdown release')
      return respond(interaction, `Lockdown released across ${count} channel(s).`)
    }

    if (name === 'panel') {
      return interaction.reply({ embeds: [embed('**Security:** /guardian audit · /security status · /antinuke status\n**Recovery:** /guardian snapshot · /overwatch backup · /resilience status\n**Moderation:** /warn · /timeout · /ban · /lockdown\n**Setup:** /logs · /verification setup · /ticket-config', 'ESN Guardian Staff Panel')] })
    }

    if (name === 'config') {
      const cfg = db.setting(interaction.guildId)
      return respond(interaction, `Moderation log: ${channelMention(cfg.moderation_log_channel_id)}\nSecurity log: ${channelMention(cfg.security_log_channel_id)}\nMember log: ${channelMention(cfg.member_log_channel_id)}\nSystem log: ${channelMention(cfg.system_log_channel_id)}\nWelcome: ${channelMention(cfg.welcome_channel_id)}\nGoodbye: ${channelMention(cfg.goodbye_channel_id)}\nAutorole: ${roleMention(cfg.autorole_id)}\nLockdown active: ${Number(cfg.lockdown_active) ? 'yes' : 'no'}`)
    }

    if (name === 'welcome' || name === 'goodbye') {
      const channel = interaction.options.getChannel('channel', true)
      db.updateSetting(interaction.guildId, name === 'welcome' ? 'welcome_channel_id' : 'goodbye_channel_id', channel.id)
      return respond(interaction, `${name === 'welcome' ? 'Welcome' : 'Goodbye'} channel set to <#${channel.id}>.`)
    }

    if (name === 'autorole') {
      const role = interaction.options.getRole('role')
      if (role && !safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'Choose a manageable, non-privileged role.')
      db.updateSetting(interaction.guildId, 'autorole_id', role?.id || null)
      return respond(interaction, role ? `Autorole set to <@&${role.id}>.` : 'Autorole disabled.')
    }

    if (name === 'logs') {
      const category = interaction.options.getString('category', true)
      const channel = interaction.options.getChannel('channel', true)
      db.updateSetting(interaction.guildId, LOG_FIELDS[category], channel.id)
      return respond(interaction, `${category} logs will be sent to <#${channel.id}>.`)
    }

    if (name === 'smpannounce') {
      const channel = interaction.options.getChannel('channel', true)
      const message = interaction.options.getString('message', true)
      const cfg = db.setting(interaction.guildId)
      const last = cfg.ad_last_sent_at ? Date.parse(String(cfg.ad_last_sent_at)) : 0
      const cooldown = Number(cfg.ad_cooldown_seconds || 3600) * 1000
      if (last && Date.now() - last < cooldown && interaction.user.id !== interaction.guild.ownerId) {
        return respond(interaction, `SMP announcement cooldown active. Try again in ${Math.ceil((cooldown - (Date.now() - last)) / 60000)} minute(s).`)
      }
      await channel.send({ embeds: [embed(message, 'ESN SMP Announcement')], allowedMentions: { parse: [] } })
      db.updateSetting(interaction.guildId, 'ad_last_sent_at', new Date().toISOString())
      return respond(interaction, `Announcement sent to <#${channel.id}>.`)
    }

    if (name === 'ticket-config') {
      const role = interaction.options.getRole('support_role', true)
      if (role.id === interaction.guildId || role.managed || (interaction.user.id !== interaction.guild.ownerId && role.comparePositionTo(interaction.member.roles.highest) >= 0)) return respond(interaction, 'Choose an unmanaged support role below your role.')
      db.run('UPDATE ticket_config SET support_role_id=? WHERE guild_id=?', BigInt(role.id), BigInt(interaction.guildId))
      return respond(interaction, `Support role set to <@&${role.id}>.`)
    }

    if (name === 'verification') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'setup') {
        const channel = interaction.options.getChannel('channel', true)
        const verified = interaction.options.getRole('verified_role', true)
        const unverified = interaction.options.getRole('unverified_role')
        const minDays = interaction.options.getInteger('minimum_account_age_days') || 0
        if (!safeRole(interaction.guild, interaction.member, verified) || (unverified && !safeRole(interaction.guild, interaction.member, unverified)) || unverified?.id === verified.id) return respond(interaction, 'Choose distinct, manageable, non-privileged roles.')
        const message = await channel.send({
          embeds: [embed('Press **VERIFY** to complete verification.', 'ESN Guardian Verification')],
          components: [{ type: 1, components: [{ type: 2, style: 3, label: 'VERIFY', emoji: { name: '✅' }, custom_id: 'esn_guardian:verify' }] }]
        })
        db.run('UPDATE verification_config SET channel_id=?,message_id=?,verified_role_id=?,unverified_role_id=?,min_account_age_days=? WHERE guild_id=?', BigInt(channel.id), BigInt(message.id), BigInt(verified.id), unverified ? BigInt(unverified.id) : null, minDays, BigInt(interaction.guildId))
        db.run("INSERT OR REPLACE INTO panel_messages (guild_id,panel_type,channel_id,message_id) VALUES (?,'verification',?,?)", BigInt(interaction.guildId), BigInt(channel.id), BigInt(message.id))
        return respond(interaction, `Verification panel posted in <#${channel.id}>.`)
      }
      if (sub === 'enable' || sub === 'disable') {
        db.run('UPDATE verification_config SET enabled=? WHERE guild_id=?', sub === 'enable' ? 1 : 0, BigInt(interaction.guildId))
        return respond(interaction, `Verification ${sub === 'enable' ? 'enabled' : 'disabled'}.`)
      }
      if (sub === 'reset') {
        const member = interaction.options.getMember('member')
        if (member) db.run('DELETE FROM verified_members WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(member.id))
        else db.run('DELETE FROM verified_members WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, member ? `Reset verification for <@${member.id}>.` : 'Reset verification records for this server.')
      }
      if (sub === 'status') {
        const cfg = db.get('SELECT * FROM verification_config WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `Enabled: ${Number(cfg.enabled) ? 'yes' : 'no'}\nChannel: ${channelMention(cfg.channel_id)}\nVerified role: ${roleMention(cfg.verified_role_id)}\nUnverified role: ${roleMention(cfg.unverified_role_id)}\nMinimum account age: ${Number(cfg.min_account_age_days || 0)} days`)
      }
    }

    if (name === 'guardian') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'snapshot') {
        const snap = await saveSnapshot(db, interaction.guild)
        return respond(interaction, `Recovery snapshot saved with ${snap.roles.length} roles and ${snap.channels.length} channels. Current bots were approved.`)
      }
      if (sub === 'approve-bot' || sub === 'unapprove-bot') {
        const botId = interaction.options.getString('bot_id', true)
        if (!/^\d{15,22}$/.test(botId)) return respond(interaction, 'Provide a valid bot/application ID.')
        if (sub === 'approve-bot') db.run('INSERT OR REPLACE INTO approved_bots (guild_id,bot_id,added_by_id) VALUES (?,?,?)', BigInt(interaction.guildId), BigInt(botId), BigInt(interaction.user.id))
        else db.run('DELETE FROM approved_bots WHERE guild_id=? AND bot_id=?', BigInt(interaction.guildId), BigInt(botId))
        return respond(interaction, `Bot ${botId} ${sub === 'approve-bot' ? 'approved' : 'removed from approval'}.`)
      }
      if (sub === 'panic') {
        const enabled = interaction.options.getBoolean('enabled') ?? true
        const result = await panicGuild(db, interaction.guild, enabled)
        return respond(interaction, enabled ? `PANIC enabled. Locked ${result.locked} channel(s); removed ${result.botsRemoved} unapproved bot(s).` : `PANIC released. Restored ${result.restored} channel(s).`)
      }
      if (sub === 'audit') {
        const a = securityAudit(db, interaction.guild)
        return respond(interaction, `Missing permissions: ${a.missing.length ? a.missing.join(', ') : 'none'}\nHigh-risk roles: ${a.riskyRoles}\nUnapproved bots: ${a.unapprovedBots}\nRoles exposing Use External Apps: ${a.externalEnabled}\nAnti-nuke: ${a.antiNuke ? 'ON' : 'OFF'}\nRaid protection: ${a.raid ? 'ON' : 'OFF'}\nRecovery snapshot: ${a.snapshot ? 'YES' : 'NO'}`, true, 'Guardian Security Audit')
      }
      if (sub === 'status') {
        const panic = db.stateEnabled(`panic:${interaction.guildId}`)
        const a = securityAudit(db, interaction.guild)
        return respond(interaction, `PANIC: ${panic ? 'ACTIVE' : 'off'}\nAnti-nuke: ${a.antiNuke ? 'ON' : 'OFF'}\nRaid protection: ${a.raid ? 'ON' : 'OFF'}\nSnapshot: ${a.snapshot ? 'ready' : 'missing'}\nUnapproved bots: ${a.unapprovedBots}`)
      }
    }

    if (name === 'security') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'harden') {
        const r = await hardenGuild(db, interaction.guild)
        return respond(interaction, `Secure baseline applied. Anti-nuke, raid protection, and AutoMod are enabled. Removed Use External Apps from ${r.rolesChanged} manageable role(s). Recovery snapshot refreshed.`)
      }
      if (sub === 'status') {
        const c = db.get('SELECT * FROM security_config WHERE guild_id=?', BigInt(interaction.guildId))
        const a = db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `AutoMod: ${Number(c.automod_enabled) ? 'ON' : 'OFF'}\nFlood: ${c.flood_limit} messages / ${c.flood_window_seconds}s\nMax mentions: ${c.max_mentions}\nCaps threshold: ${c.caps_percentage}%\nBlock invites: ${Number(c.block_invites) ? 'YES' : 'NO'}\nStrict links: ${Number(c.strict_links) ? 'YES' : 'NO'}\nAnti-nuke: ${Number(a.enabled) ? 'ON' : 'OFF'}`)
      }
      if (sub === 'scan') {
        const a = securityAudit(db, interaction.guild)
        return respond(interaction, `Permissions missing: ${a.missing.length ? a.missing.join(', ') : 'none'}\nRisky roles: ${a.riskyRoles}\nUnapproved bots: ${a.unapprovedBots}\nExternal-app exposed roles: ${a.externalEnabled}`)
      }
      if (sub === 'cases') {
        const limit = interaction.options.getInteger('limit') || 10
        const rows = db.all("SELECT case_id,action,target_id,reason,created_at FROM cases WHERE guild_id=? AND (action LIKE 'ANTI%' OR action LIKE 'SECURITY%' OR action LIKE 'AUTOMOD%' OR action LIKE 'RAID%' OR action LIKE 'EXTERNAL%') ORDER BY case_id DESC LIMIT ?", BigInt(interaction.guildId), limit)
        return respond(interaction, rows.length ? rows.map(r => `#${r.case_id} ${r.action} — ${r.reason}`).join('\n') : 'No security cases found.')
      }
      if (sub === 'automod') {
        const enabled = interaction.options.getBoolean('enabled', true)
        db.run('UPDATE security_config SET automod_enabled=? WHERE guild_id=?', enabled ? 1 : 0, BigInt(interaction.guildId))
        return respond(interaction, `AutoMod ${enabled ? 'enabled' : 'disabled'}.`)
      }
      if (sub === 'thresholds') {
        db.run('UPDATE security_config SET flood_limit=?,flood_window_seconds=?,max_mentions=?,caps_percentage=? WHERE guild_id=?',
          interaction.options.getInteger('flood_limit', true),
          interaction.options.getInteger('flood_window_seconds', true),
          interaction.options.getInteger('max_mentions', true),
          interaction.options.getInteger('caps_percentage', true),
          BigInt(interaction.guildId))
        return respond(interaction, 'AutoMod thresholds updated.')
      }
      if (sub === 'links') {
        db.run('UPDATE security_config SET block_invites=?,strict_links=? WHERE guild_id=?',
          interaction.options.getBoolean('block_invites', true) ? 1 : 0,
          interaction.options.getBoolean('strict_links', true) ? 1 : 0,
          BigInt(interaction.guildId))
        return respond(interaction, 'Link protection updated.')
      }
      if (sub === 'allow-domain' || sub === 'remove-domain') {
        const domain = normalizeDomain(interaction.options.getString('domain', true))
        if (!domain) return respond(interaction, 'Provide a valid domain.')
        if (sub === 'allow-domain') db.run('INSERT OR IGNORE INTO allowed_domains (guild_id,domain) VALUES (?,?)', BigInt(interaction.guildId), domain)
        else db.run('DELETE FROM allowed_domains WHERE guild_id=? AND domain=?', BigInt(interaction.guildId), domain)
        return respond(interaction, `${domain} ${sub === 'allow-domain' ? 'allowed' : 'removed'}.`)
      }
      if (sub === 'add-word' || sub === 'remove-word') {
        const word = interaction.options.getString('word', true).trim()
        if (!word) return respond(interaction, 'Word cannot be empty.')
        if (sub === 'add-word') db.run('INSERT OR IGNORE INTO bad_words (guild_id,word) VALUES (?,?)', BigInt(interaction.guildId), word)
        else db.run('DELETE FROM bad_words WHERE guild_id=? AND word=? COLLATE NOCASE', BigInt(interaction.guildId), word)
        return respond(interaction, `Blocked-word list updated.`)
      }
      if (sub === 'words') {
        const rows = db.all('SELECT word FROM bad_words WHERE guild_id=? ORDER BY word', BigInt(interaction.guildId))
        return respond(interaction, rows.length ? rows.map(r => `• ${r.word}`).join('\n') : 'No blocked words configured.')
      }
      if (sub === 'domains') {
        const rows = db.all('SELECT domain FROM allowed_domains WHERE guild_id=? ORDER BY domain', BigInt(interaction.guildId))
        return respond(interaction, rows.length ? rows.map(r => `• ${r.domain}`).join('\n') : 'No allowed domains configured.')
      }
      if (sub === 'trusted') {
        const rows = db.all('SELECT user_id FROM anti_nuke_trusted_users WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, rows.length ? rows.map(r => `• <@${r.user_id}> (${r.user_id})`).join('\n') : 'No additional trusted users. The server owner is always trusted.')
      }
      if (sub === 'check-link') {
        const domain = normalizeDomain(interaction.options.getString('url', true))
        if (!domain) return respond(interaction, 'That URL is invalid.')
        const cfg = db.get('SELECT strict_links FROM security_config WHERE guild_id=?', BigInt(interaction.guildId))
        if (!Number(cfg.strict_links)) return respond(interaction, `${domain} is allowed because strict-link mode is disabled.`)
        const allowed = db.all('SELECT domain FROM allowed_domains WHERE guild_id=?', BigInt(interaction.guildId)).map(r => String(r.domain))
        const ok = allowed.some(base => domain === base || domain.endsWith(`.${base}`))
        return respond(interaction, `${domain}: ${ok ? 'ALLOWED' : 'BLOCKED'} by current strict-link policy.`)
      }
      if (sub === 'reset-automod') {
        db.run('UPDATE security_config SET automod_enabled=1,flood_limit=6,flood_window_seconds=10,max_mentions=6,caps_percentage=80,block_invites=1,strict_links=0 WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, 'AutoMod restored to Guardian secure defaults.')
      }
      if (sub === 'raid') {
        const role = interaction.options.getRole('quarantine_role')
        if (role && !safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'Choose a manageable, non-privileged quarantine role.')
        db.run('UPDATE raid_config SET enabled=?,join_limit=?,join_window_seconds=?,min_account_age_days=?,quarantine_role_id=? WHERE guild_id=?',
          interaction.options.getBoolean('enabled', true) ? 1 : 0,
          interaction.options.getInteger('join_limit', true),
          interaction.options.getInteger('join_window_seconds', true),
          interaction.options.getInteger('minimum_account_age_days', true),
          role ? BigInt(role.id) : null,
          BigInt(interaction.guildId))
        return respond(interaction, 'Raid protection configuration updated.')
      }
      if (sub === 'raid-status') {
        const r = db.get('SELECT * FROM raid_config WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `Enabled: ${Number(r.enabled) ? 'yes' : 'no'}\nJoin threshold: ${r.join_limit} in ${r.join_window_seconds}s\nMinimum account age: ${r.min_account_age_days} days\nQuarantine role: ${roleMention(r.quarantine_role_id)}`)
      }
      if (sub === 'quarantine' || sub === 'release') {
        const member = interaction.options.getMember('member')
        const r = db.get('SELECT quarantine_role_id FROM raid_config WHERE guild_id=?', BigInt(interaction.guildId))
        const role = r?.quarantine_role_id ? interaction.guild.roles.cache.get(String(r.quarantine_role_id)) : null
        if (!role?.editable) return respond(interaction, 'No manageable quarantine role is configured.')
        if (sub === 'quarantine') await member.roles.add(role, interaction.options.getString('reason') || 'Manual security review')
        else await member.roles.remove(role, interaction.options.getString('reason') || 'Security review completed')
        return respond(interaction, `${sub === 'quarantine' ? 'Quarantined' : 'Released'} <@${member.id}>.`)
      }
      if (sub === 'member') {
        const member = interaction.options.getMember('member')
        const rows = db.all('SELECT case_id,action,reason,created_at FROM cases WHERE guild_id=? AND target_id=? ORDER BY case_id DESC LIMIT 20', BigInt(interaction.guildId), BigInt(member.id))
        const age = Math.floor((Date.now() - member.user.createdTimestamp) / 86400000)
        const risky = member.roles.cache.filter(r => r.permissions.has(PermissionFlagsBits.Administrator) || r.permissions.has(PermissionFlagsBits.ManageGuild) || r.permissions.has(PermissionFlagsBits.ManageRoles))
        return respond(interaction, `Member: <@${member.id}>\nAccount age: ${age} days\nHigh-risk roles: ${risky.size ? risky.map(r => r.name).join(', ') : 'none'}\nRecent security/mod cases:\n${rows.length ? rows.map(r => `#${r.case_id} ${r.action}: ${r.reason}`).join('\n') : 'none'}`)
      }
    }

    if (name === 'antinuke') {
      const sub = interaction.options.getSubcommand()
      if (['disable','trust','untrust'].includes(sub) && !isGuildOwner(interaction)) return respond(interaction, 'Only the Discord server owner can change this anti-nuke control.', true, 'Access denied')
      if (sub === 'setup') {
        const limit = interaction.options.getInteger('action_limit') || 3
        const window = interaction.options.getInteger('window_seconds') || 15
        db.run('UPDATE anti_nuke_config SET enabled=1,action_limit=?,window_seconds=? WHERE guild_id=?', limit, window, BigInt(interaction.guildId))
        return respond(interaction, `Anti-nuke enabled: ${limit} destructive actions inside ${window}s triggers containment.`)
      }
      if (sub === 'enable' || sub === 'disable') {
        db.run('UPDATE anti_nuke_config SET enabled=? WHERE guild_id=?', sub === 'enable' ? 1 : 0, BigInt(interaction.guildId))
        return respond(interaction, `Anti-nuke ${sub === 'enable' ? 'enabled' : 'disabled'}.`)
      }
      if (sub === 'status') {
        const r = db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(interaction.guildId))
        const trusted = db.get('SELECT COUNT(*) AS count FROM anti_nuke_trusted_users WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `Enabled: ${Number(r.enabled) ? 'yes' : 'no'}\nThreshold: ${r.action_limit} actions / ${r.window_seconds}s\nAdditional trusted users: ${trusted.count}`)
      }
      if (sub === 'trust' || sub === 'untrust') {
        const user = interaction.options.getUser('user', true)
        if (sub === 'trust') db.run('INSERT OR REPLACE INTO anti_nuke_trusted_users (guild_id,user_id,added_by_id) VALUES (?,?,?)', BigInt(interaction.guildId), BigInt(user.id), BigInt(interaction.user.id))
        else db.run('DELETE FROM anti_nuke_trusted_users WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(user.id))
        return respond(interaction, `<@${user.id}> ${sub === 'trust' ? 'trusted' : 'removed from trust'}.`)
      }
    }

    if (name === 'overwatch') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'status') {
        const a = securityAudit(db, interaction.guild)
        const cases = db.get('SELECT COUNT(*) AS count FROM cases WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `Anti-nuke: ${a.antiNuke ? 'ON' : 'OFF'}\nRaid: ${a.raid ? 'ON' : 'OFF'}\nSnapshot: ${a.snapshot ? 'READY' : 'MISSING'}\nMissing permissions: ${a.missing.length}\nRecorded cases: ${cases.count}`)
      }
      if (sub === 'seal') {
        const cfg = {
          security: db.get('SELECT * FROM security_config WHERE guild_id=?', BigInt(interaction.guildId)),
          antinuke: db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(interaction.guildId)),
          raid: db.get('SELECT * FROM raid_config WHERE guild_id=?', BigInt(interaction.guildId)),
          approvedBots: db.all('SELECT bot_id FROM approved_bots WHERE guild_id=?', BigInt(interaction.guildId)).map(r => String(r.bot_id))
        }
        const clean = JSON.parse(JSON.stringify(cfg, (_, v) => typeof v === 'bigint' ? v.toString() : v))
        const hash = jsonHash(clean)
        db.run('INSERT INTO policy_baselines (guild_id,data,sha256,created_at) VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET data=excluded.data,sha256=excluded.sha256,created_at=CURRENT_TIMESTAMP', BigInt(interaction.guildId), JSON.stringify(clean), hash)
        return respond(interaction, `Policy baseline sealed. SHA-256: \`${hash}\``)
      }
      if (sub === 'integrity') {
        const row = db.get('SELECT * FROM policy_baselines WHERE guild_id=?', BigInt(interaction.guildId))
        if (!row) return respond(interaction, 'No sealed policy baseline exists. Run /overwatch seal.')
        const actual = crypto.createHash('sha256').update(String(row.data)).digest('hex')
        return respond(interaction, `Stored hash: \`${row.sha256}\`\nRecomputed hash: \`${actual}\`\nIntegrity: **${actual === row.sha256 ? 'VALID' : 'FAILED'}**`)
      }
      if (sub === 'incidents') {
        const rows = db.all('SELECT incident_id,kind,status,created_at FROM incident_sessions WHERE guild_id=? ORDER BY incident_id DESC LIMIT 15', BigInt(interaction.guildId))
        return respond(interaction, rows.length ? rows.map(r => `#${r.incident_id} ${r.kind} — ${r.status} — ${r.created_at}`).join('\n') : 'No persistent incident sessions recorded.')
      }
      if (sub === 'backup') {
        const file = db.backup('incident')
        return respond(interaction, file ? `Verified incident backup created: \`${file}\`` : 'Backup could not be created.')
      }
    }

    if (name === 'resilience') {
      const sub = interaction.options.getSubcommand()
      const info = db.backupInfo()
      const audit = securityAudit(db, interaction.guild)
      if (sub === 'status') return respond(interaction, `Database: ${fs.existsSync(info.database) ? 'READY' : 'MISSING'}\nBackups: ${info.count}\nLatest backup: ${info.latest || 'none'}\nRecovery snapshot: ${audit.snapshot ? 'READY' : 'MISSING'}\nRequired permissions missing: ${audit.missing.length}`)
      if (sub === 'drill') {
        const checks = [
          ['Database writable', (() => { try { fs.accessSync(info.database, fs.constants.R_OK | fs.constants.W_OK); return true } catch { return false } })()],
          ['Recovery snapshot', audit.snapshot],
          ['View Audit Log', !audit.missing.includes('View Audit Log')],
          ['Manage Roles', !audit.missing.includes('Manage Roles')],
          ['Manage Channels', !audit.missing.includes('Manage Channels')],
          ['Backups exist', info.count > 0]
        ]
        return respond(interaction, checks.map(([n, ok]) => `${ok ? '✅' : '❌'} ${n}`).join('\n'), true, 'Guardian Readiness Drill')
      }
      if (sub === 'recovery-plan') {
        const steps = []
        if (!audit.snapshot) steps.push('Run /guardian snapshot.')
        if (audit.missing.length) steps.push(`Fix Guardian permissions: ${audit.missing.join(', ')}.`)
        if (!info.count) steps.push('Run /backupdb to create a verified database backup.')
        if (!audit.antiNuke) steps.push('Run /antinuke setup.')
        if (!audit.raid) steps.push('Configure /security raid.')
        return respond(interaction, steps.length ? steps.map((x, i) => `${i + 1}. ${x}`).join('\n') : 'Guardian recovery readiness is complete.')
      }
    }

    if (name === 'sentinel') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'status') {
        const count = db.get('SELECT COUNT(*) AS count FROM security_signals WHERE guild_id=?', BigInt(interaction.guildId))
        const recent = db.get("SELECT COUNT(*) AS count FROM security_signals WHERE guild_id=? AND created_at >= datetime('now','-24 hours')", BigInt(interaction.guildId))
        return respond(interaction, `Sentinel: ACTIVE\nSignals stored: ${count.count}\nSignals in last 24h: ${recent.count}\nSource: Guardian security and anomaly telemetry.`)
      }
      if (sub === 'signals') {
        const rows = db.all('SELECT signal_id,subject_id,kind,score,created_at FROM security_signals WHERE guild_id=? ORDER BY signal_id DESC LIMIT 15', BigInt(interaction.guildId))
        return respond(interaction, rows.length ? rows.map(r => `#${r.signal_id} ${r.kind} | score ${r.score} | subject ${r.subject_id || 'n/a'} | ${r.created_at}`).join('\n') : 'No Sentinel anomaly signals recorded yet.')
      }
      if (sub === 'subject') {
        const subject = interaction.options.getString('subject_id', true)
        const rows = /^\d+$/.test(subject) ? db.all('SELECT signal_id,kind,score,details,created_at FROM security_signals WHERE guild_id=? AND subject_id=? ORDER BY signal_id DESC LIMIT 20', BigInt(interaction.guildId), BigInt(subject)) : []
        return respond(interaction, rows.length ? rows.map(r => `#${r.signal_id} ${r.kind} — score ${r.score} — ${r.created_at}`).join('\n') : 'No Sentinel profile exists for that subject.')
      }
      if (sub === 'explain') {
        const signalId = interaction.options.getInteger('signal_id', true)
        const row = db.get('SELECT * FROM security_signals WHERE guild_id=? AND signal_id=?', BigInt(interaction.guildId), signalId)
        if (!row) return respond(interaction, 'Signal not found.')
        return respond(interaction, `Signal #${row.signal_id}\nKind: ${row.kind}\nScore: ${row.score}\nSubject: ${row.subject_id || 'n/a'}\nDetails: ${row.details || 'No additional details'}\nCreated: ${row.created_at}`)
      }
    }
  } catch (error) {
    console.error(`[Guardian] command /${name} failed`, error)
    const text = 'The command failed safely. Staff can check the bot console/system log.'
    if (interaction.deferred || interaction.replied) await interaction.followUp({ content: text, ephemeral: true }).catch(() => {})
    else await interaction.reply({ content: text, ephemeral: true }).catch(() => {})
  }
}

module.exports = {
  definitions,
  asJson,
  registerGuild,
  handleCommand,
  handleButton
}
