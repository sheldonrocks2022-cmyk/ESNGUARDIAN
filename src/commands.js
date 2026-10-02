'use strict'

const {
  ChannelType,
  PermissionFlagsBits,
  SlashCommandBuilder
} = require('discord.js')
const {
  HIGH_RISK_PERMISSIONS,
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
  userMention,
  dangerousRole
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
  securityCase,
  quarantineMember
} = require('./security')
const { HELP_GUIDES } = require('./community')

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

const ticketLocks = new Map()
const announcementLocks = new Map()

async function withKeyLock(map, key, operation) {
  const lockKey = String(key)
  const previous = map.get(lockKey) || Promise.resolve()
  let release
  const gate = new Promise(resolve => { release = resolve })
  const current = previous.catch(() => {}).then(() => gate)
  map.set(lockKey, current)
  await previous.catch(() => {})
  try {
    return await operation()
  } finally {
    release()
    if (map.get(lockKey) === current) map.delete(lockKey)
  }
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

  defs.push(new SlashCommandBuilder().setName('massrole').setDescription('Add or remove a role for all eligible members.')
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
        { name: 'Setup', value: 'setup' },
        { name: 'Moderation', value: 'moderation' },
        { name: 'Security', value: 'security' },
        { name: 'Verification', value: 'verification' },
        { name: 'Community', value: 'community' },
        { name: 'Owner', value: 'owner' }
      )))

  defs.push(new SlashCommandBuilder().setName('panel').setDescription('Post the ESN Guardian staff control panel.'))
  defs.push(new SlashCommandBuilder().setName('config').setDescription('Show configured server settings.'))
  defs.push(new SlashCommandBuilder().setName('welcome').setDescription('Set the channel for automatic detailed join notices.')
    .addChannelOption(o => o.setName('channel').setDescription('Welcome channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('goodbye').setDescription('Set the channel for automatic detailed leave notices.')
    .addChannelOption(o => o.setName('channel').setDescription('Goodbye channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('autorole').setDescription('Configure the automatic member role.')
    .addRoleOption(o => o.setName('role').setDescription('Role; omit to disable').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('logs').setDescription('Set a detailed event log channel.')
    .addStringOption(o => o.setName('category').setDescription('Log category').setRequired(true).addChoices(...LOG_CHOICES.map(([name, value]) => ({ name, value }))))
    .addChannelOption(o => o.setName('channel').setDescription('Log channel').setRequired(true).addChannelTypes(ChannelType.GuildText)))
  defs.push(new SlashCommandBuilder().setName('suggest').setDescription('Submit a suggestion for staff and the community.')
    .addStringOption(o => o.setName('suggestion').setDescription('Suggestion').setRequired(true).setMaxLength(1800)))
  defs.push(new SlashCommandBuilder().setName('smpannounce').setDescription('Send an SMP announcement with a server-wide cooldown.')
    .addChannelOption(o => o.setName('channel').setDescription('Announcement channel').setRequired(true).addChannelTypes(ChannelType.GuildText))
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
  defs.push(new SlashCommandBuilder().setName('ticket').setDescription('Open a private support ticket. One active ticket per member.')
    .addStringOption(o => o.setName('subject').setDescription('Ticket subject').setRequired(true).setMaxLength(200)))
  defs.push(new SlashCommandBuilder().setName('ticket-close').setDescription('Close this ticket and retain its private message history.'))

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
  defs.push(new SlashCommandBuilder().setName('synccommands').setDescription('Refresh slash commands in one server or every connected server.')
    .addStringOption(o => o.setName('guild_id').setDescription('One guild ID; omit for all connected servers').setRequired(false)))
  defs.push(new SlashCommandBuilder().setName('globalban').setDescription('Ban a user from every served server.')
    .addStringOption(o => o.setName('user_id').setDescription('Discord user ID').setRequired(true))
    .addStringOption(o => o.setName('reason').setDescription('Reason').setRequired(true).setMaxLength(1000)))
  defs.push(new SlashCommandBuilder().setName('globalunban').setDescription('Remove a user from the global-ban list.')
    .addStringOption(o => o.setName('user_id').setDescription('Discord user ID').setRequired(true)))
  defs.push(new SlashCommandBuilder().setName('broadcast').setDescription('Send an announcement to configured system log channels.')
    .addStringOption(o => o.setName('message').setDescription('Message').setRequired(true).setMaxLength(1800)))
  defs.push(new SlashCommandBuilder().setName('maintenance').setDescription('Enable or disable maintenance mode notice.')
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

async function accessDenied(interaction) {
  await respond(interaction, 'This command is unavailable here, or you do not have permission to use it.', true, 'Access denied')
  return false
}

async function requireGuild(interaction, db, settings) {
  if (!interaction.inGuild()) return accessDenied(interaction)
  if (db.isGuildBlacklisted(interaction.guildId) && !isBotOwner(interaction, settings)) return accessDenied(interaction)
  if (db.stateEnabled('maintenance') && !isBotOwner(interaction, settings)) return accessDenied(interaction)
  db.ensureGuild(interaction.guildId)
  return true
}

async function requireStaff(interaction, db, settings) {
  if (!await requireGuild(interaction, db, settings)) return false
  if (!isStaff(interaction)) return accessDenied(interaction)
  return true
}

async function requireBotOwner(interaction, settings) {
  const owners = new Set(['1515077206886453469','1392224478175690752','1434663490160955407'])
  if (settings.ownerId) owners.add(String(settings.ownerId))
  if (!owners.has(String(interaction.user.id))) return accessDenied(interaction)
  return true
}

async function requirePermission(interaction, permission) {
  if (!interaction.memberPermissions?.has(permission)) return accessDenied(interaction)
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

function safeVerificationRole(guild, role) {
  const me = guild.members.me
  if (!me || !role || role.id === guild.id || role.managed) return false
  if (role.comparePositionTo(me.roles.highest) >= 0) return false
  if (HIGH_RISK_PERMISSIONS.some(bit => role.permissions.has(bit))) return false
  return true
}

function verificationRoleAllowedForStaff(guild, actor, role) {
  if (!safeVerificationRole(guild, role)) return false
  if (actor?.id !== guild.ownerId && role.comparePositionTo(actor.roles.highest) >= 0) return false
  return true
}

async function doVerify(interaction, db) {
  if (!interaction.inGuild()) {
    return respond(interaction, 'Verification is available only in a server.')
  }

  if (db.isGuildBlacklisted(interaction.guildId) || db.stateEnabled('maintenance')) {
    return respond(interaction, 'Verification is currently unavailable.')
  }

  db.ensureGuild(interaction.guildId)
  const cfg = db.get('SELECT * FROM verification_config WHERE guild_id=?', BigInt(interaction.guildId))
  if (!cfg || !Number(cfg.enabled)) return respond(interaction, 'Verification is not enabled here.')

  const existing = db.get('SELECT 1 AS ok FROM verified_members WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(interaction.user.id))
  if (existing) return respond(interaction, 'You are already verified.')

  const minDays = Number(cfg.min_account_age_days || 0)
  const accountAgeDays = (Date.now() - interaction.user.createdTimestamp) / 86400000
  if (accountAgeDays < minDays) return respond(interaction, `Your account must be at least ${minDays} days old.`)

  const verifiedRole = cfg.verified_role_id ? interaction.guild.roles.cache.get(String(cfg.verified_role_id)) : null
  const unverifiedRole = cfg.unverified_role_id ? interaction.guild.roles.cache.get(String(cfg.unverified_role_id)) : null

  if (
    !safeVerificationRole(interaction.guild, verifiedRole) ||
    (unverifiedRole && !safeVerificationRole(interaction.guild, unverifiedRole)) ||
    (verifiedRole && unverifiedRole && verifiedRole.id === unverifiedRole.id)
  ) {
    return respond(interaction, 'Verification is incomplete: ask staff to configure the verified role.')
  }

  let member
  try {
    member = await interaction.guild.members.fetch(interaction.user.id)
    await member.roles.add(verifiedRole, 'ESN Guardian verification')
    if (unverifiedRole && member.roles.cache.has(unverifiedRole.id)) {
      await member.roles.remove(unverifiedRole, 'ESN Guardian verification')
    }
  } catch (error) {
    console.error('[Guardian] verification role update failed', {
      guild: interaction.guildId,
      user: interaction.user.id,
      error: error?.message || String(error)
    })
    return respond(interaction, 'I could not update your verification roles. Staff need to check my role permissions.')
  }

  db.run('INSERT OR IGNORE INTO verified_members (guild_id,user_id) VALUES (?,?)', BigInt(interaction.guildId), BigInt(member.id))
  const caseId = db.createCase(interaction.guildId, member.id, interaction.client.user?.id, 'VERIFY', 'Member verified', interaction.channelId)
  await logEvent(db, interaction.guild, 'verification_log_channel_id', `Verified | Case #${caseId}`, `Member: <@${member.id}> (${member.id})`)
  return respond(interaction, 'You are verified. Access has been updated.')
}

async function handleButton(interaction, db) {
  if (interaction.customId === 'esn_guardian:verify') return doVerify(interaction, db)
  if (interaction.client.guardianCommunity) {
    const handled = await interaction.client.guardianCommunity.handleButton(interaction)
    if (handled) return
  }
}

async function handleCommand(interaction, db, settings) {
  const name = interaction.commandName
  const client = interaction.client

  try {
    if (['botstats','backupdb','backupstatus','servers','synccommands','globalban','globalunban','broadcast','maintenance','blacklist','unblacklist'].includes(name)) {
      if (!await requireBotOwner(interaction, settings)) return

      if (name === 'botstats') {
        return respond(interaction,'Servers: '+client.guilds.cache.size+'\nUsers cached: '+client.users.cache.size+'\nLatency: '+Math.round(client.ws.ping)+'ms\nDatabase: online')
      }
      if (name === 'backupdb') {
        try {
          const file=db.backup('manual')
          return respond(interaction,file?'Database backup created: '+require('node:path').basename(file)+'.':'Database backup could not be created.')
        } catch (error) {
          console.error('[Guardian] manual database backup failed',error)
          return respond(interaction,'Database backup failed. Check the bot console for the logged error.')
        }
      }
      if (name === 'backupstatus') {
        const info=db.backupInfo()
        return respond(interaction,'Database: '+info.database+'\nBackups kept: '+info.count+'\nLatest backup: '+(info.latest||'none yet'))
      }
      if (name === 'servers') {
        const guilds=[...client.guilds.cache.values()].sort((a,b)=>a.name.localeCompare(b.name))
        const total=guilds.reduce((n,g)=>n+(g.memberCount||0),0)
        const body=guilds.map(g=>g.name+' ('+g.id+') - '+(g.memberCount||0).toLocaleString()+' members').join('\n')||'No servers.'
        return interaction.reply({
          embeds:[embed('Servers: '+guilds.length.toLocaleString()+'\nCombined members: '+total.toLocaleString(),'Connected servers')],
          files:[{attachment:Buffer.from(body,'utf8'),name:'servers.txt'}],
          ephemeral:true
        })
      }
      if (name === 'synccommands') {
        const guildId=interaction.options.getString('guild_id')
        if(guildId&&!/^\d+$/.test(guildId))return respond(interaction,'Provide a numeric server ID, or leave it empty to sync every connected server.')
        const targets=guildId?[client.guilds.cache.get(guildId)].filter(Boolean):[...client.guilds.cache.values()]
        if(guildId&&!targets.length)return respond(interaction,'I am not connected to that server.')
        await interaction.deferReply({ephemeral:true})
        let synced=0,failed=0,count=0
        for (const guild of targets) {
          try { const result=await registerGuild(guild); synced++; count+=result.size } catch { failed++ }
        }
        const scope=guildId?'server `'+guildId+'`':'all connected servers'
        return respond(interaction,'Synced '+count+' command(s) across '+synced+' '+scope+'; failed: '+failed+'.')
      }
      if (name === 'globalban') {
        const userId=interaction.options.getString('user_id',true),reason=interaction.options.getString('reason',true)
        if(!/^\d{15,22}$/.test(userId))return respond(interaction,'Provide a valid Discord user ID.')
        if(['1515077206886453469','1392224478175690752','1434663490160955407'].includes(userId))return respond(interaction,'A configured bot owner cannot be globally banned.')
        db.run('INSERT INTO global_bans (user_id,reason,banned_by_id) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason,banned_by_id=excluded.banned_by_id',BigInt(userId),reason,BigInt(interaction.user.id))
        let banned=0,failed=0
        for(const guild of client.guilds.cache.values())await guild.members.ban(userId,{reason:'ESN Guardian global ban: '+reason}).then(()=>banned++).catch(()=>failed++)
        const user=await client.users.fetch(userId).catch(()=>null)
        if(user)await user.send({content:'You have been globally banned by ESN Guardian.\nReason: '+reason,allowedMentions:{parse:[]}}).catch(()=>{})
        return respond(interaction,'Global ban saved for '+userId+'. Banned in '+banned+' server(s); failed in '+failed+'.')
      }
      if (name === 'globalunban') {
        const userId=interaction.options.getString('user_id',true)
        if(!/^\d{15,22}$/.test(userId))return respond(interaction,'Provide a valid Discord user ID.')
        db.run('DELETE FROM global_bans WHERE user_id=?',BigInt(userId))
        let unbanned=0,failed=0
        for(const guild of client.guilds.cache.values())await guild.members.unban(userId,'ESN Guardian global ban removed').then(()=>unbanned++).catch(error=>{if(error?.code!==10026)failed++})
        const user=await client.users.fetch(userId).catch(()=>null)
        if(user)await user.send({content:'Your ESN Guardian global ban has been removed.',allowedMentions:{parse:[]}}).catch(()=>{})
        return respond(interaction,'Removed '+userId+' from the global-ban list. Unbanned in '+unbanned+' server(s); failed in '+failed+'.')
      }
      if (name === 'broadcast') {
        const message=interaction.options.getString('message',true);let delivered=0
        for(const guild of client.guilds.cache.values()){
          const cfg=db.setting(guild.id),channel=cfg.system_log_channel_id?guild.channels.cache.get(String(cfg.system_log_channel_id)):null
          if(channel?.isTextBased())await channel.send({content:message,allowedMentions:{parse:[]}}).then(()=>delivered++).catch(()=>{})
        }
        return respond(interaction,'Broadcast delivered to '+delivered+' configured system channels.')
      }
      if (name === 'maintenance') {
        const enabled=interaction.options.getBoolean('enabled',true);db.setStateEnabled('maintenance',enabled)
        const notice=enabled?'ESN Guardian maintenance has started. Normal server commands are temporarily unavailable.':'ESN Guardian maintenance has ended. Normal server commands are available again.'
        let delivered=0
        for(const userId of db.statusSubscriberIds('bot')){
          if(String(userId)===String(interaction.user.id))continue
          const user=await client.users.fetch(String(userId)).catch(()=>null)
          if(user)await user.send({content:notice,allowedMentions:{parse:[]}}).then(()=>delivered++).catch(()=>{})
        }
        return respond(interaction,'Maintenance mode '+(enabled?'enabled':'disabled')+'. Notified '+delivered+' bot-status subscriber(s). Use `/broadcast` to communicate the change in servers.')
      }
      if (name === 'blacklist') {
        const guildId=interaction.options.getString('guild_id',true),reason=interaction.options.getString('reason',true)
        if(!/^\d{15,22}$/.test(guildId))return respond(interaction,'Provide a valid server ID.')
        db.run('INSERT INTO guild_blacklist (guild_id,reason) VALUES (?,?) ON CONFLICT(guild_id) DO UPDATE SET reason=excluded.reason',BigInt(guildId),reason)
        const guild=client.guilds.cache.get(guildId)
        if(guild){
          const owner=await guild.fetchOwner().catch(()=>null)
          if(owner)await owner.send({content:'ESN Guardian has blacklisted **'+guild.name+'** ('+guild.id+') and will now leave the server.\nReason: '+reason,allowedMentions:{parse:[]}}).catch(()=>{})
          await guild.leave().catch(()=>{})
        }
        return respond(interaction,'Blacklisted server '+guildId+'.')
      }
      if (name === 'unblacklist') {
        const guildId=interaction.options.getString('guild_id',true)
        if(!/^\d+$/.test(guildId))return respond(interaction,'Provide a numeric server ID.')
        db.run('DELETE FROM guild_blacklist WHERE guild_id=?',BigInt(guildId))
        return respond(interaction,'Removed server `'+guildId+'` from the blacklist.')
      }
    }

    if (name === 'help') {
      const section = interaction.options.getString('section') || 'setup'
      return respond(interaction, HELP_GUIDES[section] || HELP_GUIDES.setup)
    }

    if (!await requireGuild(interaction, db, settings)) return

    if (name === 'verify') return doVerify(interaction, db)

    if (name === 'ticket') {
      await interaction.deferReply({ ephemeral: true })
      const subject = interaction.options.getString('subject', true)
      const guild = interaction.guild
      return withKeyLock(ticketLocks, guild.id, async () => {
        db.ensureGuild(guild.id)
        const cfg = db.get('SELECT support_role_id FROM ticket_config WHERE guild_id=?', BigInt(guild.id))
        const support = cfg?.support_role_id ? guild.roles.cache.get(String(cfg.support_role_id)) : null
        if (!support || support.id === guild.id || support.managed) return interaction.editReply('Staff must configure a support role with `/ticket-config` first.')
        const previous = db.get('SELECT * FROM tickets WHERE guild_id=? AND user_id=?', BigInt(guild.id), BigInt(interaction.user.id))
        if (previous?.channel_id) {
          const existing = await guild.channels.fetch(String(previous.channel_id)).catch(error => error?.code === 10003 ? null : undefined)
          if (existing) return interaction.editReply(`You already have a ticket: <#${previous.channel_id}>.`)
          if (existing === undefined) return interaction.editReply('I cannot check your existing ticket right now. Try again shortly.')
        }
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
        return interaction.editReply(`Ticket created: <#${channel.id}>. Use `/ticket-close` inside it when finished.`)
      })
    }

    if (name === 'ticket-close') {
      await interaction.deferReply({ ephemeral: true })
      return withKeyLock(ticketLocks, interaction.guildId, async () => {
        const row = db.get('SELECT * FROM tickets WHERE guild_id=? AND channel_id=?', BigInt(interaction.guildId), BigInt(interaction.channelId))
        if (!row) return interaction.editReply('Run this inside an active Guardian ticket.')
        const cfg = db.get('SELECT support_role_id FROM ticket_config WHERE guild_id=?', BigInt(interaction.guildId))
        const member = interaction.member
        const authorized = String(row.user_id) === interaction.user.id || isStaff(interaction) || (cfg?.support_role_id && member.roles.cache.has(String(cfg.support_role_id)))
        if (!authorized) return interaction.editReply('Only the ticket opener or support staff can close this ticket.')
        const openerId = String(row.user_id)
        const current = interaction.channel.permissionOverwrites.cache.get(openerId)
        const updated = {
          ViewChannel: current?.allow?.has(PermissionFlagsBits.ViewChannel) ? true : current?.deny?.has(PermissionFlagsBits.ViewChannel) ? false : null,
          SendMessages: false,
          ReadMessageHistory: current?.allow?.has(PermissionFlagsBits.ReadMessageHistory) ? true : current?.deny?.has(PermissionFlagsBits.ReadMessageHistory) ? false : null,
          SendMessagesInThreads: false,
          CreatePublicThreads: false,
          CreatePrivateThreads: false
        }
        const closed = await interaction.channel.permissionOverwrites
          .edit(openerId, updated, { reason: `Ticket closed by ${interaction.user.id}` })
          .then(() => interaction.channel.setName(`closed-${openerId}`, `Ticket closed by ${interaction.user.id}`))
          .then(() => true)
          .catch(() => false)
        if (!closed) return interaction.editReply('I could not close this ticket. Its active record has been kept so you can retry.')
        db.run('UPDATE tickets SET channel_id=NULL WHERE guild_id=? AND user_id=?', BigInt(interaction.guildId), BigInt(openerId))
        return interaction.editReply('Ticket closed. The channel remains private and its message history is preserved.')
      })
    }

    if (name === 'suggest') {
      if (interaction.channel?.type !== ChannelType.GuildText) return respond(interaction, 'Use this command in a text channel.')
      const suggestion=interaction.options.getString('suggestion',true)
      const message=await interaction.channel.send({embeds:[embed(suggestion,'Suggestion').setAuthor({name:interaction.user.tag,iconURL:interaction.user.displayAvatarURL()})],allowedMentions:{parse:[]}}).catch(()=>null)
      if(!message)return respond(interaction,'I could not post that suggestion. Check my channel permissions.')
      await message.react('👍').catch(()=>{})
      await message.react('👎').catch(()=>{})
      return respond(interaction,'Suggestion posted.')
    }

    const staffCommands = new Set([
      'warn','warnings','timeout','untimeout','kick','ban','unban','clear','slowmode','case','history','nickname','role','massrole',
      'lock','unlock','lockdown','unlockdown','panel','config','autorole','logs','smpannounce',
      'ticket-config','verification','guardian','security','antinuke','overwatch','resilience','sentinel'
    ])
    if (staffCommands.has(name) && !await requireStaff(interaction, db, settings)) return

    if (name === 'warn') {
      const member = interaction.options.getMember('member')
      const reason = interaction.options.getString('reason', true)
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
      const caseId = await moderationCase(db, interaction, member, 'WARN', reason)
      db.run('INSERT INTO warnings (case_id,guild_id,user_id) VALUES (?,?,?)', caseId, BigInt(interaction.guildId), BigInt(member.id))
      await logCase(db, interaction, caseId, member.user, 'WARN', reason)
      return respond(interaction, `Warned <@${member.id}>. Case #${caseId}.`)
    }

    if (name === 'warnings') {
      const member = interaction.options.getMember('member')
      const rows = db.all('SELECT c.case_id,c.reason,c.created_at FROM warnings w JOIN cases c ON c.case_id=w.case_id WHERE w.guild_id=? AND w.user_id=? AND w.active=1 ORDER BY c.case_id DESC', BigInt(interaction.guildId), BigInt(member.id))
      return respond(interaction, rows.length ? rows.map(r => `#${r.case_id} - ${r.reason} (${r.created_at})`).join('\n') : 'No active warnings.')
    }

    if (name === 'timeout' || name === 'untimeout' || name === 'kick' || name === 'ban') {
      if ((name==='timeout'||name==='untimeout') && !await requirePermission(interaction,PermissionFlagsBits.ModerateMembers)) return
      if (name==='kick' && !await requirePermission(interaction,PermissionFlagsBits.KickMembers)) return
      if (name==='ban' && !await requirePermission(interaction,PermissionFlagsBits.BanMembers)) return
      const member = interaction.options.getMember('member')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
      const reason = interaction.options.getString('reason') || (name === 'untimeout' ? 'Timeout removed' : 'No reason provided')
      const action = name.toUpperCase()
      const caseId = await moderationCase(db, interaction, member, action, reason)
      try {
        if (name === 'timeout') await member.timeout(interaction.options.getInteger('minutes', true) * 60000, `Case #${caseId}: ${reason}`)
        if (name === 'untimeout') await member.timeout(null, `Case #${caseId}: ${reason}`)
        if (name === 'kick') await member.kick(`Case #${caseId}: ${reason}`)
        if (name === 'ban') await member.ban({ reason: `Case #${caseId}: ${reason}`, deleteMessageSeconds: (interaction.options.getInteger('delete_message_days') || 0) * 86400 })
      } catch (error) {
        if (error?.code === 50013) return respond(interaction, 'I lack permission to perform that action.')
        return respond(interaction, 'Discord rejected the action. Please retry shortly.')
      }
      await logCase(db, interaction, caseId, member.user, action, reason)
      const success = {
        timeout: 'Timed out <@'+member.id+'>. Case #'+caseId+'.',
        untimeout: 'Removed timeout for <@'+member.id+'>. Case #'+caseId+'.',
        kick: 'Kicked <@'+member.id+'>. Case #'+caseId+'.',
        ban: 'Banned <@'+member.id+'>. Case #'+caseId+'.'
      }[name]
      return respond(interaction, success)
    }

    if (name === 'unban') {
      if (!await requirePermission(interaction,PermissionFlagsBits.BanMembers)) return
      const userId = interaction.options.getString('user_id', true)
      const reason = interaction.options.getString('reason') || 'Unbanned'
      if(!/^\d+$/.test(userId))return respond(interaction,'Provide a valid Discord user ID.')
      const user = await client.users.fetch(userId).catch(() => null)
      if (!user) return respond(interaction, 'Provide a valid Discord user ID.')
      const caseId = await moderationCase(db, interaction, user, 'UNBAN', reason)
      try{
        await interaction.guild.members.unban(userId, `Case #${caseId}: ${reason}`)
      }catch(error){
        if(error?.code===50013)return respond(interaction,'I lack permission to perform that action.')
        return respond(interaction,'Discord rejected the action. Please retry shortly.')
      }
      await logCase(db, interaction, caseId, user, 'UNBAN', reason)
      return respond(interaction, `Unbanned ${user.tag}. Case #${caseId}.`)
    }

    if (name === 'clear') {
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageMessages,'Manage Messages')) return
      if (!interaction.channel?.bulkDelete) return respond(interaction, 'This command requires a text channel.')
      await interaction.deferReply({ ephemeral: true })
      const amount = interaction.options.getInteger('amount', true)
      const deleted = await interaction.channel.bulkDelete(amount, true)
      const caseId = await moderationCase(db, interaction, null, 'CLEAR', `Deleted ${deleted.size} messages`)
      await logCase(db, interaction, caseId, null, 'CLEAR', `Deleted ${deleted.size} messages in <#${interaction.channelId}>`)
      return interaction.editReply(`Deleted ${deleted.size} messages. Case #${caseId}.`)
    }

    if (name === 'slowmode') {
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageChannels)) return
      const seconds = interaction.options.getInteger('seconds', true)
      if (interaction.channel?.type !== ChannelType.GuildText) return respond(interaction, 'This command requires a text channel.')
      const caseId = await moderationCase(db, interaction, null, 'SLOWMODE', `Set to ${seconds} seconds`)
      try{
        await interaction.channel.setRateLimitPerUser(seconds, `Case #${caseId}`)
      }catch(error){
        if(error?.code===50013)return respond(interaction,'I lack permission to perform that action.')
        return respond(interaction,'Discord rejected the action. Please retry shortly.')
      }
      await logCase(db, interaction, caseId, null, 'SLOWMODE', `Set to ${seconds} seconds`)
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
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageNicknames)) return
      const member = interaction.options.getMember('member')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
      const nickname = interaction.options.getString('nickname')
      const reason = interaction.options.getString('reason') || 'Nickname changed'
      const caseId = await moderationCase(db, interaction, member, 'NICKNAME', reason)
      try{
        await member.setNickname(nickname, `Case #${caseId}: ${reason}`)
      }catch(error){
        if(error?.code===50013)return respond(interaction,'I lack permission to perform that action.')
        return respond(interaction,'Discord rejected the action. Please retry shortly.')
      }
      await logCase(db, interaction, caseId, member.user, 'NICKNAME', reason)
      return respond(interaction, `Updated nickname. Case #${caseId}.`)
    }

    if (name === 'role') {
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageRoles)) return
      const member = interaction.options.getMember('member')
      const role = interaction.options.getRole('role')
      if (!safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'That role is privileged, managed, or above the allowed role hierarchy.')
      if (!memberManageable(interaction.guild, interaction.member, member)) return respond(interaction, 'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
      const remove = interaction.options.getBoolean('remove') || false
      const reason = interaction.options.getString('reason') || 'Role updated'
      const caseId = await moderationCase(db, interaction, member, remove ? 'ROLE_REMOVE' : 'ROLE_ADD', reason)
      try{
        await (remove ? member.roles.remove(role, `Case #${caseId}: ${reason}`) : member.roles.add(role, `Case #${caseId}: ${reason}`))
      }catch(error){
        if(error?.code===50013)return respond(interaction,'I lack permission to perform that action.')
        return respond(interaction,'Discord rejected the action. Please retry shortly.')
      }
      await logCase(db, interaction, caseId, member.user, 'ROLE', reason)
      return respond(interaction, `Role updated for <@${member.id}>. Case #${caseId}.`)
    }

    if (name === 'massrole') {
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageRoles,'Manage Roles')) return
      const role = interaction.options.getRole('role')
      if (!safeRole(interaction.guild, interaction.member, role)) return respond(interaction, 'That role is privileged, managed, or above the allowed role hierarchy.')
      const remove = interaction.options.getBoolean('remove') || false
      const includeBots = interaction.options.getBoolean('include_bots') || false
      await interaction.deferReply({ ephemeral: true })
      let changed = 0
      for (const member of interaction.guild.members.cache.values()) {
        if (member.user.bot && !includeBots) continue
        if (!memberManageable(interaction.guild, interaction.member, member)) continue
        await (remove ? member.roles.remove(role, `Mass role by ${interaction.user.tag}`) : member.roles.add(role, `Mass role by ${interaction.user.tag}`)).then(() => changed++).catch(() => {})
      }
      const summary = `${remove ? 'Removed' : 'Added'} ${role.name} for ${changed} members`
      const caseId = await moderationCase(db, interaction, null, 'MASSROLE', summary)
      await logCase(db, interaction, caseId, null, 'MASSROLE', `${remove ? 'Removed' : 'Added'} <@&${role.id}> for ${changed} members`)
      return interaction.editReply(`Updated ${changed} members. Case #${caseId}.`)
    }

    if (name === 'lock' || name === 'unlock') {
      if (interaction.channel?.type !== ChannelType.GuildText) return respond(interaction, 'This command requires a text channel.')
      const reason = interaction.options.getString('reason') || (name === 'lock' ? 'Channel locked' : 'Channel unlocked')
      const ok = await interaction.channel.permissionOverwrites
        .edit(interaction.guild.roles.everyone, { SendMessages: name === 'lock' ? false : null }, { reason })
        .then(() => true).catch(() => false)
      if (!ok) return respond(interaction, 'I could not '+name+' this channel.')
      const caseId = await securityCase(db, interaction.guild, null, name === 'lock' ? 'CHANNEL_LOCK' : 'CHANNEL_UNLOCK', reason, interaction.channelId)
      return respond(interaction, `Channel ${name === 'lock' ? 'locked' : 'unlocked'}. Case #${caseId}.`)
    }

    if (name === 'lockdown') {
      if (!interaction.deferred && !interaction.replied) await interaction.deferReply({ ephemeral: true })
      const changed = await lockdownGuild(db, interaction.guild, interaction.options.getString('reason') || 'Manual lockdown')
      return respond(interaction, changed ? 'Lockdown enabled.' : 'Lockdown is already active.')
    }
    if (name === 'unlockdown') {
      if (!interaction.deferred && !interaction.replied) await interaction.deferReply({ ephemeral: true })
      const changed = await unlockdownGuild(db, interaction.guild, interaction.options.getString('reason') || 'Manual lockdown release')
      return respond(interaction, `Restored ${changed} channels.`)
    }

    if (name === 'panel') {
      if (interaction.channel?.type !== ChannelType.GuildText) return respond(interaction, 'This command requires a text channel.')
      try {
        await client.guardianCommunity?.postPanel(interaction)
        return respond(interaction,'Control panel posted.')
      } catch {
        return respond(interaction,'I could not post the control panel in this channel.')
      }
    }

    if (name === 'config') {
      const sections=['Server settings']
      const settingsRow=db.setting(interaction.guildId)
      for(const [key,value] of Object.entries(settingsRow))if(!['guild_id','ad_enabled','ad_channel_id','created_at','updated_at'].includes(key))sections.push(key.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase()) + ': ' + (value==null?'Not set':String(value)))
      for(const [table,label] of [['security_config','AutoMod'],['anti_nuke_config','Anti-nuke'],['raid_config','Raid'],['verification_config','Verification'],['ticket_config','Tickets']]){
        const row=db.get('SELECT * FROM '+table+' WHERE guild_id=?',BigInt(interaction.guildId))
        sections.push('\n'+label)
        for(const [key,value] of Object.entries(row||{}))if(key!=='guild_id')sections.push(key.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase()) + ': ' + (value==null?'Not set':String(value)))
      }
      let output=sections.join('\n')
      while(output.length>3900){
        let split=output.lastIndexOf('\n',3900);if(split<=0)split=3900
        await respond(interaction,output.slice(0,split))
        output=output.slice(split).replace(/^\n/,'')
      }
      return respond(interaction,output)
    }

    if (name === 'welcome' || name === 'goodbye') {
      if (!isGuildOwner(interaction)) return accessDenied(interaction)
      const channel=interaction.options.getChannel('channel',true)
      db.updateSetting(interaction.guildId,name==='welcome'?'welcome_channel_id':'goodbye_channel_id',channel.id)
      const isWelcome=name==='welcome'
      const title=isWelcome?'Join notices configured':'Leave notices configured'
      const description='Future '+(isWelcome?'joins':'leaves')+' will include the member\'s user ID, account and server timestamps, names, roles, status, and available membership flags.'
      const sent=await channel.send({embeds:[embed(description,title)],allowedMentions:{parse:[]}}).then(()=>true).catch(()=>false)
      if(!sent)return respond(interaction,(isWelcome?'Join':'Leave')+' notice channel was saved, but I could not post a test entry. Check my View Channel and Send Messages permissions.')
      return respond(interaction,'Detailed '+(isWelcome?'join':'leave')+' notices will go to <#'+channel.id+'>.')
    }

    if (name === 'autorole') {
      const role = interaction.options.getRole('role')
      if (role && (!safeRole(interaction.guild, interaction.member, role) || dangerousRole(role))) return respond(interaction, 'Autoroles must be non-privileged roles below the allowed hierarchy.')
      db.updateSetting(interaction.guildId, 'autorole_id', role?.id || null)
      return respond(interaction, role ? 'Autorole updated.' : 'Autorole disabled.')
    }

    if (name === 'logs') {
      const category = interaction.options.getString('category', true)
      const label = category.replace(/^./, char => char.toUpperCase())
      const channel = interaction.options.getChannel('channel', true)
      const field = LOG_FIELDS[category]
      db.updateSetting(interaction.guildId, field, channel.id)

      const sent = await channel.send({
        embeds: [embed('ESN Guardian can write to this log channel.', label + ' logging configured')],
        allowedMentions: { parse: [] }
      }).then(() => true).catch(error => {
        console.error('[Guardian] log configuration test failed', { guild: interaction.guildId, category, channel: channel.id, error: error?.message || String(error) })
        return false
      })
      if (!sent) return respond(interaction, label + ' logs were saved, but I could not post a test entry. Check my View Channel and Send Messages permissions.')
      return respond(interaction, label + ' logs will go to <#' + channel.id + '>. Test entry posted.')
    }

    if (name === 'smpannounce') {
      if (!await requirePermission(interaction, PermissionFlagsBits.ManageMessages)) return
      const channel = interaction.options.getChannel('channel', true)
      const message = interaction.options.getString('message', true)
      if (channel.guildId !== interaction.guildId || !channel.permissionsFor(interaction.member)?.has(PermissionFlagsBits.SendMessages)) {
        return respond(interaction, 'Choose a channel in this server where you can send messages.')
      }
      if (!interaction.deferred && !interaction.replied) await interaction.deferReply({ ephemeral: true })
      return withKeyLock(announcementLocks, interaction.guildId, async () => {
        const cfg = db.setting(interaction.guildId)
        const now = Date.now()
        const last = cfg.ad_last_sent_at ? Date.parse(String(cfg.ad_last_sent_at)) : 0
        const cooldown = Number(cfg.ad_cooldown_seconds || 3600) * 1000
        if (last && now - last < cooldown) {
          return respond(interaction, 'Wait ' + (Math.floor((cooldown - (now - last)) / 1000) + 1) + ' seconds before the next announcement.')
        }
        const sent = await channel.send({ content: message, allowedMentions: { parse: [] } }).then(() => true).catch(() => false)
        if (!sent) return respond(interaction, 'I could not send the announcement. Check my channel permissions.')
        db.updateSetting(interaction.guildId, 'ad_last_sent_at', new Date(now).toISOString())
        return respond(interaction, 'Announcement sent.')
      })
    }

    if (name === 'ticket-config') {
      if (!await requirePermission(interaction,PermissionFlagsBits.ManageRoles,'Manage Roles')) return
      const role = interaction.options.getRole('support_role', true)
      if (role.id === interaction.guildId || role.managed || (interaction.user.id !== interaction.guild.ownerId && role.comparePositionTo(interaction.member.roles.highest) >= 0)) return respond(interaction, 'Choose an unmanaged support role below your role, other than @everyone.')
      db.run('UPDATE ticket_config SET support_role_id=? WHERE guild_id=?', BigInt(role.id), BigInt(interaction.guildId))
      return respond(interaction, 'Support role saved. This applies to new tickets; existing ticket access is unchanged.')
    }

    if (name === 'verification') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'setup') {
        const channel = interaction.options.getChannel('channel', true)
        const verified = interaction.options.getRole('verified_role', true)
        const unverified = interaction.options.getRole('unverified_role')
        const minDays = interaction.options.getInteger('minimum_account_age_days') || 0
        if (
          !verificationRoleAllowedForStaff(interaction.guild, interaction.member, verified) ||
          (unverified && !verificationRoleAllowedForStaff(interaction.guild, interaction.member, unverified)) ||
          unverified?.id === verified.id
        ) {
          return respond(interaction, 'Choose distinct, non-privileged, unmanaged roles below your role and my role.')
        }

        let message
        try {
          message = await channel.send({
            embeds: [embed('Press **VERIFY** to complete verification.', 'ESN Guardian Verification')],
            components: [{ type: 1, components: [{ type: 2, style: 3, label: 'VERIFY', emoji: { name: '✅' }, custom_id: 'esn_guardian:verify' }] }],
            allowedMentions: { parse: [] }
          })
        } catch (error) {
          console.error('[Guardian] could not post verification panel', {
            guild: interaction.guildId,
            channel: channel.id,
            error: error?.message || String(error)
          })
          return respond(interaction, 'I could not post in that channel.')
        }

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
        return respond(interaction, `Enabled: ${Number(cfg.enabled) ? 'yes' : 'no'}\nChannel: ${channelMention(cfg.channel_id)}\nVerified role: ${roleMention(cfg.verified_role_id)}\nMinimum account age: ${Number(cfg.min_account_age_days || 0)} days`)
      }
    }

    if (name === 'guardian') {
      const sub=interaction.options.getSubcommand()
      if (['snapshot','approve-bot','unapprove-bot','panic'].includes(sub) && !isGuildOwner(interaction)) return respond(interaction,'Only the Discord server owner can use this Guardian control.',true,'Access denied')
      if (sub==='snapshot') {
        await saveSnapshot(db,interaction.guild,true)
        return respond(interaction,'Guardian recovery snapshot saved. Current bots, webhooks, and integrations are now the trusted baseline.')
      }
      if (sub==='approve-bot'||sub==='unapprove-bot') {
        const botId=interaction.options.getString('bot_id',true)
        if(!/^\d{15,22}$/.test(botId))return respond(interaction,'Provide a numeric Discord bot/application ID.')
        if(sub==='approve-bot')db.insertApprovedBot(interaction.guildId,botId,interaction.user.id)
        else db.run('DELETE FROM approved_bots WHERE guild_id=? AND bot_id=?',BigInt(interaction.guildId),BigInt(botId))
        return respond(interaction,(sub==='approve-bot'?'Approved bot/application ID ':'Removed bot/application ID ')+botId+(sub==='approve-bot'?'.':' from the approval list.'))
      }
      if (sub==='panic') {
        const enabled=interaction.options.getBoolean('enabled')??true
        const result=await panicGuild(db,interaction.guild,enabled)
        if(enabled)return respond(interaction,'PANIC enabled. External-app locks changed '+result.externalChanged+' permission entries ('+result.externalFailed+' failed); removed '+result.botsRemoved+' unapproved bots, '+result.webhooksRemoved+' webhooks, and '+result.integrationsRemoved+' integrations.')
        return respond(interaction,'PANIC released. Core protections remain enabled.')
      }
      if (sub==='audit') {
        const a=await securityAudit(db,interaction.guild)
        return respond(interaction,'Guardian Security Scoreboard\nScore: '+a.score+'/100\nMissing Guardian permissions: '+(a.missing.join(', ')||'none')+'\nHigh-risk roles: '+a.riskyRoles+'\nUnapproved bots: '+(a.unapprovedBots.slice(0,10).join(', ')||'none')+'\nRoles still allowing external apps: '+a.externalEnabled+'\nCurrent webhooks: '+a.webhookCount+'\nRollback: '+(Number(a.guardian?.rollback_enabled)?'ON':'OFF')+'\nWebhook guard: '+(Number(a.guardian?.webhook_guard)?'ON':'OFF')+'\nIntegration guard: '+(Number(a.guardian?.integration_guard)?'ON':'OFF')+'\nCredential leak guard: '+(Number(a.guardian?.credential_guard)?'ON':'OFF'))
      }
      if (sub==='status') {
        const cfg=db.get('SELECT * FROM guardian_config WHERE guild_id=?',BigInt(interaction.guildId))
        const bots=db.get('SELECT COUNT(*) AS count FROM approved_bots WHERE guild_id=?',BigInt(interaction.guildId))
        const snap=db.get('SELECT created_at FROM guardian_snapshots WHERE guild_id=?',BigInt(interaction.guildId))
        return respond(interaction,'External-app lock: '+(Number(cfg.external_app_lock)?'ON':'OFF')+'\nBot approval: '+(Number(cfg.bot_approval)?'ON':'OFF')+'\nWebhook guard: '+(Number(cfg.webhook_guard)?'ON':'OFF')+'\nIntegration guard: '+(Number(cfg.integration_guard)?'ON':'OFF')+'\nCredential leak guard: '+(Number(cfg.credential_guard)?'ON':'OFF')+'\nAutomatic rollback: '+(Number(cfg.rollback_enabled)?'ON':'OFF')+'\nPANIC: '+(Number(cfg.panic_mode)?'ACTIVE':'inactive')+'\nApproved bots: '+Number(bots?.count||0)+'\nLast snapshot: '+(snap?.created_at||'none'))
      }
    }

    if (name === 'security') {
      const sub = interaction.options.getSubcommand()
      if (sub === 'harden') {
        if (!isGuildOwner(interaction)) return accessDenied(interaction)
        const r = await hardenGuild(db, interaction.guild)
        return respond(interaction, `Secure baseline applied with advanced protection. External-app permission entries changed: ${r.rolesChanged}; failed: ${r.failed}. Current bots, webhooks, and integrations were saved as the trusted baseline.`)
      }
      if (sub === 'status') {
        const c = db.get('SELECT * FROM security_config WHERE guild_id=?', BigInt(interaction.guildId))
        const a = db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?', BigInt(interaction.guildId))
        return respond(interaction, `AutoMod: ${Number(c.automod_enabled) ? 'enabled' : 'disabled'}\nFlood: ${c.flood_limit} messages / ${c.flood_window_seconds}s\nMentions: ${c.max_mentions}\nCaps: ${c.caps_percentage}%\nInvite blocking: ${Number(c.block_invites) ? 'enabled' : 'disabled'}\nStrict links: ${Number(c.strict_links) ? 'enabled' : 'disabled'}\nAnti-nuke: ${Number(a.enabled) ? 'enabled' : 'disabled'}`)
      }
      if (sub === 'scan') {
        const botMember=interaction.guild.members.me
        if(!botMember)return respond(interaction,'I cannot inspect my server member record yet. Retry shortly.')
        const required=[
          ['view audit log',PermissionFlagsBits.ViewAuditLog],['manage messages',PermissionFlagsBits.ManageMessages],
          ['moderate members',PermissionFlagsBits.ModerateMembers],['kick members',PermissionFlagsBits.KickMembers],
          ['ban members',PermissionFlagsBits.BanMembers],['manage roles',PermissionFlagsBits.ManageRoles],
          ['manage channels',PermissionFlagsBits.ManageChannels],['manage webhooks',PermissionFlagsBits.ManageWebhooks]
        ]
        const missing=required.filter(([,bit])=>!botMember.permissions.has(bit)).map(([name])=>name)
        const manageable=interaction.guild.roles.cache.filter(role=>!role.managed&&role.comparePositionTo(botMember.roles.highest)<0).size
        const riskyAbove=interaction.guild.roles.cache.filter(role=>!role.managed&&role.comparePositionTo(botMember.roles.highest)>0&&dangerousRole(role)).map(role=>role.name)
        return respond(interaction,'Security scan\nMissing permissions: '+(missing.join(', ')||'none')+'\nRoles below bot: '+manageable+'\nBot top role: '+botMember.roles.highest.name+'\nHigh-risk roles above bot: '+(riskyAbove.slice(0,10).join(', ')||'none')+'\nAudit attribution: '+(missing.includes('view audit log')?'unavailable':'ready'))
      }
      if (sub === 'cases') {
        const limit = interaction.options.getInteger('limit') || 10
        const rows = db.all("SELECT case_id,action,reason,created_at FROM cases WHERE guild_id=? AND (action LIKE 'AUTOMOD_%' OR action LIKE 'ANTINUKE_%' OR action IN ('LOCKDOWN','UNLOCKDOWN','SUSPICIOUS_JOIN','WEBHOOK_CHANGE','CHANNEL_DELETE','ROLE_DELETE','ROLE_PERMISSION_CHANGE','QUARANTINE','QUARANTINE_RELEASE')) ORDER BY case_id DESC LIMIT ?", BigInt(interaction.guildId), limit)
        return respond(interaction, rows.length ? rows.map(r => `#${r.case_id} ${r.action}: ${r.reason}`).join('\n') : 'No security cases found.')
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
        const blockInvites=interaction.options.getBoolean('block_invites',true)
        const strictLinks=interaction.options.getBoolean('strict_links',true)
        db.run('UPDATE security_config SET block_invites=?,strict_links=? WHERE guild_id=?',blockInvites?1:0,strictLinks?1:0,BigInt(interaction.guildId))
        return respond(interaction,'Invite blocking: '+(blockInvites?'enabled':'disabled')+'; strict link allowlisting: '+(strictLinks?'enabled':'disabled')+'.')
      }
      if (sub === 'allow-domain' || sub === 'remove-domain') {
        const domain=interaction.options.getString('domain',true).toLowerCase().trim().replace(/^https?:\/\//,'').split('/',1)[0]
        if(sub==='allow-domain'&&(!domain||!domain.includes('.')||domain.includes(' ')))return respond(interaction,'Provide a valid domain, such as `example.com`.')
        if(sub==='allow-domain'){
          db.run('INSERT OR IGNORE INTO allowed_domains (guild_id,domain) VALUES (?,?)',BigInt(interaction.guildId),domain)
          return respond(interaction,'Allowed `'+domain+'` and its subdomains in strict link mode.')
        }
        db.run('DELETE FROM allowed_domains WHERE guild_id=? AND domain=?',BigInt(interaction.guildId),domain)
        return respond(interaction,'Removed `'+domain+'` from the strict link allowlist.')
      }
      if (sub === 'add-word' || sub === 'remove-word') {
        const word=interaction.options.getString('word',true).toLowerCase().trim()
        if(sub==='add-word'&&(word.length<2||word.length>100))return respond(interaction,'Blocked text must be between 2 and 100 characters.')
        if(sub==='add-word'){
          db.run('INSERT OR IGNORE INTO bad_words (guild_id,word) VALUES (?,?)',BigInt(interaction.guildId),word)
          return respond(interaction,'Blocked word or phrase added.')
        }
        db.run('DELETE FROM bad_words WHERE guild_id=? AND word=?',BigInt(interaction.guildId),word)
        return respond(interaction,'Blocked word or phrase removed.')
      }
      if (sub === 'words') {
        const rows=db.all('SELECT word FROM bad_words WHERE guild_id=? ORDER BY word LIMIT 50',BigInt(interaction.guildId))
        return respond(interaction,rows.length?rows.map(row=>'- '+row.word).join('\n'):'No blocked words or phrases are configured.')
      }
      if (sub === 'domains') {
        const rows=db.all('SELECT domain FROM allowed_domains WHERE guild_id=? ORDER BY domain LIMIT 50',BigInt(interaction.guildId))
        return respond(interaction,rows.length?rows.map(row=>'- '+row.domain).join('\n'):'No domains are allowlisted.')
      }
      if (sub === 'trusted') {
        const rows=db.all('SELECT user_id FROM anti_nuke_trusted_users WHERE guild_id=? ORDER BY created_at LIMIT 50',BigInt(interaction.guildId))
        return respond(interaction,rows.length?rows.map(row=>'- <@'+row.user_id+'>').join('\n'):'No users are trusted by anti-nuke.')
      }
      if (sub === 'check-link') {
        const value=interaction.options.getString('url',true)
        let host=null
        try{host=new URL(value.includes('://')?value:'https://'+value).hostname.toLowerCase()}catch{}
        if(!host)return respond(interaction,'Provide a valid URL or domain.')
        const cfg=db.get('SELECT strict_links FROM security_config WHERE guild_id=?',BigInt(interaction.guildId))
        const allowed=db.all('SELECT domain FROM allowed_domains WHERE guild_id=?',BigInt(interaction.guildId)).map(row=>String(row.domain))
        const permitted=!cfg||!Number(cfg.strict_links)||allowed.some(base=>host===base||host.endsWith('.'+base))
        return respond(interaction,'`'+host+'` would be '+(permitted?'allowed':'blocked')+' by the current link policy.')
      }
      if (sub === 'reset-automod') {
        db.run('UPDATE security_config SET automod_enabled=1,flood_limit=6,flood_window_seconds=10,max_mentions=6,caps_percentage=80,block_invites=1,strict_links=0 WHERE guild_id=?',BigInt(interaction.guildId))
        return respond(interaction,'AutoMod defaults restored. Existing blocked words and allowed domains were retained.')
      }
      if (sub === 'raid') {
        const role=interaction.options.getRole('quarantine_role')
        const me=interaction.guild.members.me
        if(role&&(role.id===interaction.guildId||role.managed||!me||role.comparePositionTo(me.roles.highest)>=0||dangerousRole(role)))return respond(interaction,'The quarantine role must be below my highest role.')
        db.run('UPDATE raid_config SET enabled=?,join_limit=?,join_window_seconds=?,min_account_age_days=?,quarantine_role_id=? WHERE guild_id=?',
          interaction.options.getBoolean('enabled',true)?1:0,
          interaction.options.getInteger('join_limit',true),
          interaction.options.getInteger('join_window_seconds',true),
          interaction.options.getInteger('minimum_account_age_days',true),
          role?BigInt(role.id):null,
          BigInt(interaction.guildId))
        return respond(interaction,'Raid detection and containment policy updated.')
      }
      if (sub === 'raid-status') {
        const r=db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(interaction.guildId))
        const stats=client.guardianSecurity?.raidStats?.(interaction.guildId)||{}
        const fastLimit=Math.max(3,Math.min(Number(r.join_limit),Math.floor((Number(r.join_limit)+1)/2)))
        return respond(interaction,'**Guardian Raid Engine v3**\nEnabled: '+(Number(r.enabled)?'yes':'no')+'\nContainment: '+(stats.active?'ACTIVE':'inactive')+'\nActive until: '+(stats.active&&stats.until?new Date(stats.until).toISOString():'n/a')+'\nConfigured threshold: '+r.join_limit+' joins / '+r.join_window_seconds+'s\nFast-burst threshold: '+fastLimit+' joins / 5s\nYoung-account burst: 3 accounts / 15s when account-age checks are enabled\nMinimum account age: '+r.min_account_age_days+' days\nKick workers: 5\nKick queue: '+(stats.queueDepth||0)+'/4096\nBlocked this runtime: '+(stats.blocked||0)+'\nRaid triggers this runtime: '+(stats.triggers||0)+'\nQuarantine role: '+(r.quarantine_role_id?'<@&'+r.quarantine_role_id+'>':'not configured'))
      }
      if (sub === 'quarantine') {
        const member=interaction.options.getMember('member')
        if(!memberManageable(interaction.guild,interaction.member,member))return respond(interaction,'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
        const reason=interaction.options.getString('reason')||'Manual security review'
        const ok=await quarantineMember(db,member,reason,interaction.user.id)
        return respond(interaction,ok?'Quarantined <@'+member.id+'>.':'I could not quarantine that member. Configure a role below my highest role with `/security raid`.')
      }
      if (sub === 'release') {
        const member=interaction.options.getMember('member')
        if(!memberManageable(interaction.guild,interaction.member,member))return respond(interaction,'You cannot act on yourself, the owner, the bot, or a member at or above your role or my role.')
        const reason=interaction.options.getString('reason')||'Security review completed'
        const r=db.get('SELECT quarantine_role_id FROM raid_config WHERE guild_id=?',BigInt(interaction.guildId))
        const role=r?.quarantine_role_id?interaction.guild.roles.cache.get(String(r.quarantine_role_id)):null
        if(!role||!member.roles.cache.has(role.id))return respond(interaction,'That member is not assigned the configured quarantine role.')
        const removed=await member.roles.remove(role,reason).then(()=>true).catch(()=>false)
        if(!removed)return respond(interaction,'I could not remove that quarantine role.')
        const caseId=db.createCase(interaction.guildId,member.id,interaction.user.id,'QUARANTINE_RELEASE',reason,interaction.channelId)
        await logEvent(db,interaction.guild,'security_log_channel_id','Security: QUARANTINE_RELEASE | Case #'+caseId,'Target: <@'+member.id+'>\nModerator: <@'+interaction.user.id+'>\nReason: '+reason)
        return respond(interaction,'Released <@'+member.id+'>. Case #'+caseId+'.')
      }
      if (sub === 'member') {
        const member=interaction.options.getMember('member')
        const count=db.get('SELECT COUNT(*) AS count FROM cases WHERE guild_id=? AND target_id=?',BigInt(interaction.guildId),BigInt(member.id))
        const risky=member.roles.cache.filter(role=>dangerousRole(role)).map(role=>role.name)
        const age=Math.floor((Date.now()-member.user.createdTimestamp)/86400000)
        return respond(interaction,'Member: <@'+member.id+'> ('+member.id+')\nAccount age: '+age+' days\nSecurity and moderation cases: '+Number(count?.count||0)+'\nHigh-risk roles: '+(risky.join(', ')||'none'))
      }
    }

    if (name === 'antinuke') {
      const sub = interaction.options.getSubcommand()
      if (['setup','enable','disable','trust','untrust'].includes(sub) && !isGuildOwner(interaction)) return respond(interaction, 'Only the Discord server owner can change this anti-nuke control.', true, 'Access denied')
      if (sub === 'setup') {
        const limit=interaction.options.getInteger('action_limit')||3
        const window=interaction.options.getInteger('window_seconds')||15
        db.run('UPDATE anti_nuke_config SET enabled=1,action_limit=?,window_seconds=? WHERE guild_id=?',limit,window,BigInt(interaction.guildId))
        return respond(interaction,'Anti-nuke enabled: non-trusted actors are banned after '+limit+' destructive actions in '+window+' seconds.')
      }
      if (sub === 'enable' || sub === 'disable') {
        db.run('UPDATE anti_nuke_config SET enabled=? WHERE guild_id=?', sub === 'enable' ? 1 : 0, BigInt(interaction.guildId))
        return respond(interaction, `Anti-nuke ${sub === 'enable' ? 'enabled' : 'disabled'}.`)
      }
      if (sub === 'status') {
        const r=db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(interaction.guildId))
        const trusted=db.get('SELECT COUNT(*) AS count FROM anti_nuke_trusted_users WHERE guild_id=?',BigInt(interaction.guildId))
        return respond(interaction,'Enabled: '+(Number(r.enabled)?'yes':'no')+'\nThreshold: '+r.action_limit+' destructive actions in '+r.window_seconds+' seconds\nTrusted users: '+trusted.count+'\nRequires: View Audit Log, Ban Members, Manage Channels')
      }
      if (sub === 'trust' || sub === 'untrust') {
        const user=interaction.options.getUser('user',true)
        if(sub==='trust'){
          db.run('INSERT OR REPLACE INTO anti_nuke_trusted_users (guild_id,user_id,added_by_id) VALUES (?,?,?)',BigInt(interaction.guildId),BigInt(user.id),BigInt(interaction.user.id))
          return respond(interaction,'Trusted <@'+user.id+'> for anti-nuke protection.')
        }
        db.run('DELETE FROM anti_nuke_trusted_users WHERE guild_id=? AND user_id=?',BigInt(interaction.guildId),BigInt(user.id))
        return respond(interaction,'Removed anti-nuke trust for <@'+user.id+'>.')
      }
    }

    if (name === 'overwatch') {
      const sub=interaction.options.getSubcommand(),over=client.guardianOverwatch
      if(!over)return respond(interaction,'Guardian Overwatch is not ready yet.')
      if(sub==='status')return respond(interaction,over.postureReport(interaction.guild))
      if(sub==='integrity')return respond(interaction,over.integrityReport(interaction.guild))
      if(sub==='incidents')return respond(interaction,over.incidentReport(interaction.guildId))
      if(sub==='seal'){
        if(!isGuildOwner(interaction))return respond(interaction,'Only the Discord server owner can seal the security policy baseline.',true,'Access denied')
        const fp=over.sealPolicy(interaction.guild)
        return respond(interaction,'Security policy baseline sealed. Fingerprint: '+fp)
      }
      if(sub==='backup'){
        if(!isGuildOwner(interaction))return respond(interaction,'Only the Discord server owner can create an incident backup.',true,'Access denied')
        const file=db.backup('incident')
        return respond(interaction,file?'Verified incident backup created: '+require('node:path').basename(file):'Backup could not be created.')
      }
    }

    if (name === 'resilience') {
      const sub=interaction.options.getSubcommand(),res=client.guardianResilience
      if(!res)return respond(interaction,'Guardian Resilience is not ready yet.')
      if(sub==='status')return respond(interaction,res.statusReport(interaction.guild))
      if(sub==='drill')return respond(interaction,res.drillReport(interaction.guild))
      if(sub==='recovery-plan')return respond(interaction,res.recoveryPlan(interaction.guild))
    }

    if (name === 'sentinel') {
      const sub=interaction.options.getSubcommand(),sentinel=client.guardianSentinel
      if(!sentinel)return respond(interaction,'Guardian Sentinel is not ready yet.')
      if(sub==='status')return respond(interaction,sentinel.liveReport(interaction.guild))
      if(sub==='signals')return respond(interaction,sentinel.signalsReport(interaction.guildId,8))
      if(sub==='subject'){
        const subject=interaction.options.getString('subject_id',true)
        if(!/^\d+$/.test(subject))return respond(interaction,'Provide a numeric subject ID.')
        return respond(interaction,sentinel.subjectReport(interaction.guild,subject))
      }
      if(sub==='explain'){
        const signalId=interaction.options.getInteger('signal_id',true)
        return respond(interaction,sentinel.explainSignal(interaction.guildId,signalId)||'Signal not found.')
      }
    }
  } catch (error) {
    interaction.guardianCommandFailed = true
    console.error(`[Guardian] command /${name} failed`, error)
    await respond(interaction, 'The command failed safely. Staff can check the system log.', true, 'Command unavailable').catch(() => {})
  }
}

module.exports = {
  definitions,
  asJson,
  registerGuild,
  handleCommand,
  handleButton
}
