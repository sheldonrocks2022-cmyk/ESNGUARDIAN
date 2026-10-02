'use strict'

const {
  EmbedBuilder,
  PermissionFlagsBits,
  ChannelType
} = require('discord.js')

const BRAND = 0x0B3D91
const FOOTER = 'Protected by ESN Guardian'
const HIGH_RISK_PERMISSIONS = [
  PermissionFlagsBits.Administrator,
  PermissionFlagsBits.ManageGuild,
  PermissionFlagsBits.ManageRoles,
  PermissionFlagsBits.ManageChannels,
  PermissionFlagsBits.ManageWebhooks,
  PermissionFlagsBits.BanMembers,
  PermissionFlagsBits.KickMembers,
  PermissionFlagsBits.ModerateMembers
]

function embed(content, title = 'ESN Guardian') {
  return new EmbedBuilder()
    .setTitle(title)
    .setDescription(String(content || '').slice(0, 4096))
    .setColor(BRAND)
    .setTimestamp()
    .setFooter({ text: FOOTER })
}

async function respond(interaction, content, ephemeral = true, title = 'ESN Guardian') {
  const payload = { embeds: [embed(content, title)], ephemeral }
  if (interaction.deferred || interaction.replied) return interaction.followUp(payload)
  return interaction.reply(payload)
}

function isStaff(interaction) {
  return Boolean(interaction.inGuild() && interaction.memberPermissions?.has(PermissionFlagsBits.ManageGuild))
}

function isGuildOwner(interaction) {
  return Boolean(interaction.inGuild() && interaction.guild.ownerId === interaction.user.id)
}

function isBotOwner(interaction, settings) {
  return Boolean(settings.ownerId && String(interaction.user.id) === String(settings.ownerId))
}

function memberManageable(guild, actor, target) {
  const me = guild.members.me
  if (!me || !actor || !target) return false
  if (target.id === guild.ownerId || target.id === actor.id || target.id === me.id) return false
  if (!target.manageable) return false
  if (actor.id !== guild.ownerId && target.roles.highest.comparePositionTo(actor.roles.highest) >= 0) return false
  return true
}

function safeRole(guild, actor, role) {
  const me = guild.members.me
  if (!me || !role || role.id === guild.id || role.managed) return false
  if (role.comparePositionTo(me.roles.highest) >= 0) return false
  if (actor?.id !== guild.ownerId && role.comparePositionTo(actor.roles.highest) >= 0) return false
  if (actor?.id !== guild.ownerId && HIGH_RISK_PERMISSIONS.some(bit => role.permissions.has(bit))) return false
  return true
}

async function logEvent(db, guild, field, title, description) {
  const settings = db.setting(guild.id)
  const channelId = settings?.[field]
  if (!channelId) return
  const channel = guild.channels.cache.get(String(channelId))
  if (!channel || !channel.isTextBased?.()) return
  try {
    await channel.send({ embeds: [embed(description, title)], allowedMentions: { parse: [] } })
  } catch {}
}

async function auditActor(guild, type, targetId) {
  await new Promise(resolve => setTimeout(resolve, 900))
  try {
    const logs = await guild.fetchAuditLogs({ type, limit: 6 })
    const recent = Date.now() - 90_000
    const entry = logs.entries.find(item =>
      item.createdTimestamp >= recent &&
      (!targetId || String(item.targetId || item.target?.id || '') === String(targetId))
    )
    return entry?.executor || null
  } catch {
    return null
  }
}

function normalizeDomain(input) {
  try {
    const raw = /^https?:\/\//i.test(input) ? input : `https://${input}`
    return new URL(raw).hostname.toLowerCase().replace(/^www\./, '')
  } catch {
    return null
  }
}

function extractDomains(text) {
  const urls = String(text || '').match(/https?:\/\/[^\s<>()]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>()]*)?/gi) || []
  return [...new Set(urls.map(normalizeDomain).filter(Boolean))]
}

function dangerousRole(role) {
  return HIGH_RISK_PERMISSIONS.some(bit => role.permissions.has(bit))
}

function channelMention(id) {
  return id ? `<#${id}>` : 'Not configured'
}

function roleMention(id) {
  return id ? `<@&${id}>` : 'Not configured'
}

function userMention(id) {
  return id ? `<@${id}>` : 'Unknown'
}

function canLockChannel(channel) {
  return channel?.type === ChannelType.GuildText ||
    channel?.type === ChannelType.GuildAnnouncement ||
    channel?.type === ChannelType.GuildForum
}

module.exports = {
  BRAND,
  FOOTER,
  HIGH_RISK_PERMISSIONS,
  embed,
  respond,
  isStaff,
  isGuildOwner,
  isBotOwner,
  memberManageable,
  safeRole,
  logEvent,
  auditActor,
  normalizeDomain,
  extractDomains,
  dangerousRole,
  channelMention,
  roleMention,
  userMention,
  canLockChannel
}
