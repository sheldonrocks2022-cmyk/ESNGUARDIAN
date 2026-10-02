'use strict'

const {
  Client,
  Events,
  GatewayIntentBits,
  Partials
} = require('discord.js')
const config = require('./config')
const { GuardianDB } = require('./db')
const { attachSecurity } = require('./security')
const { attachIntelligence } = require('./intelligence')
const { attachOverwatch } = require('./overwatch')
const { attachSentinel } = require('./sentinel')
const { attachResilience } = require('./resilience')
const { attachCommunity } = require('./community')
const { attachESNGAI } = require('./esng_ai')
const { registerGuild, handleCommand, handleButton } = require('./commands')
const { logEvent } = require('./utils')

const db = new GuardianDB(config.databasePath)

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildModeration,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildVoiceStates,
    GatewayIntentBits.GuildInvites,
    GatewayIntentBits.GuildWebhooks
  ],
  partials: [Partials.Channel, Partials.GuildMember, Partials.Message, Partials.User]
})

client.guardianSettings = config
client.guardianDatabase = db
client.guardianStartedAt = Date.now()

attachSecurity(client, db)
attachIntelligence(client, db)
attachOverwatch(client, db)
attachSentinel(client, db)
attachResilience(client, db)
attachCommunity(client, db)
attachESNGAI(client, db)

client.once(Events.ClientReady, async ready => {
  console.log('[ESN Guardian] Connected as ' + ready.user.tag + ' (' + ready.user.id + ') in ' + ready.guilds.cache.size + ' guild(s)')
  console.log('[ESN Guardian] Node ' + process.version + '; database ' + config.databasePath)

  try {
    db.backup('startup')
  } catch (error) {
    console.error('[ESN Guardian] Startup database backup failed', error)
  }

  let allSynced = true
  for (const guild of ready.guilds.cache.values()) {
    try {
      db.ensureGuild(guild.id)
      if (db.isGuildBlacklisted(guild.id)) {
        console.warn('[ESN Guardian] Leaving blacklisted guild ' + guild.name + ' (' + guild.id + ')')
        await guild.leave().catch(() => {})
        continue
      }
      const commands = await registerGuild(guild)
      console.log('[ESN Guardian] Synced ' + commands.size + ' commands in ' + guild.name + ' (' + guild.id + ')')
    } catch (error) {
      allSynced = false
      console.error('[ESN Guardian] Command sync failed in ' + guild.name + ' (' + guild.id + ')', error)
    }
  }

  if (allSynced) {
    try {
      await ready.application.commands.set([])
      console.log('[ESN Guardian] Cleared legacy global application commands')
    } catch (error) {
      console.error('[ESN Guardian] Could not clear legacy global commands', error)
    }
  }
})

client.on(Events.ChannelDelete, channel => {
  if (!channel.guild) return
  try { db.run('UPDATE tickets SET channel_id=NULL WHERE guild_id=? AND channel_id=?', BigInt(channel.guild.id), BigInt(channel.id)) } catch {}
})

client.on(Events.GuildCreate, async guild => {
  try {
    db.ensureGuild(guild.id)
    if (db.isGuildBlacklisted(guild.id)) {
      await guild.leave().catch(() => {})
      return
    }
    await registerGuild(guild)

    if (config.ownerId) {
      const owner = await client.users.fetch(config.ownerId).catch(() => null)
      if (owner) {
        await owner.send({
          content:
            'ESN Guardian was added to **' + guild.name + '** (' + guild.id + ').\\n' +
            'Server owner: <@' + guild.ownerId + '> (' + guild.ownerId + ')\\n' +
            'Members: ' + guild.memberCount,
          allowedMentions: { parse: [] }
        }).catch(() => {})
      }
    }
  } catch (error) {
    console.error('[ESN Guardian] guild join handler failed', error)
  }
})

client.on(Events.InteractionCreate, async interaction => {
  try {
    if (interaction.isChatInputCommand()) {
      await handleCommand(interaction, db, config)

      if (interaction.inGuild()) {
        await logEvent(
          db,
          interaction.guild,
          'command_log_channel_id',
          'Command completed',
          'Command: /' + interaction.commandName +
          '\\nExecuted by: <@' + interaction.user.id + '> (' + interaction.user.id + ')' +
          '\\nChannel: <#' + interaction.channelId + '> (' + interaction.channelId + ')' +
          '\\nInteraction ID: ' + interaction.id
        ).catch(() => {})
      }
      return
    }

    if (interaction.isButton()) {
      await handleButton(interaction, db)
    }
  } catch (error) {
    console.error('[ESN Guardian] interaction handler failure', error)
    const payload = { content: 'ESN Guardian handled an internal error safely. Please retry.', ephemeral: true }
    if (interaction.deferred || interaction.replied) await interaction.followUp(payload).catch(() => {})
    else await interaction.reply(payload).catch(() => {})
  }
})

client.on(Events.Error, error => {
  console.error('[ESN Guardian] Discord client error', error)
})

client.on(Events.Warn, warning => {
  console.warn('[ESN Guardian] Discord warning:', warning)
})

const backupInterval = setInterval(() => {
  try {
    const file = db.backup('scheduled')
    if (file) console.log('[ESN Guardian] Scheduled database backup: ' + file)
  } catch (error) {
    console.error('[ESN Guardian] Scheduled database backup failed', error)
  }
}, 6 * 60 * 60 * 1000)
backupInterval.unref?.()

process.on('unhandledRejection', error => {
  console.error('[ESN Guardian] Unhandled promise rejection contained:', error)
})

process.on('uncaughtException', error => {
  console.error('[ESN Guardian] Uncaught exception contained:', error)
})

let shuttingDown = false
async function shutdown(signal) {
  if (shuttingDown) return
  shuttingDown = true
  console.log('[ESN Guardian] Shutdown requested: ' + signal)
  clearInterval(backupInterval)
  try { db.backup('shutdown') } catch (error) { console.error('[ESN Guardian] Shutdown backup failed', error) }
  try { client.destroy() } catch {}
  try { db.close() } catch {}
  setTimeout(() => process.exit(0), 250).unref()
}

process.once('SIGTERM', () => shutdown('SIGTERM'))
process.once('SIGINT', () => shutdown('SIGINT'))

client.login(config.token).catch(error => {
  console.error('[ESN Guardian] Discord login failed. Check DISCORD_TOKEN.', error)
  process.exitCode = 1
})
