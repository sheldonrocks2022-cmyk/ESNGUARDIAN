'use strict'

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const discord = require('discord.js')
const { GuardianDB } = require('./db')

for (const name of ['UseExternalApps','Administrator','ManageGuild','ManageRoles','ManageChannels','ManageWebhooks']) {
  if (discord.PermissionFlagsBits[name] == null) throw new Error('Missing Discord permission flag: '+name)
}
for (const name of ['ClientReady','GuildMemberAdd','GuildMemberRemove','GuildMemberUpdate','GuildBanAdd','GuildBanRemove','ChannelCreate','ChannelDelete','ChannelUpdate','GuildRoleCreate','GuildRoleDelete','GuildRoleUpdate','WebhooksUpdate','GuildIntegrationsUpdate','MessageCreate','MessageDelete','MessageBulkDelete','MessageUpdate','VoiceStateUpdate','InviteCreate','InviteDelete','UserUpdate']) {
  if (!discord.Events[name]) throw new Error('Missing Discord event constant: '+name)
}

for (const mod of ['./utils','./security','./intelligence','./overwatch','./sentinel','./resilience','./community','./esng_ai','./commands']) {
  require(mod)
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'esn-guardian-'))
const dbPath = path.join(root, 'data', 'guardian.db')
const db = new GuardianDB(dbPath)
db.ensureGuild('123456789012345678')
const setting = db.setting('123456789012345678')
if (!setting) throw new Error('Guild settings migration failed')
db.createCase('123456789012345678', null, null, 'SELFTEST', 'Node Guardian smoke test')
const backup = db.backup('selftest')
if (!backup || !fs.existsSync(backup)) throw new Error('Database backup smoke test failed')
db.close()
fs.rmSync(root, { recursive: true, force: true })

console.log('ESN Guardian Node smoke test passed')
