'use strict'

const path = require('node:path')
require('dotenv').config({ path: path.join(__dirname, '..', '.env') })

function required(name) {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required.`)
  return value
}

module.exports = {
  token: required('DISCORD_TOKEN'),
  ownerId: process.env.BOT_OWNER_ID?.trim() || null,
  databasePath: process.env.DATABASE_PATH?.trim() || 'data/esn_guardian.db',
  logLevel: (process.env.LOG_LEVEL || 'INFO').trim().toUpperCase()
}
