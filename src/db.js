'use strict'

const fs = require('node:fs')
const path = require('node:path')
const { DatabaseSync } = require('node:sqlite')

function id(value) {
  if (value === null || value === undefined || value === '') return null
  return typeof value === 'bigint' ? value : BigInt(String(value))
}

function cleanBackupReason(value) {
  return String(value || 'snapshot').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-|-$/g, '').slice(0, 32) || 'snapshot'
}

class GuardianDB {
  constructor(filePath) {
    this.path = path.resolve(filePath)
    fs.mkdirSync(path.dirname(this.path), { recursive: true })
    this.backupDir = path.join(path.dirname(this.path), 'backups')
    fs.mkdirSync(this.backupDir, { recursive: true })
    this.db = new DatabaseSync(this.path)
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
    this.migrate()
  }

  close() {
    try { this.backup('shutdown') } catch {}
    this.db.close()
  }

  stmt(sql, bigInts = true) {
    const s = this.db.prepare(sql)
    if (bigInts && typeof s.setReadBigInts === 'function') s.setReadBigInts(true)
    return s
  }

  run(sql, ...values) {
    return this.db.prepare(sql).run(...values)
  }

  execute(sql, values = []) {
    return this.run(sql, ...values)
  }

  get(sql, ...values) {
    return this.stmt(sql).get(...values)
  }

  all(sql, ...values) {
    return this.stmt(sql).all(...values)
  }

  fetchone(sql, values = []) {
    return this.get(sql, ...values)
  }

  fetchall(sql, values = []) {
    return this.all(sql, ...values)
  }

  migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ticket_config (
        guild_id INTEGER PRIMARY KEY,
        support_role_id INTEGER
      );
      CREATE TABLE IF NOT EXISTS tickets (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        channel_id INTEGER UNIQUE,
        opened_at REAL NOT NULL,
        PRIMARY KEY (guild_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS lockdown_overwrites (
        guild_id INTEGER NOT NULL,
        channel_id INTEGER NOT NULL,
        send_messages INTEGER,
        PRIMARY KEY (guild_id, channel_id)
      );
      CREATE TABLE IF NOT EXISTS guild_settings (
        guild_id INTEGER PRIMARY KEY,
        moderation_log_channel_id INTEGER,
        security_log_channel_id INTEGER,
        member_log_channel_id INTEGER,
        message_log_channel_id INTEGER,
        verification_log_channel_id INTEGER,
        system_log_channel_id INTEGER,
        guild_log_channel_id INTEGER,
        voice_log_channel_id INTEGER,
        invite_log_channel_id INTEGER,
        role_log_channel_id INTEGER,
        command_log_channel_id INTEGER,
        welcome_channel_id INTEGER,
        welcome_message TEXT,
        goodbye_channel_id INTEGER,
        goodbye_message TEXT,
        autorole_id INTEGER,
        lockdown_active INTEGER NOT NULL DEFAULT 0,
        lockdown_role_id INTEGER,
        ad_channel_id INTEGER,
        ad_enabled INTEGER NOT NULL DEFAULT 0,
        ad_cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
        ad_last_sent_at TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS cases (
        case_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        target_id INTEGER,
        moderator_id INTEGER,
        action TEXT NOT NULL,
        reason TEXT NOT NULL,
        channel_id INTEGER,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_cases_guild_target ON cases(guild_id, target_id, case_id DESC);
      CREATE TABLE IF NOT EXISTS warnings (
        case_id INTEGER PRIMARY KEY,
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY(case_id) REFERENCES cases(case_id)
      );
      CREATE TABLE IF NOT EXISTS verification_config (
        guild_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        channel_id INTEGER,
        message_id INTEGER,
        verified_role_id INTEGER,
        unverified_role_id INTEGER,
        min_account_age_days INTEGER NOT NULL DEFAULT 0,
        cooldown_seconds INTEGER NOT NULL DEFAULT 30,
        rules_confirmation INTEGER NOT NULL DEFAULT 1,
        captcha_enabled INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS verified_members (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        verified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS panel_messages (
        guild_id INTEGER NOT NULL,
        panel_type TEXT NOT NULL,
        channel_id INTEGER NOT NULL,
        message_id INTEGER NOT NULL,
        PRIMARY KEY(guild_id, panel_type)
      );
      CREATE TABLE IF NOT EXISTS bad_words (
        guild_id INTEGER NOT NULL,
        word TEXT NOT NULL COLLATE NOCASE,
        PRIMARY KEY(guild_id, word)
      );
      CREATE TABLE IF NOT EXISTS guild_blacklist (
        guild_id INTEGER PRIMARY KEY,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS global_bans (
        user_id INTEGER PRIMARY KEY,
        reason TEXT NOT NULL,
        banned_by_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS anti_nuke_config (
        guild_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        action_limit INTEGER NOT NULL DEFAULT 3,
        window_seconds INTEGER NOT NULL DEFAULT 15
      );
      CREATE TABLE IF NOT EXISTS anti_nuke_trusted_users (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        added_by_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS blocked_external_apps (
        guild_id INTEGER NOT NULL,
        application_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        blocked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, application_id)
      );
      CREATE TABLE IF NOT EXISTS security_config (
        guild_id INTEGER PRIMARY KEY,
        automod_enabled INTEGER NOT NULL DEFAULT 1,
        flood_limit INTEGER NOT NULL DEFAULT 6,
        flood_window_seconds INTEGER NOT NULL DEFAULT 10,
        max_mentions INTEGER NOT NULL DEFAULT 6,
        caps_percentage INTEGER NOT NULL DEFAULT 80,
        block_invites INTEGER NOT NULL DEFAULT 1,
        strict_links INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS allowed_domains (
        guild_id INTEGER NOT NULL,
        domain TEXT NOT NULL COLLATE NOCASE,
        PRIMARY KEY(guild_id, domain)
      );
      CREATE TABLE IF NOT EXISTS raid_config (
        guild_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 1,
        join_limit INTEGER NOT NULL DEFAULT 10,
        join_window_seconds INTEGER NOT NULL DEFAULT 60,
        min_account_age_days INTEGER NOT NULL DEFAULT 3,
        quarantine_role_id INTEGER
      );
      CREATE TABLE IF NOT EXISTS bot_state (
        state_key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS approved_bots (
        guild_id INTEGER NOT NULL,
        bot_id INTEGER NOT NULL,
        added_by_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, bot_id)
      );
      CREATE TABLE IF NOT EXISTS guardian_snapshots (
        guild_id INTEGER PRIMARY KEY,
        data TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS security_signals (
        signal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        subject_id INTEGER,
        kind TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS incident_sessions (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        closed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS policy_baselines (
        guild_id INTEGER PRIMARY KEY,
        data TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS message_rate_state (
        guild_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        last_seen REAL NOT NULL,
        PRIMARY KEY(guild_id, user_id)
      );
    `)
  }

  ensureGuild(guildId) {
    const g = id(guildId)
    this.run('INSERT OR IGNORE INTO guild_settings (guild_id) VALUES (?)', g)
    this.run('INSERT OR IGNORE INTO verification_config (guild_id) VALUES (?)', g)
    this.run('INSERT OR IGNORE INTO anti_nuke_config (guild_id) VALUES (?)', g)
    this.run('INSERT OR IGNORE INTO security_config (guild_id) VALUES (?)', g)
    this.run('INSERT OR IGNORE INTO ticket_config (guild_id) VALUES (?)', g)
    this.run('INSERT OR IGNORE INTO raid_config (guild_id) VALUES (?)', g)
  }

  setting(guildId) {
    this.ensureGuild(guildId)
    return this.get('SELECT * FROM guild_settings WHERE guild_id = ?', id(guildId))
  }

  updateSetting(guildId, field, value) {
    const allowed = new Set([
      'moderation_log_channel_id','security_log_channel_id','member_log_channel_id',
      'message_log_channel_id','verification_log_channel_id','system_log_channel_id',
      'guild_log_channel_id','voice_log_channel_id','invite_log_channel_id','role_log_channel_id',
      'command_log_channel_id','welcome_channel_id','welcome_message','goodbye_channel_id',
      'goodbye_message','autorole_id','lockdown_active','lockdown_role_id','ad_channel_id',
      'ad_enabled','ad_cooldown_seconds','ad_last_sent_at'
    ])
    if (!allowed.has(field)) throw new Error(`Unsupported settings field: ${field}`)
    this.ensureGuild(guildId)
    const v = field.endsWith('_id') && value != null ? id(value) : value
    this.run(`UPDATE guild_settings SET ${field} = ?, updated_at = CURRENT_TIMESTAMP WHERE guild_id = ?`, v, id(guildId))
  }

  createCase(guildId, targetId, moderatorId, action, reason, channelId = null, details = {}) {
    const result = this.run(
      'INSERT INTO cases (guild_id,target_id,moderator_id,action,reason,channel_id,details) VALUES (?,?,?,?,?,?,?)',
      id(guildId), id(targetId), id(moderatorId), action, reason, id(channelId), JSON.stringify(details)
    )
    return Number(result.lastInsertRowid)
  }

  isGuildBlacklisted(guildId) {
    return Boolean(this.get('SELECT 1 AS ok FROM guild_blacklist WHERE guild_id = ?', id(guildId)))
  }

  globalBanReason(userId) {
    const row = this.get('SELECT reason FROM global_bans WHERE user_id = ?', id(userId))
    return row?.reason || null
  }

  stateEnabled(key) {
    return this.get('SELECT value FROM bot_state WHERE state_key = ?', key)?.value === '1'
  }

  setStateEnabled(key, enabled) {
    this.run(
      'INSERT INTO bot_state (state_key,value) VALUES (?,?) ON CONFLICT(state_key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP',
      key, enabled ? '1' : '0'
    )
  }

  backup(reason = 'scheduled', keep = 20) {
    if (!fs.existsSync(this.path)) return null
    try { this.db.exec('PRAGMA wal_checkpoint(FULL)') } catch {}
    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-')
    const target = path.join(this.backupDir, `${path.basename(this.path, path.extname(this.path))}-${stamp}-${cleanBackupReason(reason)}.db`)
    fs.copyFileSync(this.path, target)
    const backups = fs.readdirSync(this.backupDir)
      .filter(name => name.endsWith('.db'))
      .map(name => ({ name, full: path.join(this.backupDir, name), mtime: fs.statSync(path.join(this.backupDir, name)).mtimeMs }))
      .sort((a,b) => b.mtime - a.mtime)
    for (const stale of backups.slice(Math.max(keep, 3))) {
      try { fs.unlinkSync(stale.full) } catch {}
    }
    return target
  }

  backupInfo() {
    const backups = fs.existsSync(this.backupDir)
      ? fs.readdirSync(this.backupDir).filter(name => name.endsWith('.db')).map(name => ({
          name,
          mtime: fs.statSync(path.join(this.backupDir, name)).mtimeMs
        })).sort((a,b) => b.mtime - a.mtime)
      : []
    return { count: backups.length, latest: backups[0]?.name || null, directory: this.backupDir, database: this.path }
  }
}

module.exports = { GuardianDB, id }
