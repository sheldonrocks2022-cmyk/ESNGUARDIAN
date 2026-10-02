'use strict'

const fs = require('node:fs')
const path = require('node:path')
const { DatabaseSync } = require('node:sqlite')

function id(value) {
  if (value === null || value === undefined || value === '') return null
  return typeof value === 'bigint' ? value : BigInt(String(value))
}

function cleanBackupReason(value) {
  return String(value || 'snapshot')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 32) || 'snapshot'
}

function sqliteFileOk(filePath) {
  if (!fs.existsSync(filePath) || fs.statSync(filePath).size === 0) return false
  let db
  try {
    db = new DatabaseSync(filePath)
    const statement = db.prepare('PRAGMA quick_check')
    const row = statement.get()
    return Boolean(row && Object.values(row)[0] === 'ok')
  } catch {
    return false
  } finally {
    try { db?.close() } catch {}
  }
}

class GuardianDB {
  constructor(filePath) {
    this.path = path.resolve(filePath)
    fs.mkdirSync(path.dirname(this.path), { recursive: true })
    this.backupDir = path.join(path.dirname(this.path), 'backups')
    fs.mkdirSync(this.backupDir, { recursive: true })

    this.recoverIfNeeded()
    this.db = new DatabaseSync(this.path)
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;')
    this.migrate()
  }

  recoverIfNeeded() {
    if (!fs.existsSync(this.path) || fs.statSync(this.path).size === 0) return
    if (sqliteFileOk(this.path)) return

    const backups = fs.readdirSync(this.backupDir)
      .filter(name => name.endsWith('.db'))
      .map(name => ({ name, full: path.join(this.backupDir, name), mtime: fs.statSync(path.join(this.backupDir, name)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime)

    const source = backups.find(item => sqliteFileOk(item.full))
    if (!source) {
      throw new Error(`Guardian database is corrupt and no valid backup exists in ${this.backupDir}. The database was not reset automatically.`)
    }

    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-')
    const corrupt = this.path + '.corrupt-' + stamp
    fs.renameSync(this.path, corrupt)
    for (const suffix of ['-wal', '-shm']) {
      const sidecar = this.path + suffix
      if (fs.existsSync(sidecar)) fs.unlinkSync(sidecar)
    }
    fs.copyFileSync(source.full, this.path)
    if (!sqliteFileOk(this.path)) throw new Error('Guardian restored a database backup, but the restored file failed SQLite integrity checking.')
  }

  close() {
    try { this.backup('shutdown') } catch (error) { console.error('[Guardian] shutdown backup failed', error) }
    this.db.close()
  }

  stmt(sql, bigInts = true) {
    const statement = this.db.prepare(sql)
    if (bigInts && typeof statement.setReadBigInts === 'function') statement.setReadBigInts(true)
    return statement
  }

  run(sql, ...values) {
    return this.db.prepare(sql).run(...values)
  }

  execute(sql, values = []) {
    return this.run(sql, ...values)
  }

  executemany(sql, rows = []) {
    const statement = this.db.prepare(sql)
    this.db.exec('BEGIN')
    try {
      for (const row of rows) statement.run(...row)
      this.db.exec('COMMIT')
    } catch (error) {
      try { this.db.exec('ROLLBACK') } catch {}
      throw error
    }
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

  columns(table) {
    try {
      return new Set(this.all(`PRAGMA table_info(${table})`).map(row => String(row.name)))
    } catch {
      return new Set()
    }
  }

  hasColumn(table, column) {
    return this.columns(table).has(column)
  }

  addColumnIfMissing(table, column, definition) {
    if (!this.hasColumn(table, column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
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
      CREATE TABLE IF NOT EXISTS status_subscriptions (
        user_id INTEGER NOT NULL,
        topic TEXT NOT NULL CHECK(topic IN ('smp', 'bot')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, topic)
      );

      CREATE TABLE IF NOT EXISTS guardian_config (
        guild_id INTEGER PRIMARY KEY,
        external_app_lock INTEGER NOT NULL DEFAULT 1,
        bot_approval INTEGER NOT NULL DEFAULT 1,
        webhook_guard INTEGER NOT NULL DEFAULT 1,
        integration_guard INTEGER NOT NULL DEFAULT 1,
        credential_guard INTEGER NOT NULL DEFAULT 1,
        rollback_enabled INTEGER NOT NULL DEFAULT 1,
        panic_mode INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS approved_bots (
        guild_id INTEGER NOT NULL,
        bot_id INTEGER NOT NULL,
        approved_by_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, bot_id)
      );
      CREATE TABLE IF NOT EXISTS approved_webhooks (
        guild_id INTEGER NOT NULL,
        webhook_id INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, webhook_id)
      );
      CREATE TABLE IF NOT EXISTS approved_integrations (
        guild_id INTEGER NOT NULL,
        integration_id INTEGER NOT NULL,
        application_id INTEGER,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, integration_id)
      );
      CREATE TABLE IF NOT EXISTS guardian_snapshots (
        guild_id INTEGER PRIMARY KEY,
        snapshot_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS guardian_baseline_state (
        guild_id INTEGER PRIMARY KEY,
        initialized_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS guardian_raid_runtime (
        guild_id INTEGER PRIMARY KEY,
        active_until_epoch INTEGER NOT NULL DEFAULT 0,
        blocked_count INTEGER NOT NULL DEFAULT 0,
        trigger_count INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS guardian_security_ledger (
        guild_id INTEGER NOT NULL,
        sequence INTEGER NOT NULL,
        case_id INTEGER NOT NULL,
        previous_hash TEXT NOT NULL,
        case_hash TEXT NOT NULL,
        sealed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (guild_id, sequence),
        UNIQUE (guild_id, case_id)
      );
      CREATE TABLE IF NOT EXISTS guardian_policy_baseline (
        guild_id INTEGER PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS guardian_incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        severity TEXT NOT NULL,
        reason TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        opened_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        closed_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_guardian_incidents_open
        ON guardian_incidents(guild_id, closed_at, incident_id DESC);

      CREATE TABLE IF NOT EXISTS guardian_resilience_history (
        check_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        score INTEGER NOT NULL,
        grade TEXT NOT NULL,
        missing_cogs INTEGER NOT NULL,
        missing_permissions INTEGER NOT NULL,
        disabled_layers INTEGER NOT NULL,
        integrity_ok INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_guardian_resilience_history_guild
        ON guardian_resilience_history(guild_id, check_id DESC);

      CREATE TABLE IF NOT EXISTS guardian_sentinel_state (
        guild_id INTEGER PRIMARY KEY,
        last_case_id INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS guardian_sentinel_signals (
        signal_id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id INTEGER NOT NULL,
        case_id INTEGER NOT NULL,
        subject_id INTEGER,
        target_id INTEGER,
        action TEXT NOT NULL,
        category TEXT NOT NULL,
        score INTEGER NOT NULL,
        severity TEXT NOT NULL,
        explanation_json TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(guild_id, case_id)
      );
      CREATE INDEX IF NOT EXISTS idx_guardian_sentinel_signals_guild
        ON guardian_sentinel_signals(guild_id, signal_id DESC);
      CREATE TABLE IF NOT EXISTS guardian_sentinel_subject_profile (
        guild_id INTEGER NOT NULL,
        subject_id INTEGER NOT NULL,
        total_cases INTEGER NOT NULL DEFAULT 0,
        weighted_score INTEGER NOT NULL DEFAULT 0,
        last_action TEXT,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, subject_id)
      );
      CREATE TABLE IF NOT EXISTS guardian_sentinel_action_baseline (
        guild_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 0,
        last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(guild_id, action)
      );
    `)

    for (const column of ['guild_log_channel_id','voice_log_channel_id','invite_log_channel_id','role_log_channel_id','command_log_channel_id']) {
      this.addColumnIfMissing('guild_settings', column, 'INTEGER')
    }

    // Compatibility with the first Node conversion build.
    const approved = this.columns('approved_bots')
    if (!approved.has('approved_by_id')) this.addColumnIfMissing('approved_bots', 'approved_by_id', 'INTEGER')
    const snapshots = this.columns('guardian_snapshots')
    if (!snapshots.has('snapshot_json')) this.addColumnIfMissing('guardian_snapshots', 'snapshot_json', 'TEXT')
  }

  ensureGuild(guildId) {
    const g = id(guildId)
    for (const sql of [
      'INSERT OR IGNORE INTO guild_settings (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO verification_config (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO anti_nuke_config (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO security_config (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO ticket_config (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO raid_config (guild_id) VALUES (?)',
      'INSERT OR IGNORE INTO guardian_config (guild_id) VALUES (?)'
    ]) this.run(sql, g)
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
      id(guildId), id(targetId), id(moderatorId), action, reason, id(channelId), JSON.stringify(details || {})
    )
    return Number(result.lastInsertRowid)
  }

  createCasesBulk(rows) {
    if (!rows?.length) return 0
    const statement = this.db.prepare(
      'INSERT INTO cases (guild_id,target_id,moderator_id,action,reason,channel_id,details) VALUES (?,?,?,?,?,?,?)'
    )
    this.db.exec('BEGIN')
    try {
      for (const row of rows) {
        const [guildId,targetId,moderatorId,action,reason,channelId,details] = row
        statement.run(id(guildId),id(targetId),id(moderatorId),action,reason,id(channelId),JSON.stringify(details || {}))
      }
      this.db.exec('COMMIT')
      return rows.length
    } catch (error) {
      try { this.db.exec('ROLLBACK') } catch {}
      throw error
    }
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

  subscribeToStatus(userId, topic) {
    this.run('INSERT OR IGNORE INTO status_subscriptions (user_id,topic) VALUES (?,?)', id(userId), topic)
  }

  unsubscribeFromStatus(userId, topic) {
    this.run('DELETE FROM status_subscriptions WHERE user_id=? AND topic=?', id(userId), topic)
  }

  statusSubscriptions(userId) {
    return new Set(this.all('SELECT topic FROM status_subscriptions WHERE user_id=?', id(userId)).map(row => String(row.topic)))
  }

  statusSubscriberIds(topic) {
    return this.all('SELECT user_id FROM status_subscriptions WHERE topic=?', topic).map(row => String(row.user_id))
  }

  insertApprovedBot(guildId, botId, approvedById) {
    const columns = this.columns('approved_bots')
    if (columns.has('added_by_id') && columns.has('approved_by_id')) {
      this.run(
        'INSERT OR REPLACE INTO approved_bots (guild_id,bot_id,added_by_id,approved_by_id) VALUES (?,?,?,?)',
        id(guildId), id(botId), id(approvedById), id(approvedById)
      )
    } else if (columns.has('added_by_id')) {
      this.run(
        'INSERT OR REPLACE INTO approved_bots (guild_id,bot_id,added_by_id) VALUES (?,?,?)',
        id(guildId), id(botId), id(approvedById)
      )
    } else {
      this.run(
        'INSERT OR REPLACE INTO approved_bots (guild_id,bot_id,approved_by_id) VALUES (?,?,?)',
        id(guildId), id(botId), id(approvedById)
      )
    }
  }

  saveGuardianSnapshot(guildId, json) {
    const columns = this.columns('guardian_snapshots')
    if (columns.has('data') && columns.has('snapshot_json')) {
      this.run(
        'INSERT INTO guardian_snapshots (guild_id,data,snapshot_json,created_at) VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET data=excluded.data,snapshot_json=excluded.snapshot_json,created_at=CURRENT_TIMESTAMP',
        id(guildId), json, json
      )
    } else if (columns.has('data')) {
      this.run(
        'INSERT INTO guardian_snapshots (guild_id,data,created_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET data=excluded.data,created_at=CURRENT_TIMESTAMP',
        id(guildId), json
      )
    } else {
      this.run(
        'INSERT INTO guardian_snapshots (guild_id,snapshot_json,created_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,created_at=CURRENT_TIMESTAMP',
        id(guildId), json
      )
    }
  }

  guardianSnapshotJson(guildId) {
    const columns = this.columns('guardian_snapshots')
    const select = columns.has('snapshot_json') && columns.has('data')
      ? 'COALESCE(snapshot_json,data)'
      : columns.has('snapshot_json') ? 'snapshot_json' : 'data'
    const row = this.get(`SELECT ${select} AS payload FROM guardian_snapshots WHERE guild_id=?`, id(guildId))
    return row?.payload ? String(row.payload) : null
  }

  backup(reason = 'scheduled', keep = 20) {
    try { this.db.exec('PRAGMA wal_checkpoint(FULL)') } catch {}
    if (!fs.existsSync(this.path)) return null

    const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-')
    const target = path.join(
      this.backupDir,
      `${path.basename(this.path, path.extname(this.path))}-${stamp}-${cleanBackupReason(reason)}.db`
    )
    fs.copyFileSync(this.path, target)

    if (!sqliteFileOk(target)) {
      try { fs.unlinkSync(target) } catch {}
      throw new Error(`Backup integrity check failed for ${path.basename(target)}`)
    }

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
      ? fs.readdirSync(this.backupDir)
        .filter(name => name.endsWith('.db'))
        .map(name => ({ name, mtime: fs.statSync(path.join(this.backupDir, name)).mtimeMs }))
        .sort((a,b) => b.mtime - a.mtime)
      : []
    return {
      count: backups.length,
      latest: backups[0]?.name || null,
      directory: this.backupDir,
      database: this.path
    }
  }
}

module.exports = { GuardianDB, id, sqliteFileOk }
