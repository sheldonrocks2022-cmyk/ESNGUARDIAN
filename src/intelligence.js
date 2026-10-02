'use strict'

const { PermissionFlagsBits } = require('discord.js')
const { logEvent } = require('./utils')

const CASE_WEIGHTS = [
  ['GUARDIAN_TAMPER',10],['ANTINUKE_',9],['EXTERNAL_APP_',9],['UNAPPROVED_BOT_',9],
  ['AUTO_ROLLBACK_FAILED',9],['CREDENTIAL_LEAK',8],['WEBHOOK',8],['INTEGRATION',8],
  ['ROLE_DELETE',8],['CHANNEL_DELETE',8],['ROLE_PERMISSION',8],['LOCKDOWN',7],
  ['SUSPICIOUS_JOIN',5],['QUARANTINE',5],['AUTOMOD_',3]
]
const CONTAINMENT_PREFIXES = [
  'ANTINUKE_','EXTERNAL_APP_','UNAPPROVED_BOT_','GUARDIAN_TAMPER','AUTO_ROLLBACK_FAILED',
  'CREDENTIAL_LEAK','WEBHOOK','INTEGRATION','ROLE_DELETE','CHANNEL_DELETE','ROLE_PERMISSION'
]
const REQUIRED = [
  ['view_audit_log',PermissionFlagsBits.ViewAuditLog],['manage_messages',PermissionFlagsBits.ManageMessages],
  ['moderate_members',PermissionFlagsBits.ModerateMembers],['kick_members',PermissionFlagsBits.KickMembers],
  ['ban_members',PermissionFlagsBits.BanMembers],['manage_roles',PermissionFlagsBits.ManageRoles],
  ['manage_channels',PermissionFlagsBits.ManageChannels],['manage_webhooks',PermissionFlagsBits.ManageWebhooks]
]

function caseWeight(action) {
  const value=String(action||'').toUpperCase()
  for(const [marker,weight] of CASE_WEIGHTS) if(value.startsWith(marker)||value.includes(marker)) return weight
  return 1
}
function family(action) {
  const value=String(action||'').toUpperCase()
  for(const marker of CONTAINMENT_PREFIXES) if(value.startsWith(marker)||value.includes(marker)) return marker
  return value.split('_',1)[0]
}
function correlationShouldContain(actions) {
  const serious=actions.filter(x=>caseWeight(x)>=8)
  if(serious.length<4) return false
  return new Set(serious.map(family)).size>=2 && serious.reduce((n,x)=>n+caseWeight(x),0)>=32
}
function riskLevel(score) {
  if(score>=70)return'CRITICAL'; if(score>=40)return'HIGH'; if(score>=18)return'ELEVATED'; if(score>=6)return'GUARDED'; return'LOW'
}
function missingPermissions(guild) {
  return REQUIRED.filter(([,bit])=>!guild.members.me?.permissions.has(bit)).map(([name])=>name)
}
function recentCases(db,guildId,minutes=60,limit=25) {
  return db.all(
    "SELECT case_id,target_id,moderator_id,action,reason,channel_id,details,created_at FROM cases WHERE guild_id=? AND created_at>=datetime('now',?) ORDER BY case_id DESC LIMIT ?",
    BigInt(guildId),'-'+Math.max(1,Math.min(minutes,10080))+' minutes',Math.max(1,Math.min(limit,100))
  )
}
function snapshot(client,db,guild) {
  db.ensureGuild(guild.id)
  const rows10=recentCases(db,guild.id,10,100), rows1h=recentCases(db,guild.id,60,100), rows24=recentCases(db,guild.id,1440,100)
  const security=db.get('SELECT * FROM security_config WHERE guild_id=?',BigInt(guild.id))
  const anti=db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id))
  const raid=db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(guild.id))
  const guardian=db.get('SELECT * FROM guardian_config WHERE guild_id=?',BigInt(guild.id))
  const verification=db.get('SELECT * FROM verification_config WHERE guild_id=?',BigInt(guild.id))
  const settings=db.setting(guild.id)
  const blocked=db.get('SELECT COUNT(*) AS count FROM blocked_external_apps WHERE guild_id=?',BigInt(guild.id))
  const missing=missingPermissions(guild)
  let score=rows10.reduce((n,r)=>n+caseWeight(r.action),0)+missing.length*8
  if(!anti||!Number(anti.enabled))score+=10
  if(!guardian||!Number(guardian.rollback_enabled))score+=8
  if(!guardian||!Number(guardian.webhook_guard))score+=6
  if(Number(settings.lockdown_active))score+=20
  const counts=new Map()
  for(const r of rows1h)counts.set(String(r.action),(counts.get(String(r.action))||0)+1)
  return {
    risk_score:score,risk_level:riskLevel(score),cases_10m:rows10.length,cases_1h:rows1h.length,cases_24h:rows24.length,
    top_actions:[...counts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5),missing_permissions:missing,
    automod:Boolean(security&&Number(security.automod_enabled)),antinuke:Boolean(anti&&Number(anti.enabled)),
    raid:Boolean(raid&&Number(raid.enabled)),verification:Boolean(verification&&Number(verification.enabled)),
    lockdown:Boolean(Number(settings.lockdown_active)),rollback:Boolean(guardian&&Number(guardian.rollback_enabled)),
    webhook_guard:Boolean(guardian&&Number(guardian.webhook_guard)),integration_guard:Boolean(guardian&&Number(guardian.integration_guard)),
    credential_guard:Boolean(guardian&&Number(guardian.credential_guard)),external_app_lock:Boolean(guardian&&Number(guardian.external_app_lock)),
    bot_approval:Boolean(guardian&&Number(guardian.bot_approval)),panic:Boolean(guardian&&Number(guardian.panic_mode)),
    blocked_apps:Number(blocked?.count||0),backup:db.backupInfo()
  }
}
function recommendations(client,db,guild) {
  const d=snapshot(client,db,guild), out=[]
  if(d.missing_permissions.length)out.push('Restore Guardian permissions: '+d.missing_permissions.map(x=>x.replaceAll('_',' ')).join(', ')+'.')
  if(!d.antinuke)out.push('Enable anti-nuke protection.')
  if(!d.rollback)out.push('Enable automatic rollback.')
  if(!d.webhook_guard)out.push('Enable webhook guard.')
  if(!d.integration_guard)out.push('Enable integration guard.')
  if(!d.credential_guard)out.push('Enable credential-leak guard.')
  if(!d.bot_approval)out.push('Enable bot approval so unknown bots cannot remain in the server.')
  if(!d.external_app_lock)out.push('Enable the external-app lock.')
  if(d.cases_10m>=3)out.push('Review the newest security cases; activity is elevated right now.')
  if(!out.length)out.push('Core Guardian protections are enabled and no immediate configuration gap was detected.')
  return out.slice(0,8)
}
function threatReport(client,db,guild) {
  const d=snapshot(client,db,guild)
  const top=d.top_actions.map(x=>x[0]+' ×'+x[1]).join(', ')||'none'
  const missing=d.missing_permissions.map(x=>x.replaceAll('_',' ')).join(', ')||'none'
  return '**Live Guardian threat report**\nRisk: '+d.risk_level+' ('+d.risk_score+' signals)\nSecurity cases: '+d.cases_10m+' / 10m • '+d.cases_1h+' / 1h • '+d.cases_24h+' / 24h\nTop recent actions: '+top+'\nLockdown: '+(d.lockdown?'ACTIVE':'inactive')+' • PANIC: '+(d.panic?'ACTIVE':'inactive')+'\nBlocked external apps: '+d.blocked_apps+'\nMissing Guardian permissions: '+missing
}
function healthReport(client,db,guild) {
  const d=snapshot(client,db,guild)
  return '**Guardian security health**\nAutoMod: '+(d.automod?'ON':'OFF')+' • Anti-nuke: '+(d.antinuke?'ON':'OFF')+' • Raid: '+(d.raid?'ON':'OFF')+
    '\nRollback: '+(d.rollback?'ON':'OFF')+' • Webhooks: '+(d.webhook_guard?'ON':'OFF')+' • Integrations: '+(d.integration_guard?'ON':'OFF')+
    '\nCredential guard: '+(d.credential_guard?'ON':'OFF')+' • Bot approval: '+(d.bot_approval?'ON':'OFF')+' • External apps: '+(d.external_app_lock?'LOCKED':'open')+
    '\nBackups: '+d.backup.count+' • Latest: '+(d.backup.latest||'none')
}
function timeline(db,guildId,limit=8) {
  const rows=recentCases(db,guildId,1440,limit)
  if(!rows.length)return'No Guardian security cases were recorded in the last 24 hours.'
  return '**Recent Guardian incidents**\n'+rows.map(r=>'#'+r.case_id+' • '+r.action+' • '+r.created_at+' UTC • '+String(r.reason).slice(0,160)).join('\n')
}
function explainCase(db,guildId,caseId) {
  const r=db.get('SELECT case_id,target_id,moderator_id,action,reason,channel_id,details,created_at FROM cases WHERE guild_id=? AND case_id=?',BigInt(guildId),caseId)
  if(!r)return null
  let details=''
  try{const obj=JSON.parse(String(r.details||'{}'));if(obj&&typeof obj==='object')details='\nDetails: '+Object.entries(obj).slice(0,6).map(([k,v])=>k+'='+v).join(', ')}catch{}
  return 'Case #'+r.case_id+' — '+r.action+'\nTime: '+r.created_at+' UTC\nTarget ID: '+(r.target_id||'N/A')+'\nReason: '+r.reason+details
}
function raidActive(client,guildId){return Boolean(client.guardianSecurity?.isRaidModeActive?.(guildId))}
function attachIntelligence(client,db) {
  const containmentCooldown=new Map(), permissionCooldown=new Map()
  const api={
    caseWeight,riskLevel,recentCases:(id,m,l)=>recentCases(db,id,m,l),snapshot:g=>snapshot(client,db,g),
    recommendations:g=>recommendations(client,db,g),threatReport:g=>threatReport(client,db,g),
    healthReport:g=>healthReport(client,db,g),timeline:(id,l)=>timeline(db,id,l),explainCase:(id,c)=>explainCase(db,id,c)
  }
  client.guardianIntelligence=api
  const correlation=setInterval(async()=>{
    const now=Date.now()
    for(const guild of client.guilds.cache.values()){
      if(raidActive(client,guild.id))continue
      try{
        const actions=recentCases(db,guild.id,2,50).map(r=>String(r.action))
        if(!correlationShouldContain(actions))continue
        if(now-(containmentCooldown.get(guild.id)||0)<600000)continue
        if(Number(db.setting(guild.id).lockdown_active))continue
        const changed=await client.guardianSecurity?.lockdownGuild?.(guild,'ESN Guardian adaptive containment: correlated high-severity security events')
        if(!changed)continue
        containmentCooldown.set(guild.id,now)
        db.createCase(guild.id,null,client.user?.id,'ADAPTIVE_CONTAINMENT','Guardian correlated at least four serious events from multiple security families within two minutes.')
        try{db.backup('adaptive-containment')}catch{}
      }catch(error){console.error('[Guardian] incident correlation failed',error)}
    }
  },90000)
  correlation.unref?.()

  const heartbeat=setInterval(async()=>{
    const now=Date.now()
    for(const guild of client.guilds.cache.values()){
      if(raidActive(client,guild.id))continue
      const missing=missingPermissions(guild)
      if(!missing.length||now-(permissionCooldown.get(guild.id)||0)<3600000)continue
      permissionCooldown.set(guild.id,now)
      await logEvent(db,guild,'security_log_channel_id','Guardian protection degraded','Missing permissions: '+missing.map(x=>x.replaceAll('_',' ')).join(', '))
    }
  },600000)
  heartbeat.unref?.()
  return api
}

module.exports={attachIntelligence,caseWeight,riskLevel,correlationShouldContain,missingPermissions,recentCases}
