'use strict'

const { PermissionFlagsBits }=require('discord.js')
const { logEvent }=require('./utils')

const REQUIRED_MODULES=[
  ['SecurityCog','guardianSecurity'],
  ['AdvancedSecurityCog','guardianSecurity'],
  ['SecurityIntelligenceCog','guardianIntelligence'],
  ['SecurityOverwatchCog','guardianOverwatch'],
  ['SecuritySentinelCog','guardianSentinel']
]
const REQUIRED_PERMISSIONS=[
  ['view_audit_log',PermissionFlagsBits.ViewAuditLog],
  ['manage_messages',PermissionFlagsBits.ManageMessages],
  ['moderate_members',PermissionFlagsBits.ModerateMembers],
  ['kick_members',PermissionFlagsBits.KickMembers],
  ['ban_members',PermissionFlagsBits.BanMembers],
  ['manage_roles',PermissionFlagsBits.ManageRoles],
  ['manage_channels',PermissionFlagsBits.ManageChannels],
  ['manage_webhooks',PermissionFlagsBits.ManageWebhooks]
]
function readinessGrade(score){if(score>=90)return'READY';if(score>=75)return'STRONG';if(score>=55)return'DEGRADED';if(score>=30)return'WEAK';return'CRITICAL'}
function snapshot(client,db,guild){
  db.ensureGuild(guild.id)
  const missingModules=REQUIRED_MODULES.filter(([,property])=>!client[property]).map(([name])=>name)
  const botMember=guild.members.me
  const missingPermissions=REQUIRED_PERMISSIONS.filter(([,bit])=>!botMember?.permissions.has(bit)).map(([name])=>name)
  const security=db.get('SELECT automod_enabled FROM security_config WHERE guild_id=?',BigInt(guild.id))
  const anti=db.get('SELECT enabled FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id))
  const raid=db.get('SELECT enabled FROM raid_config WHERE guild_id=?',BigInt(guild.id))
  const guardian=db.get('SELECT external_app_lock,bot_approval,webhook_guard,integration_guard,credential_guard,rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(guild.id))
  const layers={
    automod:Boolean(security&&Number(security.automod_enabled)),antinuke:Boolean(anti&&Number(anti.enabled)),raid:Boolean(raid&&Number(raid.enabled)),
    external_app_lock:Boolean(guardian&&Number(guardian.external_app_lock)),bot_approval:Boolean(guardian&&Number(guardian.bot_approval)),
    webhook_guard:Boolean(guardian&&Number(guardian.webhook_guard)),integration_guard:Boolean(guardian&&Number(guardian.integration_guard)),
    credential_guard:Boolean(guardian&&Number(guardian.credential_guard)),rollback:Boolean(guardian&&Number(guardian.rollback_enabled))
  }
  const disabled=Object.entries(layers).filter(([,v])=>!v).map(([k])=>k)
  const backup=db.backupInfo(),hasBackup=Number(backup.count||0)>0
  const recovery=db.get('SELECT created_at FROM guardian_snapshots WHERE guild_id=?',BigInt(guild.id))
  let integrity=true
  try{integrity=Boolean(client.guardianOverwatch?.verifyLedger(guild.id)?.ok??true)}catch{integrity=false}
  let score=100
  score-=Math.min(35,missingModules.length*10)
  score-=Math.min(32,missingPermissions.length*4)
  score-=Math.min(28,disabled.length*4)
  if(!hasBackup)score-=10
  if(!recovery)score-=10
  if(!integrity)score-=20
  score=Math.max(0,Math.min(100,score))
  return{score,grade:readinessGrade(score),missing_cogs:missingModules,missing_permissions:missingPermissions,disabled_layers:disabled,has_backup:hasBackup,backup_count:Number(backup.count||0),latest_backup:backup.latest,has_snapshot:Boolean(recovery),snapshot_at:recovery?.created_at||null,integrity_ok:integrity,layers}
}
function recordSnapshot(client,db,guild){
  const d=snapshot(client,db,guild)
  db.run('INSERT INTO guardian_resilience_history (guild_id,score,grade,missing_cogs,missing_permissions,disabled_layers,integrity_ok) VALUES (?,?,?,?,?,?,?)',BigInt(guild.id),d.score,d.grade,d.missing_cogs.length,d.missing_permissions.length,d.disabled_layers.length,d.integrity_ok?1:0)
  return d
}
function statusReport(client,db,guild){
  const d=snapshot(client,db,guild)
  return'**Guardian Resilience**\nReadiness: '+d.score+'/100 ('+d.grade+')\nMissing security modules: '+(d.missing_cogs.join(', ')||'none')+'\nMissing permissions: '+(d.missing_permissions.map(x=>String(x).replaceAll('_',' ')).join(', ')||'none')+'\nDisabled protection layers: '+(d.disabled_layers.join(', ')||'none')+'\nTamper-evident ledger: '+(d.integrity_ok?'OK':'FAILED')+'\nRecovery snapshot: '+(d.snapshot_at||'none')+'\nBackups: '+d.backup_count+' • Latest: '+(d.latest_backup||'none')
}
function drillReport(client,db,guild){
  const d=snapshot(client,db,guild)
  const checks=[['Core security modules loaded',!d.missing_cogs.length],['Critical Discord permissions available',!d.missing_permissions.length],['Protection layers enabled',!d.disabled_layers.length],['Case ledger verifies',d.integrity_ok],['Recovery snapshot exists',d.has_snapshot],['At least one database backup exists',d.has_backup]]
  return'**Guardian non-destructive security drill**\n'+checks.map(([name,pass])=>(pass?'PASS':'FAIL')+' — '+name).join('\n')+'\nThis drill changes nothing in the server. It verifies whether Guardian is prepared to respond and recover.'
}
function recoveryPlan(client,db,guild){
  const d=snapshot(client,db,guild),steps=[]
  if(d.missing_permissions.length)steps.push("Restore Guardian's missing Discord permissions: "+d.missing_permissions.map(x=>String(x).replaceAll('_',' ')).join(', ')+'.')
  if(d.missing_cogs.length)steps.push('Restart or repair Guardian so these modules load: '+d.missing_cogs.join(', ')+'.')
  if(d.disabled_layers.length)steps.push('Review and re-enable protection layers that should be active: '+d.disabled_layers.join(', ')+'.')
  if(!d.integrity_ok)steps.push('Treat the case ledger integrity failure as high priority; preserve current backups and investigate before approving a new baseline.')
  if(!d.has_snapshot)steps.push('Create a trusted Guardian recovery snapshot after confirming the current server state is clean.')
  if(!d.has_backup)steps.push('Create an immediate Guardian database backup.')
  if(!steps.length)steps.push('No readiness gaps are currently detected. Continue monitoring Sentinel, Overwatch, and scheduled backups.')
  return'**Guardian recovery readiness plan**\n'+steps.map((x,i)=>(i+1)+'. '+x).join('\n')
}
function attachResilience(client,db){
  const alertCooldown=new Map()
  const api={snapshot:g=>snapshot(client,db,g),recordSnapshot:g=>recordSnapshot(client,db,g),statusReport:g=>statusReport(client,db,g),drillReport:g=>drillReport(client,db,g),recoveryPlan:g=>recoveryPlan(client,db,g)}
  client.guardianResilience=api
  const timer=setInterval(async()=>{
    const now=Date.now()
    for(const guild of client.guilds.cache.values()){
      if(client.guardianSecurity?.isRaidModeActive?.(guild.id))continue
      try{
        const d=recordSnapshot(client,db,guild)
        if(d.score>=55)continue
        if(now-(alertCooldown.get(guild.id)||0)<3600000)continue
        alertCooldown.set(guild.id,now)
        await logEvent(db,guild,'security_log_channel_id','Guardian resilience degraded — '+d.grade,'Readiness score: '+d.score+'/100\nMissing modules: '+d.missing_cogs.length+'\nMissing permissions: '+d.missing_permissions.length+'\nDisabled layers: '+d.disabled_layers.length+'\nLedger integrity: '+(d.integrity_ok?'OK':'FAILED'))
      }catch(error){console.error('[Guardian] resilience check failed',error)}
    }
  },300000)
  timer.unref?.()
  return api
}
module.exports={attachResilience,readinessGrade}
