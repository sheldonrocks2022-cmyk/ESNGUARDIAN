'use strict'

const crypto=require('node:crypto')
const { dangerousRole, logEvent }=require('./utils')
const { caseWeight, riskLevel, missingPermissions }=require('./intelligence')

const GENESIS='GENESIS'

function normalize(value){
  if(typeof value==='bigint')return value.toString()
  if(Array.isArray(value))return value.map(normalize)
  if(value&&typeof value==='object'){const out={};for(const key of Object.keys(value).sort())out[key]=normalize(value[key]);return out}
  return value
}
function canonical(value){return JSON.stringify(normalize(value))}
function digest(row,previous=GENESIS){
  const payload={
    case_id:row.case_id??null,guild_id:row.guild_id??null,target_id:row.target_id??null,
    moderator_id:row.moderator_id??null,action:row.action??null,reason:row.reason??null,
    channel_id:row.channel_id??null,details:row.details||'{}',created_at:row.created_at??null,previous_hash:previous
  }
  return crypto.createHash('sha256').update(canonical(payload)).digest('hex')
}
function trendLabel(recent,previous){
  const expected=previous/5
  if(recent>=Math.max(12,expected*2.25))return'RISING FAST'
  if(recent>=Math.max(6,expected*1.35))return'RISING'
  if(previous>=10&&recent<=expected*0.45)return'FALLING'
  return'STABLE'
}
function postureScore(missing,disabled,ledgerOk,incident){
  let deduction=missing*7+disabled*8
  if(!ledgerOk)deduction+=20
  if(incident)deduction+=15
  return Math.max(0,100-Math.min(100,deduction))
}
function flatten(prefix,value,out){
  if(value&&typeof value==='object'&&!Array.isArray(value)){for(const key of Object.keys(value).sort())flatten(prefix?prefix+'.'+key:key,value[key],out)}
  else out[prefix]=normalize(value)
}
function diffPayloads(a,b){
  const left={},right={};flatten('',a,left);flatten('',b,right)
  return [...new Set([...Object.keys(left),...Object.keys(right)])].sort().filter(k=>JSON.stringify(left[k])!==JSON.stringify(right[k])).map(k=>k+': '+JSON.stringify(left[k])+' -> '+JSON.stringify(right[k]))
}
function syncLedger(db,guildId,batchSize=500){
  const last=db.get('SELECT sequence,case_id,case_hash FROM guardian_security_ledger WHERE guild_id=? ORDER BY sequence DESC LIMIT 1',BigInt(guildId))
  let seq=Number(last?.sequence||0), lastCase=Number(last?.case_id||0), prev=String(last?.case_hash||GENESIS)
  const rows=db.all('SELECT case_id,guild_id,target_id,moderator_id,action,reason,channel_id,details,created_at FROM cases WHERE guild_id=? AND case_id>? ORDER BY case_id ASC LIMIT ?',BigInt(guildId),lastCase,Math.max(1,Math.min(batchSize,2000)))
  let count=0
  for(const row of rows){
    seq++
    const hash=digest(row,prev)
    db.run('INSERT OR IGNORE INTO guardian_security_ledger (guild_id,sequence,case_id,previous_hash,case_hash) VALUES (?,?,?,?,?)',BigInt(guildId),seq,Number(row.case_id),prev,hash)
    prev=hash
    count++
  }
  return count
}
function verifyLedger(db,guildId){
  const rows=db.all('SELECT l.sequence,l.case_id,l.previous_hash,l.case_hash,c.guild_id,c.target_id,c.moderator_id,c.action,c.reason,c.channel_id,c.details,c.created_at FROM guardian_security_ledger l JOIN cases c ON c.case_id=l.case_id WHERE l.guild_id=? ORDER BY l.sequence ASC',BigInt(guildId))
  let prev=GENESIS,checked=0
  for(const row of rows){
    checked++
    if(String(row.previous_hash)!==prev)return{ok:false,checked,reason:'Ledger chain broke before case #'+row.case_id+'.'}
    const expected=digest(row,prev)
    if(expected!==String(row.case_hash))return{ok:false,checked,reason:'Case #'+row.case_id+' no longer matches its sealed hash.'}
    prev=expected
  }
  return{ok:true,checked,reason:'Ledger chain verified.'}
}
function policyPayload(db,guild){
  db.ensureGuild(guild.id)
  return normalize({
    security:db.get('SELECT * FROM security_config WHERE guild_id=?',BigInt(guild.id))||{},
    antinuke:db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id))||{},
    raid:db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(guild.id))||{},
    guardian:db.get('SELECT * FROM guardian_config WHERE guild_id=?',BigInt(guild.id))||{},
    guardian_permissions:Object.fromEntries(missingPermissions(guild).length?[]:[])
  })
}
function permissionPayload(guild){
  const names=['ViewAuditLog','ManageMessages','ModerateMembers','KickMembers','BanMembers','ManageRoles','ManageChannels','ManageWebhooks']
  const out={}
  const map=require('discord.js').PermissionFlagsBits
  for(const name of names)out[name]=Boolean(guild.members.me?.permissions.has(map[name]))
  return out
}
function fullPolicyPayload(db,guild){
  const p=policyPayload(db,guild)
  p.guardian_permissions=permissionPayload(guild)
  return p
}
function fingerprint(value){return crypto.createHash('sha256').update(canonical(value)).digest('hex')}
function sealPolicy(db,guild){
  const payload=fullPolicyPayload(db,guild),fp=fingerprint(payload)
  db.run('INSERT INTO guardian_policy_baseline (guild_id,fingerprint,payload_json) VALUES (?,?,?) ON CONFLICT(guild_id) DO UPDATE SET fingerprint=excluded.fingerprint,payload_json=excluded.payload_json,updated_at=CURRENT_TIMESTAMP',BigInt(guild.id),fp,canonical(payload))
  return fp
}
function policyDrift(db,guild){
  const current=fullPolicyPayload(db,guild),fp=fingerprint(current)
  const row=db.get('SELECT fingerprint,payload_json,updated_at FROM guardian_policy_baseline WHERE guild_id=?',BigInt(guild.id))
  if(!row){sealPolicy(db,guild);return{changed:false,changes:[],fingerprint:fp,initialized:true}}
  let previous={};try{previous=JSON.parse(String(row.payload_json))}catch{}
  const changes=String(row.fingerprint)===fp?[]:diffPayloads(previous,current)
  return{changed:Boolean(changes.length),changes,fingerprint:fp,updated_at:row.updated_at,initialized:false}
}
function weighted(db,guildId,start,end=null){
  const rows=end?
    db.all("SELECT action,reason,created_at FROM cases WHERE guild_id=? AND created_at>=datetime('now',?) AND created_at<datetime('now',?) ORDER BY case_id DESC LIMIT 250",BigInt(guildId),start,end):
    db.all("SELECT action,reason,created_at FROM cases WHERE guild_id=? AND created_at>=datetime('now',?) ORDER BY case_id DESC LIMIT 250",BigInt(guildId),start)
  return{score:rows.reduce((n,r)=>n+caseWeight(r.action),0),rows}
}
function trendReport(db,guild){
  const recent=weighted(db,guild.id,'-10 minutes'),previous=weighted(db,guild.id,'-60 minutes','-10 minutes')
  return{label:trendLabel(recent.score,previous.score),recent_score:recent.score,previous_score:previous.score,recent_cases:recent.rows.length,previous_cases:previous.rows.length}
}
function activeIncident(db,guildId){return db.get('SELECT * FROM guardian_incidents WHERE guild_id=? AND closed_at IS NULL ORDER BY incident_id DESC LIMIT 1',BigInt(guildId))||null}
function posture(client,db,guild){
  const snap=client.guardianIntelligence?.snapshot(guild)||{}
  const ledger=verifyLedger(db,guild.id),incident=activeIncident(db,guild.id)
  const keys=['automod','antinuke','raid','rollback','webhook_guard','integration_guard','credential_guard','external_app_lock','bot_approval']
  const disabled=keys.filter(k=>snap&&snap[k]===false).length
  const missing=(snap.missing_permissions||[]).length
  const score=postureScore(missing,disabled,ledger.ok,Boolean(incident))
  return{score,level:riskLevel(Math.max(0,100-score)),ledger,trend:trendReport(db,guild),disabled_layers:disabled,missing_permissions:snap.missing_permissions||[],active_incident:incident,snapshot:snap}
}
function memberRiskReport(db,guild,memberId){
  const member=guild.members.cache.get(String(memberId))
  const rows=db.all('SELECT case_id,action,reason,created_at FROM cases WHERE guild_id=? AND target_id=? ORDER BY case_id DESC LIMIT 20',BigInt(guild.id),BigInt(memberId))
  const score=rows.slice(0,10).reduce((n,r)=>n+caseWeight(r.action),0)
  let age='unknown',roles=[]
  if(member){age=Math.floor((Date.now()-member.user.createdTimestamp)/86400000)+' days';roles=member.roles.cache.filter(dangerousRole).map(r=>r.name)}
  const last=rows[0]
  return '**Member security profile — '+memberId+'**\nAccount age: '+age+'\nRecorded cases: '+rows.length+'\nWeighted recent risk signals: '+score+'\nHigh-risk roles: '+(roles.slice(0,8).join(', ')||'none detected')+(last?'\nLatest case: #'+last.case_id+' '+last.action+' — '+last.reason:'')
}
function integrityReport(db,guild){
  syncLedger(db,guild.id)
  const ledger=verifyLedger(db,guild.id),drift=policyDrift(db,guild),backup=db.backupInfo()
  return '**Guardian integrity report**\nCase ledger: '+(ledger.ok?'VERIFIED':'FAILED')+' ('+ledger.checked+' sealed cases checked)\nLedger detail: '+ledger.reason+'\nPolicy baseline: '+(drift.changed?'CHANGED':'matches current state')+'\nDetected policy differences: '+drift.changes.length+'\nDatabase backups: '+backup.count+' • Latest: '+(backup.latest||'none')
}
function postureReport(client,db,guild){
  const d=posture(client,db,guild),incident=d.active_incident
  return '**Guardian defense posture**\nPosture score: '+d.score+'/100\nThreat trend: '+d.trend.label+'\nRecent weighted activity: '+d.trend.recent_score+' / previous 50m: '+d.trend.previous_score+'\nDisabled protection layers: '+d.disabled_layers+'\nMissing Guardian permissions: '+(d.missing_permissions.map(x=>String(x).replaceAll('_',' ')).join(', ')||'none')+'\nTamper-evident ledger: '+(d.ledger.ok?'OK':'FAILED')+'\nActive incident: '+(incident?'#'+incident.incident_id+' '+incident.severity:'none')
}
function incidentReport(db,guildId){
  const rows=db.all('SELECT incident_id,severity,reason,opened_at,closed_at FROM guardian_incidents WHERE guild_id=? ORDER BY incident_id DESC LIMIT 8',BigInt(guildId))
  if(!rows.length)return'No persistent Guardian incident sessions have been recorded.'
  return '**Guardian incident sessions**\n'+rows.map(r=>'#'+r.incident_id+' • '+r.severity+' • opened '+r.opened_at+' UTC • '+(r.closed_at?'closed '+r.closed_at+' UTC':'ACTIVE')+' • '+String(r.reason).slice(0,120)).join('\n')
}
function driftReport(db,guild){
  const d=policyDrift(db,guild)
  if(!d.changed)return'**Security policy drift**\nNo unsealed configuration differences are currently detected.'
  return '**Security policy drift detected**\n'+d.changes.slice(0,12).map(x=>'• '+x).join('\n')+(d.changes.length>12?'\n• Additional changes omitted.':'')
}
function attachOverwatch(client,db){
  const integrityCooldown=new Map()
  const api={
    syncLedger:id=>syncLedger(db,id),verifyLedger:id=>verifyLedger(db,id),sealPolicy:g=>sealPolicy(db,g),
    policyDrift:g=>policyDrift(db,g),trendReport:g=>trendReport(db,g),posture:g=>posture(client,db,g),
    memberRiskReport:(g,id)=>memberRiskReport(db,g,id),integrityReport:g=>integrityReport(db,g),
    postureReport:g=>postureReport(client,db,g),incidentReport:id=>incidentReport(db,id),driftReport:g=>driftReport(db,g)
  }
  client.guardianOverwatch=api

  client.once('clientReady',()=>{
    for(const guild of client.guilds.cache.values()){
      try{if(!db.get('SELECT 1 AS ok FROM guardian_policy_baseline WHERE guild_id=?',BigInt(guild.id)))sealPolicy(db,guild)}catch{}
    }
  })

  const ledgerTimer=setInterval(async()=>{
    const now=Date.now()
    for(const guild of client.guilds.cache.values()){
      if(client.guardianSecurity?.isRaidModeActive?.(guild.id))continue
      try{
        syncLedger(db,guild.id);const result=verifyLedger(db,guild.id)
        if(result.ok)continue
        if(now-(integrityCooldown.get(guild.id)||0)<3600000)continue
        integrityCooldown.set(guild.id,now)
        await logEvent(db,guild,'security_log_channel_id','Guardian integrity failure',result.reason)
        try{db.backup('integrity-alert')}catch{}
      }catch(error){console.error('[Guardian] ledger loop failed',error)}
    }
  },120000);ledgerTimer.unref?.()

  const driftTimer=setInterval(async()=>{
    for(const guild of client.guilds.cache.values()){
      if(client.guardianSecurity?.isRaidModeActive?.(guild.id))continue
      try{
        const drift=policyDrift(db,guild)
        if(!drift.changed)continue
        db.createCase(guild.id,null,client.user?.id,'SECURITY_POLICY_DRIFT','Guardian security configuration changed in '+drift.changes.length+' tracked fields.',null,{changes:drift.changes.slice(0,25)})
        await logEvent(db,guild,'security_log_channel_id','Guardian security policy changed',drift.changes.slice(0,12).join('\n'))
        sealPolicy(db,guild)
      }catch(error){console.error('[Guardian] policy drift loop failed',error)}
    }
  },300000);driftTimer.unref?.()

  const incidentTimer=setInterval(async()=>{
    for(const guild of client.guilds.cache.values()){
      if(client.guardianSecurity?.isRaidModeActive?.(guild.id))continue
      try{
        const window=weighted(db,guild.id,'-5 minutes'),active=activeIncident(db,guild.id),serious=window.rows.filter(r=>caseWeight(r.action)>=8)
        if(!active&&(window.score>=30||serious.length>=3)){
          const severity=window.score>=55||serious.length>=5?'CRITICAL':'HIGH'
          const evidence=window.rows.slice(0,12).map(r=>({action:String(r.action),reason:String(r.reason).slice(0,200),created_at:String(r.created_at)}))
          db.run('INSERT INTO guardian_incidents (guild_id,severity,reason,evidence_json) VALUES (?,?,?,?)',BigInt(guild.id),severity,'Guardian observed '+window.rows.length+' security cases with weighted score '+window.score+' inside five minutes.',JSON.stringify(evidence))
          try{db.backup('incident-open')}catch{}
          await logEvent(db,guild,'security_log_channel_id','Guardian incident opened — '+severity,'Weighted 5-minute score: '+window.score+'. Serious signals: '+serious.length+'.')
        }else if(active&&window.score<6){
          const opened=Date.parse(String(active.opened_at).replace(' ','T')+'Z')
          if(Number.isFinite(opened)&&Date.now()-opened>=600000)db.run('UPDATE guardian_incidents SET closed_at=CURRENT_TIMESTAMP WHERE incident_id=?',Number(active.incident_id))
        }
      }catch(error){console.error('[Guardian] incident loop failed',error)}
    }
  },120000);incidentTimer.unref?.()
  return api
}

module.exports={attachOverwatch,digest,trendLabel,postureScore,diffPayloads}
