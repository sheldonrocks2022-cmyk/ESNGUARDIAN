'use strict'

const {
  AuditLogEvent,
  Events,
  PermissionFlagsBits,
  ChannelType
}=require('discord.js')
const {
  auditActor,
  canLockChannel,
  dangerousRole,
  extractDomains,
  logEvent
}=require('./utils')

const destructiveWindows=new Map()
const antiNukeWindows=new Map()
const messageWindows=new Map()
const messageContentWindows=new Map()
const joins=new Map()
const fastJoins=new Map()
const youngJoins=new Map()
const recentJoinMembers=new Map()
const raidModeUntil=new Map()
const internalRemovals=new Map()
const rollbackGuard=new Set()
const safeBaselineLocks=new Set()
const integrationLocks=new Set()
const auditAccessWarnedAt=new Map()
const raidQueue=[]
const raidQueued=new Set()
const raidAuditBuffer=[]
const raidBlockedCount=new Map()
const raidTriggerCount=new Map()
let raidActiveWorkers=0

const RAID_CONTAINMENT_MS=5*60*1000
const RAID_FAST_WINDOW_MS=5000
const RAID_YOUNG_WINDOW_MS=15000
const RAID_QUEUE_MAX=4096
const USE_EXTERNAL_APPS_BIT=1n<<50n

const CREDENTIAL_PATTERNS=[
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\b(?:mfa\.)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,}\b/
]
const SUSPICIOUS_DOMAIN_TOKENS=['discord-gift','discordgift','free-nitro','freenitro','nitro-gift','steamcommuniity','steamcomrnunity','dlscord','dicsord','discorcl']
const SHORTENERS=new Set(['bit.ly','tinyurl.com','is.gd','rb.gy','cutt.ly'])

function fastBurstLimit(joinLimit){return Math.max(3,Math.min(joinLimit,Math.floor((joinLimit+1)/2)))}
function isRaidModeActive(guildId){const until=raidModeUntil.get(String(guildId));return Boolean(until&&until>Date.now())}
function isInternalRemoval(guildId,userId){
  const key=String(guildId)+':'+String(userId),until=internalRemovals.get(key)
  if(!until)return false
  if(until<=Date.now()){internalRemovals.delete(key);return false}
  return true
}
function markInternalRemoval(guildId,userId){internalRemovals.set(String(guildId)+':'+String(userId),Date.now()+120000)}
function jsonSafe(value){
  if(typeof value==='bigint')return value.toString()
  if(Array.isArray(value))return value.map(jsonSafe)
  if(value&&typeof value==='object'){const out={};for(const [k,v] of Object.entries(value))out[k]=jsonSafe(v);return out}
  return value
}
function snapshotGuild(guild){
  return{
    guild_id:guild.id,
    roles:guild.roles.cache.filter(r=>r.id!==guild.id&&!r.managed).map(role=>({
      id:role.id,name:role.name,permissions:role.permissions.bitfield.toString(),colour:role.color,hoist:role.hoist,
      mentionable:role.mentionable,position:role.position,members:role.members.map(m=>m.id)
    })),
    channels:guild.channels.cache.map(channel=>({
      id:channel.id,name:channel.name,type:channel.type,position:channel.rawPosition,category_id:channel.parentId,
      topic:'topic'in channel?channel.topic:null,slowmode_delay:'rateLimitPerUser'in channel?channel.rateLimitPerUser:0,
      nsfw:'nsfw'in channel?channel.nsfw:false,
      overwrites:channel.permissionOverwrites?.cache?.map(o=>({target_id:o.id,target_type:Number(o.type)===0?'role':'member',allow:o.allow.bitfield.toString(),deny:o.deny.bitfield.toString()}))||[]
    }))
  }
}
async function approveCurrent(db,guild){
  for(const member of guild.members.cache.values()){
    if(member.user.bot&&member.id!==guild.members.me?.id)db.insertApprovedBot(guild.id,member.id,guild.ownerId)
  }
  try{
    const hooks=await guild.fetchWebhooks()
    for(const hook of hooks.values())db.run('INSERT OR IGNORE INTO approved_webhooks (guild_id,webhook_id) VALUES (?,?)',BigInt(guild.id),BigInt(hook.id))
  }catch{}
  try{
    const integrations=await guild.fetchIntegrations()
    for(const integration of integrations.values())db.run('INSERT OR IGNORE INTO approved_integrations (guild_id,integration_id,application_id) VALUES (?,?,?)',BigInt(guild.id),BigInt(integration.id),integration.application?.id?BigInt(integration.application.id):null)
  }catch{}
}
async function saveSnapshot(db,guild,approve=true){
  const data=snapshotGuild(guild)
  db.saveGuardianSnapshot(guild.id,JSON.stringify(data))
  if(approve)await approveCurrent(db,guild)
  return data
}
function getSnapshot(db,guildId){
  const raw=db.guardianSnapshotJson(guildId)
  if(!raw)return null
  try{return JSON.parse(raw)}catch{return null}
}
async function ensureSafeBaseline(db,guild){
  const key=String(guild.id)
  if(safeBaselineLocks.has(key))return
  if(db.get('SELECT 1 AS ok FROM guardian_baseline_state WHERE guild_id=?',BigInt(guild.id)))return
  safeBaselineLocks.add(key)
  try{
    await approveCurrent(db,guild)
    db.run('INSERT OR REPLACE INTO guardian_baseline_state (guild_id,initialized_at) VALUES (?,CURRENT_TIMESTAMP)',BigInt(guild.id))
  }finally{safeBaselineLocks.delete(key)}
}
async function securityAuditActor(db,guild,type,targetId){
  for(const delay of [600,1200,2000]){
    await new Promise(resolve=>setTimeout(resolve,delay))
    try{
      const logs=await guild.fetchAuditLogs({type,limit:10})
      const recent=Date.now()-120000
      const entry=logs.entries.find(item=>
        item.createdTimestamp>=recent&&
        (!targetId||String(item.targetId||item.target?.id||'')===String(targetId))&&
        item.executor
      )
      if(entry?.executor)return entry.executor
    }catch(error){
      if(error?.code===50013||error?.code===50001){
        const now=Date.now(),last=auditAccessWarnedAt.get(String(guild.id))||0
        if(now-last>=600000){
          auditAccessWarnedAt.set(String(guild.id),now)
          await logEvent(db,guild,'security_log_channel_id','Anti-nuke audit access unavailable','Grant View Audit Log to attribute destructive actions.')
        }
        return null
      }
    }
  }
  return null
}

function trustedUser(db,guild,userId){
  if(!userId)return false
  if(String(userId)===String(guild.ownerId)||String(userId)===String(guild.members.me?.id))return true
  return Boolean(db.get('SELECT 1 AS ok FROM anti_nuke_trusted_users WHERE guild_id=? AND user_id=?',BigInt(guild.id),BigInt(userId)))
}
function isApprovedBot(db,guildId,botId){return Boolean(db.get('SELECT 1 AS ok FROM approved_bots WHERE guild_id=? AND bot_id=?',BigInt(guildId),BigInt(botId)))}
async function securityCase(db,guild,target,action,reason,channelId=null,details={}){
  const targetId=target?.id||target||null
  const caseId=db.createCase(guild.id,targetId,guild.client.user?.id,action,reason,channelId,details)
  await logEvent(db,guild,'security_log_channel_id','Security: '+action+' | Case #'+caseId,'Target: '+(targetId?'<@'+targetId+'>':'N/A')+'\nReason: '+reason)
  const owner=await guild.fetchOwner().catch(()=>null)
  if(owner){
    await owner.send({content:'Security alert in **'+guild.name+'** ('+guild.id+')\nCase #'+caseId+': '+action+'\nTarget: '+(targetId||'N/A')+'\nReason: '+reason,allowedMentions:{parse:[]}}).catch(()=>{})
  }
  return caseId
}
async function containActor(db,guild,actor,reason){
  if(!actor||actor.id===guild.ownerId||actor.id===guild.members.me?.id)return false
  const member=await guild.members.fetch(actor.id).catch(()=>null)
  if(!member){await securityCase(db,guild,actor,'COMPROMISED_ADMIN_ALERT',reason);return false}
  let removed=0
  for(const role of member.roles.cache.filter(r=>r.id!==guild.id&&r.editable&&dangerousRole(r)).values()){
    await member.roles.remove(role,'ESN Guardian containment: '+reason).then(()=>removed++).catch(()=>{})
  }
  let contained=false
  if(member.moderatable)await member.timeout(24*60*60*1000,'ESN Guardian containment: '+reason).then(()=>contained=true).catch(()=>{})
  if(!contained)await guild.members.ban(member.id,{reason:'ESN Guardian emergency containment: '+reason,deleteMessageSeconds:0}).then(()=>contained=true).catch(()=>{})
  await securityCase(db,guild,member,'COMPROMISED_ADMIN_CONTAINED',reason,null,{removedRoles:removed,contained})
  return contained
}
async function recordDestructive(db,guild,actor,action){
  if(!actor||actor.id===guild.ownerId||actor.id===guild.members.me?.id)return
  const key=guild.id+':'+actor.id,now=Date.now()
  const history=(destructiveWindows.get(key)||[]).filter(t=>now-t<10000)
  history.push(now)
  destructiveWindows.set(key,history)
  if(history.length>=3){
    destructiveWindows.set(key,[])
    await containActor(db,guild,actor,'Compromised-admin protection: 3 destructive actions inside 10 seconds; latest='+action)
  }
}
async function checkNukeAction(db,guild,actor,actionName,{allowUnattributed=false,targetId=null}={}){
  db.ensureGuild(guild.id)
  const cfg=db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id))
  if(!cfg||!Number(cfg.enabled))return
  if(actor&&trustedUser(db,guild,actor.id))return
  if(!actor&&!allowUnattributed)return

  const actorId=actor?.id||'0'
  const key=guild.id+':'+actorId
  const now=Date.now(),windowMs=Number(cfg.window_seconds||15)*1000
  const events=(antiNukeWindows.get(key)||[]).filter(t=>now-t<=windowMs)
  events.push(now)
  antiNukeWindows.set(key,events)

  const limit=Number(cfg.action_limit||3)
  const actorName=actor?.tag||actor?.username||actor?.user?.tag||actor?.id||'unattributed actor'
  if(events.length<limit){
    await securityCase(
      db,guild,actor,
      actor?'ANTINUKE_ALERT':'ANTINUKE_UNATTRIBUTED',
      actionName+' by '+actorName+' ('+events.length+'/'+limit+' actions)',
      null,{targetId}
    )
    return
  }

  antiNukeWindows.set(key,[])
  if(actor){
    const banned=await guild.members.ban(actor.id,{reason:'ESN Guardian anti-nuke: '+actionName+' threshold exceeded',deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
    if(banned){
      await securityCase(db,guild,actor,'ANTINUKE_BAN','Banned after '+limit+' destructive actions in '+Number(cfg.window_seconds||15)+' seconds',null,{targetId})
    }else{
      await securityCase(db,guild,actor,'ANTINUKE_CONTAINMENT_FAILED','Could not ban after destructive action threshold: '+actionName,null,{targetId})
    }
  }else{
    await securityCase(db,guild,null,'ANTINUKE_UNATTRIBUTED','Destructive-action threshold reached for '+actionName+', but Discord audit logs did not expose the actor in time.',null,{targetId})
  }
  await lockdownGuild(db,guild,'Automatic anti-nuke lockdown: '+actionName+' threshold exceeded')
}
async function lockdownGuild(db,guild,reason='Security lockdown'){
  const settings=db.setting(guild.id)
  if(Number(settings.lockdown_active))return false
  const channels=guild.channels.cache.filter(channel=>
    channel.type===ChannelType.GuildText||channel.type===ChannelType.GuildAnnouncement
  )
  for(const channel of channels.values()){
    const current=channel.permissionOverwrites.cache.get(guild.id)
    const send=current?.allow?.has(PermissionFlagsBits.SendMessages)?1:current?.deny?.has(PermissionFlagsBits.SendMessages)?0:null
    db.run('INSERT OR IGNORE INTO lockdown_overwrites (guild_id,channel_id,send_messages) VALUES (?,?,?)',BigInt(guild.id),BigInt(channel.id),send)
  }
  let changed=0
  for(const channel of channels.values()){
    await channel.permissionOverwrites.edit(guild.roles.everyone,{SendMessages:false},{reason}).then(()=>changed++).catch(()=>{})
  }
  db.updateSetting(guild.id,'lockdown_active',1)
  await securityCase(db,guild,null,'LOCKDOWN',reason+'; channels secured: '+changed)
  return true
}
async function unlockdownGuild(db,guild,reason='Security lockdown released'){
  const rows=db.all('SELECT * FROM lockdown_overwrites WHERE guild_id=?',BigInt(guild.id))
  let changed=0
  for(const row of rows){
    const channel=guild.channels.cache.get(String(row.channel_id))
    if(!channel||!(channel.type===ChannelType.GuildText||channel.type===ChannelType.GuildAnnouncement))continue
    let value=null
    if(row.send_messages===1||row.send_messages===1n)value=true
    if(row.send_messages===0||row.send_messages===0n)value=false
    const restored=await channel.permissionOverwrites.edit(guild.roles.everyone,{SendMessages:value},{reason}).then(()=>true).catch(()=>false)
    if(restored){
      changed++
      db.run('DELETE FROM lockdown_overwrites WHERE guild_id=? AND channel_id=?',BigInt(guild.id),BigInt(channel.id))
    }
  }
  const pending=db.get('SELECT 1 AS ok FROM lockdown_overwrites WHERE guild_id=? LIMIT 1',BigInt(guild.id))
  db.updateSetting(guild.id,'lockdown_active',pending?1:0)
  await securityCase(db,guild,null,'UNLOCKDOWN',reason+'; channels restored: '+changed)
  return changed
}
async function lockExternalApps(guild){
  let changed=0,failed=0
  for(const role of guild.roles.cache.values()){
    if(role.managed||(!role.editable&&role.id!==guild.id))continue
    if(!role.permissions.has(PermissionFlagsBits.UseExternalApps))continue
    try{await role.setPermissions(role.permissions.remove(PermissionFlagsBits.UseExternalApps),'ESN Guardian: external apps disabled');changed++}catch{failed++}
  }
  for(const channel of guild.channels.cache.values()){
    for(const overwrite of channel.permissionOverwrites?.cache?.values?.()||[]){
      if(!overwrite.allow.has(PermissionFlagsBits.UseExternalApps))continue
      try{
        const target=guild.roles.cache.get(overwrite.id)||guild.members.cache.get(overwrite.id)
        if(!target)continue
        await channel.permissionOverwrites.edit(target,{UseExternalApps:false},{reason:'ESN Guardian: external apps disabled'});changed++
      }catch{failed++}
    }
  }
  return{changed,failed}
}
async function hardenGuild(db,guild){
  db.ensureGuild(guild.id)
  db.run('UPDATE security_config SET automod_enabled=1,flood_limit=5,flood_window_seconds=10,max_mentions=5,caps_percentage=80,block_invites=1 WHERE guild_id=?',BigInt(guild.id))
  db.run('UPDATE anti_nuke_config SET enabled=1,action_limit=2,window_seconds=15 WHERE guild_id=?',BigInt(guild.id))
  db.run('UPDATE raid_config SET enabled=1,join_limit=8,join_window_seconds=30,min_account_age_days=CASE WHEN min_account_age_days<3 THEN 3 ELSE min_account_age_days END WHERE guild_id=?',BigInt(guild.id))
  db.run('UPDATE guardian_config SET external_app_lock=1,bot_approval=1,webhook_guard=1,integration_guard=1,credential_guard=1,rollback_enabled=1 WHERE guild_id=?',BigInt(guild.id))
  await saveSnapshot(db,guild,true)
  const result=await lockExternalApps(guild)
  return{rolesChanged:result.changed,failed:result.failed}
}
async function deleteUnapprovedWebhooks(db,guild,channel=null){
  const approved=new Set(db.all('SELECT webhook_id FROM approved_webhooks WHERE guild_id=?',BigInt(guild.id)).map(r=>String(r.webhook_id)))
  const hooks=channel&&channel.fetchWebhooks?await channel.fetchWebhooks().catch(()=>null):await guild.fetchWebhooks().catch(()=>null)
  if(!hooks)return 0
  let removed=0
  for(const hook of hooks.values()){
    if(approved.has(String(hook.id)))continue
    const ok=await hook.delete('ESN Guardian: unauthorized webhook').then(()=>true).catch(()=>false)
    if(ok){
      removed++
      await securityCase(db,guild,hook.user||null,'WEBHOOK_DESTROYED','Deleted unauthorized webhook '+(hook.name||hook.id),channel?.id||hook.channelId||null)
    }else{
      await securityCase(db,guild,hook.user||null,'WEBHOOK_DESTROY_FAILED','Could not delete unauthorized webhook '+(hook.name||hook.id),channel?.id||hook.channelId||null)
    }
  }
  return removed
}
async function removeUnapprovedIntegrations(db,guild){
  const key=String(guild.id)
  if(integrationLocks.has(key))return 0
  integrationLocks.add(key)
  try{
    await ensureSafeBaseline(db,guild)
    const rows=db.all('SELECT integration_id,application_id FROM approved_integrations WHERE guild_id=?',BigInt(guild.id))
    const approvedIds=new Set(rows.map(r=>String(r.integration_id)))
    const approvedApps=new Set(rows.filter(r=>r.application_id!=null).map(r=>String(r.application_id)))
    const integrations=await guild.fetchIntegrations().catch(()=>null)
    if(!integrations)return 0
    let removed=0
    for(const integration of integrations.values()){
      const appId=integration.application?.id
      const userId=integration.user?.id
      if(String(appId||userId||'')===String(guild.client.user?.id))continue
      if(approvedIds.has(String(integration.id))||(appId&&approvedApps.has(String(appId))))continue
      const ok=typeof integration.delete==='function'
        ?await integration.delete('ESN Guardian: unauthorized integration').then(()=>true).catch(()=>false)
        :false
      if(ok){
        removed++
        await securityCase(db,guild,integration.user||null,'INTEGRATION_REMOVED','Removed unauthorized integration '+(integration.name||integration.id))
      }else{
        await securityCase(db,guild,integration.user||null,'INTEGRATION_REMOVE_FAILED','Could not remove unauthorized integration '+(integration.name||integration.id))
      }
    }
    return removed
  }finally{
    integrationLocks.delete(key)
  }
}
async function banUnapprovedBots(db,guild){
  let removed=0
  for(const member of guild.members.cache.values()){
    if(!member.user.bot||member.id===guild.members.me?.id||isApprovedBot(db,guild.id,member.id))continue
    const ok=await guild.members.ban(member.id,{reason:'ESN Guardian: bot is not approved',deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
    if(ok){
      removed++
      await securityCase(db,guild,member,'UNAPPROVED_BOT_BANNED','Banned unapproved bot '+member.user.tag+' ('+member.id+')')
    }else{
      await securityCase(db,guild,member,'UNAPPROVED_BOT_BAN_FAILED','Could not ban unapproved bot '+member.user.tag+' ('+member.id+')')
    }
  }
  return removed
}
async function panicGuild(db,guild,enabled){
  db.ensureGuild(guild.id)
  if(!enabled){
    db.run('UPDATE guardian_config SET panic_mode=0 WHERE guild_id=?',BigInt(guild.id))
    const restored=await unlockdownGuild(db,guild,'Guardian PANIC mode released by server owner')
    await securityCase(db,guild,guild.ownerId,'GUARDIAN_PANIC_RELEASED','Emergency containment released')
    return{enabled:false,restored}
  }
  await saveSnapshot(db,guild,false)
  const external=await lockExternalApps(guild)
  const bots=await banUnapprovedBots(db,guild)
  const hooks=await deleteUnapprovedWebhooks(db,guild)
  const integrations=await removeUnapprovedIntegrations(db,guild)
  db.run('UPDATE guardian_config SET panic_mode=1,external_app_lock=1,bot_approval=1,webhook_guard=1,integration_guard=1,credential_guard=1,rollback_enabled=1 WHERE guild_id=?',BigInt(guild.id))
  db.run('UPDATE anti_nuke_config SET enabled=1,action_limit=2,window_seconds=15 WHERE guild_id=?',BigInt(guild.id))
  db.run('UPDATE security_config SET automod_enabled=1,flood_limit=4,flood_window_seconds=10,max_mentions=4,block_invites=1,strict_links=1 WHERE guild_id=?',BigInt(guild.id))
  const locked=await lockdownGuild(db,guild,'Guardian PANIC mode')
  await securityCase(db,guild,guild.ownerId,'GUARDIAN_PANIC','Maximum emergency containment enabled')
  return{enabled:true,locked,botsRemoved:bots,webhooksRemoved:hooks,integrationsRemoved:integrations,externalChanged:external.changed,externalFailed:external.failed}
}
function overwriteData(saved,guild){
  return(saved.overwrites||[]).map(o=>({id:String(o.target_id),type:o.target_type==='role'?0:1,allow:BigInt(o.allow||'0'),deny:BigInt(o.deny||'0')}))
}
async function restoreDeletedChannel(db,guild,deleted){
  const key='channel:'+guild.id+':'+deleted.id
  if(rollbackGuard.has(key))return
  rollbackGuard.add(key)
  try{
    const restored=await deleted.clone({reason:'ESN Guardian automatic rollback of unauthorized channel deletion'})
    const edits={}
    if(Number.isFinite(Number(deleted.rawPosition)))edits.position=Number(deleted.rawPosition)
    if(deleted.type!==ChannelType.GuildCategory&&deleted.parentId){
      const category=guild.channels.cache.get(String(deleted.parentId))
      if(category?.type===ChannelType.GuildCategory)edits.parent=category.id
    }
    if(Object.keys(edits).length)await restored.edit({...edits,reason:'ESN Guardian rollback positioning'}).catch(()=>{})

    if(deleted.type===ChannelType.GuildCategory&&restored.type===ChannelType.GuildCategory){
      const snapshot=getSnapshot(db,guild.id)
      if(snapshot){
        for(const item of snapshot.channels||[]){
          if(String(item.category_id)!==String(deleted.id))continue
          const child=guild.channels.cache.get(String(item.id))
          if(child)await child.setParent(restored.id,{lockPermissions:false,reason:'ESN Guardian category rollback'}).catch(()=>{})
        }
      }
    }
    await securityCase(db,guild,null,'AUTO_ROLLBACK_CHANNEL','Recreated deleted channel/category '+deleted.name)
  }catch{
    await securityCase(db,guild,null,'AUTO_ROLLBACK_FAILED','Could not recreate deleted channel/category '+deleted.name)
  }finally{
    setTimeout(()=>rollbackGuard.delete(key),3000).unref?.()
  }
}
async function restoreDeletedRole(db,guild,deleted){
  const key='role:'+guild.id+':'+deleted.id
  if(rollbackGuard.has(key))return
  rollbackGuard.add(key)
  try{
    const role=await guild.roles.create({
      name:deleted.name,
      permissions:deleted.permissions,
      color:deleted.color,
      hoist:deleted.hoist,
      mentionable:deleted.mentionable,
      reason:'ESN Guardian automatic rollback of unauthorized role deletion'
    })
    if(Number.isFinite(Number(deleted.position)))await role.setPosition(Number(deleted.position)).catch(()=>{})
    const snapshot=getSnapshot(db,guild.id)
    const saved=snapshot?.roles?.find(item=>String(item.id)===String(deleted.id))
    for(const memberId of saved?.members||[]){
      const member=guild.members.cache.get(String(memberId))
      if(member&&role.editable)await member.roles.add(role,'ESN Guardian role rollback').catch(()=>{})
    }
    await securityCase(db,guild,null,'AUTO_ROLLBACK_ROLE','Recreated deleted role '+deleted.name)
  }catch{
    await securityCase(db,guild,null,'AUTO_ROLLBACK_FAILED','Could not recreate deleted role '+deleted.name)
  }finally{
    setTimeout(()=>rollbackGuard.delete(key),3000).unref?.()
  }
}
function suspiciousLinkReason(text){
  const values=String(text||'').match(/(?:https?:\/\/|discord(?:app)?\.com\/invite\/|discord\.gg\/)[^\s]+/gi)||[]
  for(const value of values){
    try{
      const parsed=new URL(value.includes('://')?value:'https://'+value)
      if(parsed.username||parsed.password)return'Suspicious link with embedded credentials detected'
    }catch{}
  }
  for(const domain of extractDomains(text)){
    if(SHORTENERS.has(domain))return'URL shortener detected'
    if(SUSPICIOUS_DOMAIN_TOKENS.some(token=>domain.includes(token)))return'Known phishing-style domain detected'
    if(domain.startsWith('xn--'))return'Punycode lookalike domain detected'
    if(/^\[?[0-9a-f:.]+\]?$/i.test(domain)){
      if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)||domain.includes(':'))return'Direct IP link detected'
    }
  }
  return null
}
async function enforceViolation(db,message,reason,escalate=true){
  await message.delete().catch(()=>{})
  if(!escalate){await securityCase(db,message.guild,message.author,'AUTOMOD_STAFF_BLOCK',reason,message.channelId);return}
  const prior=db.get("SELECT COUNT(*) AS count FROM cases WHERE guild_id=? AND target_id=? AND action LIKE 'AUTOMOD_%' AND created_at>=datetime('now','-30 days')",BigInt(message.guild.id),BigInt(message.author.id))
  const count=Number(prior?.count||0)
  try{
    if(count===0)await securityCase(db,message.guild,message.author,'AUTOMOD_WARN',reason,message.channelId)
    else if(count===1){await message.member?.timeout(10*60*1000,'ESN Guardian: '+reason);await securityCase(db,message.guild,message.author,'AUTOMOD_TIMEOUT',reason+'; 10 minute timeout',message.channelId)}
    else if(count===2){await message.member?.timeout(60*60*1000,'ESN Guardian: '+reason);await securityCase(db,message.guild,message.author,'AUTOMOD_TIMEOUT',reason+'; 1 hour timeout',message.channelId)}
    else if(count===3){await message.member?.kick('ESN Guardian: '+reason);await securityCase(db,message.guild,message.author,'AUTOMOD_KICK',reason,message.channelId)}
    else{await message.guild.members.ban(message.author.id,{reason:'ESN Guardian: '+reason});await securityCase(db,message.guild,message.author,'AUTOMOD_BAN',reason,message.channelId)}
  }catch{await securityCase(db,message.guild,message.author,'AUTOMOD_ALERT','Could not fully enforce: '+reason,message.channelId)}
}
async function applyAutomod(db,message){
  if(!message.guild||message.author.bot)return false
  db.ensureGuild(message.guild.id)
  const text=message.content||'',lower=text.toLowerCase()

  const guardian=db.get('SELECT credential_guard FROM guardian_config WHERE guild_id=?',BigInt(message.guild.id))
  if(Number(guardian?.credential_guard??1)&&CREDENTIAL_PATTERNS.some(pattern=>pattern.test(text))){
    await message.delete().catch(()=>{})
    await message.member?.timeout(10*60*1000,'ESN Guardian: possible credential leak').catch(()=>{})
    await securityCase(db,message.guild,message.author,'CREDENTIAL_LEAK_BLOCKED','Message matched a high-confidence credential/token pattern',message.channelId)
    return true
  }

  const cfg=db.get('SELECT * FROM security_config WHERE guild_id=?',BigInt(message.guild.id))
  if(!cfg||!Number(cfg.automod_enabled))return false

  const key=message.guild.id+':'+message.author.id
  const now=Date.now(),windowMs=Number(cfg.flood_window_seconds||10)*1000
  const times=(messageWindows.get(key)||[]).filter(time=>now-time<=windowMs)
  times.push(now)
  messageWindows.set(key,times)
  const contents=(messageContentWindows.get(key)||[]).filter(item=>now-item.time<=windowMs)
  contents.push({time:now,text:lower.trim()})
  messageContentWindows.set(key,contents)

  let dangerous=suspiciousLinkReason(text)
  const hasInvite=lower.includes('discord.gg/')||lower.includes('discord.com/invite/')||lower.includes('discordapp.com/invite/')
  if(!dangerous&&Number(cfg.block_invites)&&hasInvite)dangerous='Unauthorized invite link'
  if(!dangerous&&Number(cfg.strict_links)){
    const allowed=new Set(db.all('SELECT domain FROM allowed_domains WHERE guild_id=?',BigInt(message.guild.id)).map(row=>String(row.domain).toLowerCase()))
    const denied=extractDomains(text).filter(domain=>![...allowed].some(base=>domain===base||domain.endsWith('.'+base)))
    if(denied.length)dangerous='External link is not allowlisted'
  }

  const permissions=message.member?.permissions
  const staff=Boolean(
    permissions?.has(PermissionFlagsBits.ManageMessages)||
    permissions?.has(PermissionFlagsBits.ManageGuild)||
    permissions?.has(PermissionFlagsBits.Administrator)
  )
  if(dangerous){
    await enforceViolation(db,message,dangerous,!staff)
    return true
  }
  if(staff)return false

  let violation=null
  if(times.length>=Number(cfg.flood_limit||6))violation='Message flood detected'
  else if(message.mentions.users.size+message.mentions.roles.size>=Number(cfg.max_mentions||6))violation='Mass mentions detected'
  else if(text.length>=12&&([...text].filter(character=>character>='A'&&character<='Z').length*100/Math.max(text.length,1))>=Number(cfg.caps_percentage||80))violation='Excessive capitals detected'
  else if(contents.filter(item=>item.text===lower.trim()).length>=3)violation='Repeated message detected'
  else{
    const words=db.all('SELECT word FROM bad_words WHERE guild_id=?',BigInt(message.guild.id))
    if(words.some(row=>lower.includes(String(row.word).toLowerCase())))violation='Blocked word detected'
  }
  if(violation){
    await enforceViolation(db,message,violation)
    return true
  }
  return false
}
async function blockExternalApp(db,guild,appId,channelId=null){
  if(!appId)return
  db.run(
    'INSERT INTO blocked_external_apps (guild_id,application_id,reason,last_detected_at) VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id,application_id) DO UPDATE SET reason=excluded.reason,last_detected_at=CURRENT_TIMESTAMP',
    BigInt(guild.id),BigInt(appId),'Zero-tolerance external app policy'
  )
  const appMember=guild.members.cache.get(String(appId))
  if(appMember?.user.bot){
    const banned=await guild.members.ban(appId,{reason:'ESN Guardian: blocked external application '+appId,deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
    await securityCase(
      db,guild,appMember,
      banned?'EXTERNAL_APP_BOT_BAN':'EXTERNAL_APP_BOT_BAN_FAILED',
      (banned?'Blocked':'Could not ban blocked')+' external application bot '+appId,
      channelId
    )
  }
  const integrations=await guild.fetchIntegrations().catch(()=>null)
  if(!integrations)return
  for(const integration of integrations.values()){
    if(String(integration.application?.id||'')!==String(appId))continue
    const removed=typeof integration.delete==='function'
      ?await integration.delete('ESN Guardian: blocked external application '+appId).then(()=>true).catch(()=>false)
      :false
    await securityCase(
      db,guild,integration.user||null,
      removed?'EXTERNAL_APP_INTEGRATION_REMOVED':'EXTERNAL_APP_INTEGRATION_REMOVE_FAILED',
      (removed?'Removed server integration for blocked application ':'Could not remove server integration for blocked application ')+appId,
      channelId
    )
  }
}
async function detectExternalApp(db,message){
  if(!message.guild)return false
  const meta=message.interactionMetadata||message.interaction
  if(!meta)return false
  let isUserIntegration=false
  try{isUserIntegration=Boolean(meta.isUserIntegration?.())}catch{}
  if(!isUserIntegration){
    const owners=meta.integrationOwners||meta.authorizingIntegrationOwners
    if(owners?.size||owners?.user) isUserIntegration=true
  }
  if(!isUserIntegration)return false

  const appId=message.applicationId||meta.applicationId||meta.application?.id||null
  const invoker=meta.user||null
  const reason='Zero-tolerance external app use detected; application_id='+(appId||'unknown')
  await blockExternalApp(db,message.guild,appId,message.channelId)
  await message.delete().catch(()=>{})

  if(!invoker){
    await securityCase(db,message.guild,null,'EXTERNAL_APP_BAN_FAILED',reason+'; Discord did not expose the invoking user',message.channelId)
    return true
  }
  const member=await message.guild.members.fetch(invoker.id).catch(()=>null)
  if(!member){
    await securityCase(db,message.guild,invoker,'EXTERNAL_APP_BAN_FAILED',reason+'; invoking member could not be resolved',message.channelId)
    return true
  }
  const banned=await message.guild.members.ban(member.id,{reason:'ESN Guardian: '+reason,deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
  await securityCase(
    db,message.guild,member,
    banned?'EXTERNAL_APP_BAN':'EXTERNAL_APP_BAN_FAILED',
    banned?reason:reason+'; Guardian could not ban the invoking member',
    message.channelId
  )
  return true
}
function pruneWindow(map,key,windowMs){const now=Date.now(),a=(map.get(key)||[]).filter(t=>now-t<=windowMs);map.set(key,a);return a}
function persistRaidRuntime(db,guildId,until){
  db.run(
    'INSERT INTO guardian_raid_runtime (guild_id,active_until_epoch,blocked_count,trigger_count,updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET active_until_epoch=excluded.active_until_epoch,blocked_count=excluded.blocked_count,trigger_count=excluded.trigger_count,updated_at=CURRENT_TIMESTAMP',
    BigInt(guildId),Math.floor(until/1000),
    raidBlockedCount.get(String(guildId))||0,
    raidTriggerCount.get(String(guildId))||0
  )
}
function queueRaidCase(member,reason){
  raidAuditBuffer.push([member.guild.id,member.id,member.client.user?.id,'RAID_JOIN_BLOCKED',reason,null,null])
  raidBlockedCount.set(String(member.guild.id),(raidBlockedCount.get(String(member.guild.id))||0)+1)
}
async function kickRaidMember(db,member,reason){
  const key=member.guild.id+':'+member.id
  try{
    if(member.user.bot||member.id===member.guild.ownerId)return
    if(member.roles.highest.comparePositionTo(member.guild.members.me.roles.highest)>=0){
      await securityCase(db,member.guild,member,'RAID_CONTAINMENT_DEGRADED','Could not remove raid member because target role is not below Guardian')
      return
    }
    markInternalRemoval(member.guild.id,member.id)
    const result=await member.kick('ESN Guardian raid containment: '+reason).then(()=>true).catch(error=>error?.code===10007?'left':false)
    if(result){
      queueRaidCase(member,result==='left'?reason+'; member already left':reason)
    }else{
      internalRemovals.delete(key)
      await securityCase(db,member.guild,member,'RAID_CONTAINMENT_DEGRADED','Raid removal failed; check Kick Members and role hierarchy')
    }
  }finally{raidQueued.delete(key)}
}
function pumpRaidQueue(db){
  while(raidActiveWorkers<5&&raidQueue.length){
    const item=raidQueue.shift()
    if(!item)break
    raidActiveWorkers++
    kickRaidMember(db,item.member,item.reason)
      .catch(()=>{})
      .finally(()=>{raidActiveWorkers--;pumpRaidQueue(db)})
  }
}
function queueRaidKick(db,member,reason){
  if(member.user.bot||member.id===member.guild.ownerId)return false
  const key=member.guild.id+':'+member.id
  if(raidQueued.has(key)||isInternalRemoval(member.guild.id,member.id))return false
  raidQueued.add(key)
  if(raidQueue.length>=RAID_QUEUE_MAX){
    raidQueued.delete(key)
    kickRaidMember(db,member,reason).catch(()=>{})
    return true
  }
  raidQueue.push({member,reason})
  pumpRaidQueue(db)
  return true
}
async function activateRaid(db,guild,reason,recentIds=[]){
  const until=Date.now()+RAID_CONTAINMENT_MS
  raidModeUntil.set(String(guild.id),until)
  raidTriggerCount.set(String(guild.id),(raidTriggerCount.get(String(guild.id))||0)+1)
  persistRaidRuntime(db,guild.id,until)
  let queued=0
  for(const memberId of recentIds){
    const member=guild.members.cache.get(String(memberId))
    if(member&&queueRaidKick(db,member,reason))queued++
  }
  lockdownGuild(db,guild,'Automatic raid lockdown: '+reason).catch(()=>{})
  securityCase(db,guild,null,'RAID_MODE','Raid containment enabled for 5 minutes; '+reason+'; queued removals: '+queued).catch(()=>{})
}
async function quarantineMember(db,member,reason,moderatorId=null){
  const cfg=db.get('SELECT quarantine_role_id FROM raid_config WHERE guild_id=?',BigInt(member.guild.id))
  const role=cfg?.quarantine_role_id?member.guild.roles.cache.get(String(cfg.quarantine_role_id)):null
  if(!role||role.id===member.guild.id||role.managed||!role.editable||dangerousRole(role)||member.id===member.guild.ownerId){
    await securityCase(db,member.guild,member,'QUARANTINE_ALERT','Could not quarantine member: '+reason)
    return false
  }
  const added=await member.roles.add(role,'ESN Guardian quarantine: '+reason).then(()=>true).catch(()=>false)
  if(!added){
    await securityCase(db,member.guild,member,'QUARANTINE_ALERT','Could not quarantine member: '+reason)
    return false
  }
  const caseId=db.createCase(member.guild.id,member.id,moderatorId||member.client.user?.id,'QUARANTINE',reason)
  await logEvent(db,member.guild,'security_log_channel_id','Security: QUARANTINE | Case #'+caseId,'Target: <@'+member.id+'>\nReason: '+reason)
  return true
}
async function handleRaidJoin(db,member){
  const guild=member.guild
  db.ensureGuild(guild.id)
  const cfg=db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(guild.id))
  if(!cfg||!Number(cfg.enabled)||member.user.bot)return

  const now=Date.now(),g=String(guild.id),windowMs=Number(cfg.join_window_seconds||60)*1000
  const normal=pruneWindow(joins,g,windowMs);normal.push(now);joins.set(g,normal)
  const fast=pruneWindow(fastJoins,g,RAID_FAST_WINDOW_MS);fast.push(now);fastJoins.set(g,fast)
  const ageMs=now-member.user.createdTimestamp
  const minDays=Number(cfg.min_account_age_days||0)
  const ageDays=Math.floor(ageMs/86400000)
  const isYoung=minDays>0&&ageMs<minDays*86400000
  const young=pruneWindow(youngJoins,g,RAID_YOUNG_WINDOW_MS)
  if(isYoung)young.push(now)
  youngJoins.set(g,young)
  const recent=(recentJoinMembers.get(g)||[]).filter(item=>now-item.time<=windowMs)
  recent.push({time:now,id:member.id})
  recentJoinMembers.set(g,recent)

  if(isRaidModeActive(guild.id)){
    const until=now+RAID_CONTAINMENT_MS
    raidModeUntil.set(g,until)
    persistRaidRuntime(db,guild.id,until)
    queueRaidKick(db,member,'Server is in active raid containment mode')
    return
  }

  let reason=null
  const fastLimit=fastBurstLimit(Number(cfg.join_limit||10))
  if(fast.length>=fastLimit)reason='Fast join burst: '+fast.length+' members/5s (fast threshold '+fastLimit+')'
  else if(minDays>0&&young.length>=3)reason='Young-account burst: '+young.length+' accounts under '+minDays+' days/15s'
  else if(normal.length>=Number(cfg.join_limit||10))reason='Join surge: '+normal.length+' members reached configured limit '+cfg.join_limit

  if(reason){
    const burstCap=Math.min(200,Math.max(25,Number(cfg.join_limit||10)*2))
    const ids=recent.slice(-burstCap).map(item=>item.id)
    await activateRaid(db,guild,reason,ids)
    return
  }

  if(isYoung){
    const why='Account is younger than '+minDays+' days (age: '+ageDays+' days)'
    await securityCase(db,guild,member,'SUSPICIOUS_JOIN',why)
    await quarantineMember(db,member,why)
  }
}
async function restoreRaidRuntime(db,client){
  const now=Math.floor(Date.now()/1000)
  const rows=db.all('SELECT guild_id,active_until_epoch,blocked_count,trigger_count FROM guardian_raid_runtime WHERE active_until_epoch>?',now)
  for(const row of rows){
    const key=String(row.guild_id)
    raidModeUntil.set(key,Number(row.active_until_epoch)*1000)
    raidBlockedCount.set(key,Number(row.blocked_count||0))
    raidTriggerCount.set(key,Number(row.trigger_count||0))
  }
}
async function securityAudit(db,guild){
  db.ensureGuild(guild.id)
  const me=guild.members.me
  const required=[
    ['view audit log',PermissionFlagsBits.ViewAuditLog],['manage messages',PermissionFlagsBits.ManageMessages],
    ['moderate members',PermissionFlagsBits.ModerateMembers],['kick members',PermissionFlagsBits.KickMembers],
    ['ban members',PermissionFlagsBits.BanMembers],['manage roles',PermissionFlagsBits.ManageRoles],
    ['manage channels',PermissionFlagsBits.ManageChannels],['manage webhooks',PermissionFlagsBits.ManageWebhooks]
  ]
  const missing=required.filter(([,bit])=>!me?.permissions.has(bit)).map(([name])=>name)
  const riskyRoles=guild.roles.cache.filter(role=>role.id!==guild.id&&!role.managed&&dangerousRole(role))
  const unknownBots=guild.members.cache.filter(member=>member.user.bot&&member.id!==me?.id&&!isApprovedBot(db,guild.id,member.id))
  const externalRoles=guild.roles.cache.filter(role=>role.permissions.has(PermissionFlagsBits.UseExternalApps))
  const guardian=db.get('SELECT * FROM guardian_config WHERE guild_id=?',BigInt(guild.id))
  let webhookCount=0
  const hooks=await guild.fetchWebhooks().catch(()=>null)
  if(hooks)webhookCount=hooks.size
  const deductions=Math.min(100,missing.length*10+unknownBots.size*12+externalRoles.size*5+(!Number(guardian?.rollback_enabled)?10:0)+(!Number(guardian?.webhook_guard)?10:0))
  return{
    score:Math.max(0,100-deductions),
    missing,
    riskyRoles:riskyRoles.size,
    unapprovedBots:[...unknownBots.values()].map(member=>member.user.tag||member.user.username||member.id),
    externalEnabled:externalRoles.size,
    webhookCount,
    guardian
  }
}
function attachSecurity(client,db){
  client.guardianSecurity={
    isRaidModeActive,
    isInternalRemoval,
    lockdownGuild:(g,r)=>lockdownGuild(db,g,r),
    unlockdownGuild:(g,r)=>unlockdownGuild(db,g,r),
    saveSnapshot:(g,a=true)=>saveSnapshot(db,g,a),
    hardenGuild:g=>hardenGuild(db,g),
    panicGuild:(g,e)=>panicGuild(db,g,e),
    securityAudit:g=>securityAudit(db,g),
    ensureSafeBaseline:g=>ensureSafeBaseline(db,g),
    quarantineMember:(member,reason,moderatorId)=>quarantineMember(db,member,reason,moderatorId),
    raidStats:guildId=>({
      active:isRaidModeActive(guildId),
      until:raidModeUntil.get(String(guildId))||null,
      queueDepth:raidQueue.length,
      activeWorkers:raidActiveWorkers,
      blocked:raidBlockedCount.get(String(guildId))||0,
      triggers:raidTriggerCount.get(String(guildId))||0
    })
  }

  client.once(Events.ClientReady,async()=>{
    await restoreRaidRuntime(db,client)
    for(const guild of client.guilds.cache.values())await ensureSafeBaseline(db,guild).catch(()=>{})
  })
  client.on(Events.MessageCreate,async message=>{
    try{if(await detectExternalApp(db,message))return;await applyAutomod(db,message)}catch(error){console.error('[Guardian] message security error',error)}
  })
  client.on(Events.GuildMemberAdd,async member=>{
    try{
      db.ensureGuild(member.guild.id)
      const global=db.globalBanReason(member.id)
      if(global&&member.bannable){markInternalRemoval(member.guild.id,member.id);await member.ban({reason:'ESN Guardian global ban: '+global}).catch(()=>{});return}
      if(member.user.bot&&member.id!==client.user?.id){
        const blocked=db.get('SELECT application_id FROM blocked_external_apps WHERE guild_id=? AND application_id=?',BigInt(member.guild.id),BigInt(member.id))
        if(blocked){
          const banned=await member.guild.members.ban(member.id,{reason:'ESN Guardian: application '+member.id+' is permanently blocked',deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
          await securityCase(db,member.guild,member,banned?'EXTERNAL_APP_REBAN':'EXTERNAL_APP_REBAN_FAILED',(banned?'Blocked application ':'Could not ban blocked application ')+member.id+(banned?' attempted to join the server':' after it joined'))
          return
        }

        const actor=await securityAuditActor(db,member.guild,AuditLogEvent.BotAdd,member.id)
        const anti=db.get('SELECT enabled FROM anti_nuke_config WHERE guild_id=?',BigInt(member.guild.id))
        if(Number(anti?.enabled)&&!trustedUser(db,member.guild,actor?.id)){
          const removed=await member.kick('ESN Guardian anti-nuke: untrusted bot addition').then(()=>true).catch(()=>false)
          await securityCase(
            db,member.guild,actor,
            removed?'BOT_ADD_BLOCKED':'ANTINUKE_CONTAINMENT_FAILED',
            removed?'Removed untrusted bot '+member.user.tag+' ('+member.id+')':'Could not remove untrusted bot '+member.user.tag+' ('+member.id+')'
          )
          await checkNukeAction(db,member.guild,actor,'untrusted bot addition',{allowUnattributed:true,targetId:member.id})
        }

        const config=db.get('SELECT bot_approval FROM guardian_config WHERE guild_id=?',BigInt(member.guild.id))
        if(Number(config?.bot_approval??1)&&!isApprovedBot(db,member.guild.id,member.id)){
          const banned=await member.guild.members.ban(member.id,{reason:'ESN Guardian: unapproved bot addition',deleteMessageSeconds:0}).then(()=>true).catch(()=>false)
          await securityCase(db,member.guild,actor,banned?'UNAPPROVED_BOT_BANNED':'UNAPPROVED_BOT_BAN_FAILED',(banned?'Banned':'Could not ban')+' unapproved bot '+member.user.tag+' ('+member.id+')')
          if(!trustedUser(db,member.guild,actor?.id))await containActor(db,member.guild,actor,'Added unapproved bot '+member.id)
        }
        return
      }
      await handleRaidJoin(db,member)
    }catch(error){console.error('[Guardian] member join security error',error)}
  })
  client.on(Events.ChannelCreate,async channel=>{
    try{
      const actor=await securityAuditActor(db,channel.guild,AuditLogEvent.ChannelCreate,channel.id)
      await checkNukeAction(db,channel.guild,actor,'channel creation',{allowUnattributed:true,targetId:channel.id})
    }catch{}
  })
  client.on(Events.ChannelDelete,async channel=>{
    try{
      db.createCase(channel.guild.id,null,client.user?.id,'CHANNEL_DELETE','Channel deleted: '+channel.name,channel.id)
      const actor=await securityAuditActor(db,channel.guild,AuditLogEvent.ChannelDelete,channel.id)
      await checkNukeAction(db,channel.guild,actor,'channel deletion',{allowUnattributed:true,targetId:channel.id})
      await recordDestructive(db,channel.guild,actor,'channel deletion')
      const cfg=db.get('SELECT rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(channel.guild.id))
      if(Number(cfg?.rollback_enabled??1)&&!trustedUser(db,channel.guild,actor?.id))await restoreDeletedChannel(db,channel.guild,channel)
    }catch(error){console.error('[Guardian] channel delete handler error',error)}
  })
  client.on(Events.ChannelUpdate,async(before,after)=>{
    try{
      const critical=before.name!==after.name||before.rawPosition!==after.rawPosition||JSON.stringify(before.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})))!==JSON.stringify(after.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})))
      if(!critical)return
      const actor=await securityAuditActor(db,after.guild,AuditLogEvent.ChannelUpdate,after.id)
      if(before.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})).toString()!==after.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})).toString()){
        await checkNukeAction(db,after.guild,actor,'channel permission update',{allowUnattributed:true,targetId:after.id})
      }
      await recordDestructive(db,after.guild,actor,'channel modification')
      const cfg=db.get('SELECT rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(after.guild.id))
      if(!Number(cfg?.rollback_enabled??1)||trustedUser(db,after.guild,actor?.id))return
      const options={name:before.name,position:before.rawPosition,permissionOverwrites:before.permissionOverwrites.cache.map(o=>({id:o.id,type:o.type,allow:o.allow.bitfield,deny:o.deny.bitfield}))}
      if('parentId'in before)options.parent=before.parentId
      if('topic'in before)options.topic=before.topic
      if('rateLimitPerUser'in before)options.rateLimitPerUser=before.rateLimitPerUser
      await after.edit({...options,reason:'ESN Guardian automatic rollback of unauthorized channel change'}).then(()=>securityCase(db,after.guild,actor,'AUTO_ROLLBACK_CHANNEL_UPDATE','Reverted unauthorized changes to '+after.name,after.id)).catch(()=>securityCase(db,after.guild,actor,'AUTO_ROLLBACK_FAILED','Could not revert unauthorized changes to '+after.name,after.id))
    }catch(error){console.error('[Guardian] channel update rollback error',error)}
  })
  client.on(Events.GuildRoleCreate,async role=>{
    try{
      const actor=await securityAuditActor(db,role.guild,AuditLogEvent.RoleCreate,role.id)
      await checkNukeAction(db,role.guild,actor,'role creation',{allowUnattributed:true,targetId:role.id})
    }catch{}
  })
  client.on(Events.GuildRoleDelete,async role=>{
    try{
      db.createCase(role.guild.id,null,client.user?.id,'ROLE_DELETE','Role deleted: '+role.name)
      const actor=await securityAuditActor(db,role.guild,AuditLogEvent.RoleDelete,role.id)
      await checkNukeAction(db,role.guild,actor,'role deletion',{allowUnattributed:true,targetId:role.id})
      await recordDestructive(db,role.guild,actor,'role deletion')
      const cfg=db.get('SELECT rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(role.guild.id))
      if(Number(cfg?.rollback_enabled??1)&&!trustedUser(db,role.guild,actor?.id))await restoreDeletedRole(db,role.guild,role)
    }catch{}
  })
  client.on(Events.GuildRoleUpdate,async(before,after)=>{
    try{
      if(before.permissions.bitfield===after.permissions.bitfield&&before.position===after.position)return
      db.createCase(after.guild.id,null,client.user?.id,'ROLE_PERMISSION_CHANGE','Permissions or position changed for '+after.name)
      const actor=await securityAuditActor(db,after.guild,AuditLogEvent.RoleUpdate,after.id)
      const anti=db.get('SELECT enabled FROM anti_nuke_config WHERE guild_id=?',BigInt(after.guild.id))
      const gained=[PermissionFlagsBits.Administrator,PermissionFlagsBits.ManageGuild,PermissionFlagsBits.ManageRoles,PermissionFlagsBits.ManageChannels,PermissionFlagsBits.ManageWebhooks,PermissionFlagsBits.BanMembers,PermissionFlagsBits.KickMembers,PermissionFlagsBits.ModerateMembers].some(bit=>after.permissions.has(bit)&&!before.permissions.has(bit))
      if(Number(anti?.enabled)&&gained&&!trustedUser(db,after.guild,actor?.id)){
        const reverted=await after.edit({permissions:before.permissions,reason:'ESN Guardian anti-nuke: reverted dangerous role permission escalation'}).then(()=>true).catch(()=>false)
        await securityCase(db,after.guild,actor,reverted?'ANTINUKE_ROLE_REVERT':'ANTINUKE_ROLE_REVERT_FAILED',(reverted?'Reverted':'Could not revert')+' dangerous permissions on '+after.name)
      }
      if(before.permissions.bitfield!==after.permissions.bitfield){
        await checkNukeAction(db,after.guild,actor,gained?'dangerous role permission escalation':'role permission change',{allowUnattributed:true,targetId:after.id})
      }
      await recordDestructive(db,after.guild,actor,'role permission/position change')
      const botRole=after.guild.members.me?.roles.cache.has(after.id)
      if(botRole&&actor?.id!==after.guild.ownerId){
        await after.edit({permissions:before.permissions,position:before.position,reason:'ESN Guardian tamper protection'}).then(()=>securityCase(db,after.guild,actor,'GUARDIAN_TAMPER_REVERTED','Reverted change to Guardian role '+after.name)).catch(()=>securityCase(db,after.guild,actor,'GUARDIAN_TAMPER_ALERT','Guardian role '+after.name+' changed and could not be restored'))
      }
    }catch{}
  })
  client.on(Events.GuildMemberUpdate,async(before,after)=>{
    try{
      if(after.id===client.user?.id){
        const removed=before.roles.cache.filter(r=>r.id!==after.guild.id&&!after.roles.cache.has(r.id))
        if(removed.size){
          const actor=await securityAuditActor(db,after.guild,AuditLogEvent.MemberRoleUpdate,after.id)
          if(actor?.id!==after.guild.ownerId){
            let restored=0
            for(const role of removed.values())if(role.editable)await after.roles.add(role,'ESN Guardian tamper protection').then(()=>restored++).catch(()=>{})
            await securityCase(db,after.guild,actor,'GUARDIAN_TAMPER_ALERT','Guardian roles removed; restored '+restored+'/'+removed.size)
          }
        }
        return
      }
      const added=after.roles.cache.filter(r=>!before.roles.cache.has(r.id)&&dangerousRole(r))
      if(added.size){
        const anti=db.get('SELECT enabled FROM anti_nuke_config WHERE guild_id=?',BigInt(after.guild.id))
        if(!Number(anti?.enabled))return
        const actor=await securityAuditActor(db,after.guild,AuditLogEvent.MemberRoleUpdate,after.id)
        if(trustedUser(db,after.guild,actor?.id))return
        const removable=added.filter(r=>r.editable)
        if(removable.size){
          const ok=await after.roles.remove([...removable.values()],'ESN Guardian anti-nuke: reverted dangerous role assignment').then(()=>true).catch(()=>false)
          await securityCase(db,after.guild,actor,ok?'ANTINUKE_ROLE_ASSIGNMENT_REVERT':'ANTINUKE_ROLE_ASSIGNMENT_REVERT_FAILED',(ok?'Removed':'Could not remove')+' dangerous roles from '+after.user.tag)
        }else await securityCase(db,after.guild,actor,'ANTINUKE_ROLE_ASSIGNMENT_UNMANAGEABLE','Dangerous role assigned to '+after.user.tag+', but it is above Guardian role')
        await checkNukeAction(db,after.guild,actor,'dangerous role assignment',{allowUnattributed:true,targetId:after.id})
      }
    }catch{}
  })
  client.on(Events.GuildBanAdd,async ban=>{
    try{
      await logEvent(db,ban.guild,'member_log_channel_id','Member banned','User: <@'+ban.user.id+'> ('+ban.user.id+')')
      const actor=await securityAuditActor(db,ban.guild,AuditLogEvent.MemberBanAdd,ban.user.id)
      await checkNukeAction(db,ban.guild,actor,'member ban',{allowUnattributed:true,targetId:ban.user.id})
      await recordDestructive(db,ban.guild,actor,'member ban')
    }catch{}
  })
  client.on(Events.GuildMemberRemove,async member=>{
    if(isInternalRemoval(member.guild.id,member.id))return
    try{
      const actor=await securityAuditActor(db,member.guild,AuditLogEvent.MemberKick,member.id)
      if(actor){
        await checkNukeAction(db,member.guild,actor,'member kick',{targetId:member.id})
        await recordDestructive(db,member.guild,actor,'member kick')
      }
    }catch{}
  })
  client.on(Events.GuildBanRemove,async ban=>{
    try{
      const actor=await securityAuditActor(db,ban.guild,AuditLogEvent.MemberBanRemove,ban.user.id)
      await checkNukeAction(db,ban.guild,actor,'member unban',{allowUnattributed:true,targetId:ban.user.id})
    }catch{}
  })
  client.on(Events.WebhooksUpdate,async channel=>{
    try{
      db.createCase(channel.guild.id,null,client.user?.id,'WEBHOOK_CHANGE','Webhook update in #'+channel.name,channel.id)
      const cfg=db.get('SELECT webhook_guard FROM guardian_config WHERE guild_id=?',BigInt(channel.guild.id));if(!Number(cfg?.webhook_guard??1))return
      const actor=await securityAuditActor(db,channel.guild,AuditLogEvent.WebhookCreate,null)
      if(trustedUser(db,channel.guild,actor?.id)){
        const hooks=await channel.fetchWebhooks().catch(()=>null);if(hooks)for(const hook of hooks.values())db.run('INSERT OR IGNORE INTO approved_webhooks (guild_id,webhook_id) VALUES (?,?)',BigInt(channel.guild.id),BigInt(hook.id))
      }else{
        const removed=await deleteUnapprovedWebhooks(db,channel.guild,channel)
        if(removed){
          await checkNukeAction(db,channel.guild,actor,'webhook change',{allowUnattributed:true,targetId:channel.id})
          await recordDestructive(db,channel.guild,actor,'unauthorized webhook creation')
        }
      }
    }catch(error){console.error('[Guardian] webhook guard error',error)}
  })
  client.on(Events.GuildIntegrationsUpdate,async guild=>{
    try{
      const cfg=db.get('SELECT integration_guard FROM guardian_config WHERE guild_id=?',BigInt(guild.id));if(!Number(cfg?.integration_guard??1))return
      const actor=await securityAuditActor(db,guild,AuditLogEvent.IntegrationCreate,null)
      if(trustedUser(db,guild,actor?.id)){const integrations=await guild.fetchIntegrations().catch(()=>null);if(integrations)for(const integration of integrations.values())db.run('INSERT OR IGNORE INTO approved_integrations (guild_id,integration_id,application_id) VALUES (?,?,?)',BigInt(guild.id),BigInt(integration.id),integration.application?.id?BigInt(integration.application.id):null)}
      else{
        const removed=await removeUnapprovedIntegrations(db,guild)
        if(removed)await recordDestructive(db,guild,actor,'unauthorized integration')
      }
    }catch(error){console.error('[Guardian] integration guard error',error)}
  })

  const raidAuditTimer=setInterval(()=>{
    if(!raidAuditBuffer.length)return
    const batch=raidAuditBuffer.splice(0,200)
    try{db.createCasesBulk(batch)}
    catch{raidAuditBuffer.unshift(...batch)}
  },1000)
  raidAuditTimer.unref?.()

  const snapshotTimer=setInterval(async()=>{for(const guild of client.guilds.cache.values()){try{const existing=db.get('SELECT 1 AS ok FROM guardian_snapshots WHERE guild_id=?',BigInt(guild.id));await saveSnapshot(db,guild,!existing)}catch{}}},30*60*1000)
  snapshotTimer.unref?.()
  const integrationTimer=setInterval(async()=>{for(const guild of client.guilds.cache.values()){try{const cfg=db.get('SELECT integration_guard FROM guardian_config WHERE guild_id=?',BigInt(guild.id));if(Number(cfg?.integration_guard??1))await removeUnapprovedIntegrations(db,guild)}catch{}}},5*60*1000)
  integrationTimer.unref?.()
  const raidExpiry=setInterval(()=>{for(const [id,until] of raidModeUntil){if(until<=Date.now()){raidModeUntil.delete(id);db.run('UPDATE guardian_raid_runtime SET active_until_epoch=0,updated_at=CURRENT_TIMESTAMP WHERE guild_id=?',BigInt(id))}}},30000)
  raidExpiry.unref?.()
}
module.exports={
  attachSecurity,saveSnapshot,getSnapshot,hardenGuild,panicGuild,lockdownGuild,unlockdownGuild,
  containActor,securityAudit,trustedUser,isApprovedBot,isRaidModeActive,isInternalRemoval,
  quarantineMember,checkNukeAction,recordDestructive
}
