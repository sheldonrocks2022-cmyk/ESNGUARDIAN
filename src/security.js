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

const actionWindows=new Map()
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
const raidQueue=[]
const raidQueued=new Set()
let raidWorkersRunning=false

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
  db.run('INSERT OR REPLACE INTO guardian_baseline_state (guild_id,initialized_at) VALUES (?,CURRENT_TIMESTAMP)',BigInt(guild.id))
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
  if(!actor||actor.id===guild.ownerId||actor.id===guild.members.me?.id||trustedUser(db,guild,actor.id))return false
  const member=await guild.members.fetch(actor.id).catch(()=>null)
  if(!member){await securityCase(db,guild,actor,'COMPROMISED_ADMIN_ALERT',reason);return false}
  let removed=0
  for(const role of member.roles.cache.filter(r=>r.id!==guild.id&&r.editable&&dangerousRole(r)).values()){
    await member.roles.remove(role,'ESN Guardian containment: '+reason).then(()=>removed++).catch(()=>{})
  }
  let contained=false
  if(member.moderatable)await member.timeout(24*60*60*1000,'ESN Guardian containment: '+reason).then(()=>contained=true).catch(()=>{})
  if(!contained&&member.bannable)await member.ban({reason:'ESN Guardian emergency containment: '+reason}).then(()=>contained=true).catch(()=>{})
  await securityCase(db,guild,member,'COMPROMISED_ADMIN_CONTAINED',reason,null,{removedRoles:removed,contained})
  return contained
}
async function registerDestructiveAction(db,guild,actor,action,targetId,forceLimit=3,forceWindowMs=10000){
  if(!actor||actor.bot||actor.id===guild.members.me?.id||trustedUser(db,guild,actor.id))return
  db.ensureGuild(guild.id)
  const cfg=db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id))
  const enabled=cfg&&Number(cfg.enabled)
  const limit=enabled?Number(cfg.action_limit||3):forceLimit
  const windowMs=enabled?Number(cfg.window_seconds||15)*1000:forceWindowMs
  const key=guild.id+':'+actor.id,now=Date.now(),history=(actionWindows.get(key)||[]).filter(t=>now-t<windowMs)
  history.push(now);actionWindows.set(key,history)
  if(enabled)await securityCase(db,guild,actor,'ANTINUKE_'+action,'Destructive action detected: '+action,null,{targetId})
  if(history.length>=limit){
    actionWindows.set(key,[])
    await containActor(db,guild,actor,'Compromised-admin protection: '+history.length+' destructive actions inside '+Math.round(windowMs/1000)+' seconds; latest='+action)
    if(enabled)await lockdownGuild(db,guild,'Automatic anti-nuke lockdown: '+action+' threshold exceeded')
  }
}
async function lockdownGuild(db,guild,reason='Security lockdown'){
  let changed=0
  for(const channel of guild.channels.cache.values()){
    if(!canLockChannel(channel))continue
    try{
      const current=channel.permissionOverwrites.cache.get(guild.id)
      const send=current?.allow?.has(PermissionFlagsBits.SendMessages)?1:current?.deny?.has(PermissionFlagsBits.SendMessages)?0:null
      db.run('INSERT OR REPLACE INTO lockdown_overwrites (guild_id,channel_id,send_messages) VALUES (?,?,?)',BigInt(guild.id),BigInt(channel.id),send)
      await channel.permissionOverwrites.edit(guild.roles.everyone,{SendMessages:false},{reason});changed++
    }catch{}
  }
  db.updateSetting(guild.id,'lockdown_active',1)
  db.createCase(guild.id,null,guild.client.user?.id,'LOCKDOWN',reason)
  return changed
}
async function unlockdownGuild(db,guild,reason='Security lockdown released'){
  const rows=db.all('SELECT * FROM lockdown_overwrites WHERE guild_id=?',BigInt(guild.id))
  let changed=0
  for(const row of rows){
    const channel=guild.channels.cache.get(String(row.channel_id));if(!channel||!canLockChannel(channel))continue
    let value=null;if(row.send_messages===1||row.send_messages===1n)value=true;if(row.send_messages===0||row.send_messages===0n)value=false
    await channel.permissionOverwrites.edit(guild.roles.everyone,{SendMessages:value},{reason}).then(()=>changed++).catch(()=>{})
  }
  db.run('DELETE FROM lockdown_overwrites WHERE guild_id=?',BigInt(guild.id))
  db.updateSetting(guild.id,'lockdown_active',0)
  db.createCase(guild.id,null,guild.client.user?.id,'UNLOCKDOWN',reason)
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
    await hook.delete('ESN Guardian: unauthorized webhook').then(()=>removed++).catch(()=>{})
  }
  return removed
}
async function removeUnapprovedIntegrations(db,guild){
  const key=String(guild.id);if(integrationLocks.has(key))return 0;integrationLocks.add(key)
  try{
    await ensureSafeBaseline(db,guild)
    const rows=db.all('SELECT integration_id,application_id FROM approved_integrations WHERE guild_id=?',BigInt(guild.id))
    const approvedIds=new Set(rows.map(r=>String(r.integration_id))),approvedApps=new Set(rows.filter(r=>r.application_id!=null).map(r=>String(r.application_id)))
    const integrations=await guild.fetchIntegrations().catch(()=>null);if(!integrations)return 0
    let removed=0
    for(const integration of integrations.values()){
      const appId=integration.application?.id,userId=integration.user?.id
      if(String(appId||userId||'')===String(guild.client.user?.id))continue
      if(approvedIds.has(String(integration.id))||(appId&&approvedApps.has(String(appId))))continue
      if(typeof integration.delete==='function')await integration.delete('ESN Guardian: unauthorized integration').then(()=>removed++).catch(()=>{})
    }
    return removed
  }finally{integrationLocks.delete(key)}
}
async function banUnapprovedBots(db,guild){
  let removed=0
  for(const member of guild.members.cache.values()){
    if(!member.user.bot||member.id===guild.members.me?.id||isApprovedBot(db,guild.id,member.id))continue
    if(member.bannable)await member.ban({reason:'ESN Guardian: bot is not approved'}).then(()=>removed++).catch(()=>{})
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
  const key='channel:'+guild.id+':'+deleted.id;if(rollbackGuard.has(key))return
  const snapshot=getSnapshot(db,guild.id),saved=snapshot?.channels?.find(x=>String(x.id)===String(deleted.id));if(!saved)return
  rollbackGuard.add(key)
  try{
    const options={name:saved.name,type:Number(saved.type),permissionOverwrites:overwriteData(saved,guild),reason:'ESN Guardian automatic rollback of unauthorized channel deletion'}
    if(saved.category_id&&guild.channels.cache.has(String(saved.category_id)))options.parent=String(saved.category_id)
    if(saved.topic!=null&&[ChannelType.GuildText,ChannelType.GuildAnnouncement,ChannelType.GuildForum].includes(Number(saved.type)))options.topic=saved.topic
    if(saved.slowmode_delay!=null)options.rateLimitPerUser=Number(saved.slowmode_delay)
    const recreated=await guild.channels.create(options)
    if(Number.isFinite(Number(saved.position)))await recreated.setPosition(Number(saved.position)).catch(()=>{})
    if(Number(saved.type)===ChannelType.GuildCategory){
      for(const childData of snapshot.channels.filter(x=>String(x.category_id)===String(deleted.id))){
        const child=guild.channels.cache.get(String(childData.id));if(child)await child.setParent(recreated.id,{lockPermissions:false,reason:'ESN Guardian category rollback'}).catch(()=>{})
      }
    }
    await securityCase(db,guild,null,'AUTO_ROLLBACK_CHANNEL','Recreated deleted channel/category '+saved.name)
  }catch{await securityCase(db,guild,null,'AUTO_ROLLBACK_FAILED','Could not recreate deleted channel/category '+deleted.name)}
  finally{setTimeout(()=>rollbackGuard.delete(key),3000).unref?.()}
}
async function restoreDeletedRole(db,guild,deleted){
  const key='role:'+guild.id+':'+deleted.id;if(rollbackGuard.has(key))return
  const snapshot=getSnapshot(db,guild.id),saved=snapshot?.roles?.find(x=>String(x.id)===String(deleted.id));if(!saved)return
  rollbackGuard.add(key)
  try{
    const role=await guild.roles.create({name:saved.name,permissions:BigInt(saved.permissions||'0'),color:Number(saved.colour||0),hoist:Boolean(saved.hoist),mentionable:Boolean(saved.mentionable),reason:'ESN Guardian automatic rollback of unauthorized role deletion'})
    if(Number.isFinite(Number(saved.position)))await role.setPosition(Number(saved.position)).catch(()=>{})
    for(const memberId of saved.members||[]){
      const member=guild.members.cache.get(String(memberId));if(member&&role.editable)await member.roles.add(role,'ESN Guardian role rollback').catch(()=>{})
    }
    await securityCase(db,guild,null,'AUTO_ROLLBACK_ROLE','Recreated deleted role '+saved.name)
  }catch{await securityCase(db,guild,null,'AUTO_ROLLBACK_FAILED','Could not recreate deleted role '+deleted.name)}
  finally{setTimeout(()=>rollbackGuard.delete(key),3000).unref?.()}
}
function suspiciousLinkReason(text){
  for(const domain of extractDomains(text)){
    if(SHORTENERS.has(domain))return'URL shortener detected'
    if(SUSPICIOUS_DOMAIN_TOKENS.some(token=>domain.includes(token)))return'Known phishing-style domain detected'
    if(domain.startsWith('xn--'))return'Punycode lookalike domain detected'
    if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain))return'Direct IP link detected'
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
  const cfg=db.get('SELECT * FROM security_config WHERE guild_id=?',BigInt(message.guild.id));if(!cfg||!Number(cfg.automod_enabled))return false
  const text=message.content||'',lower=text.toLowerCase()
  const guardian=db.get('SELECT credential_guard FROM guardian_config WHERE guild_id=?',BigInt(message.guild.id))
  if(Number(guardian?.credential_guard??1)&&CREDENTIAL_PATTERNS.some(p=>p.test(text))){
    await message.delete().catch(()=>{});await message.member?.timeout(10*60*1000,'ESN Guardian: possible credential leak').catch(()=>{})
    await securityCase(db,message.guild,message.author,'CREDENTIAL_LEAK_BLOCKED','Message matched a high-confidence credential/token pattern',message.channelId);return true
  }
  const suspicious=suspiciousLinkReason(text)
  const staff=message.member?.permissions?.has(PermissionFlagsBits.ManageGuild)
  if(suspicious){await enforceViolation(db,message,suspicious,!staff);return true}
  const words=db.all('SELECT word FROM bad_words WHERE guild_id=?',BigInt(message.guild.id))
  if(words.some(r=>lower.includes(String(r.word).toLowerCase()))){await enforceViolation(db,message,'Blocked word or phrase');return true}
  const mentions=message.mentions.users.size+message.mentions.roles.size
  if(mentions>Number(cfg.max_mentions||6)){await enforceViolation(db,message,'Mass mention count '+mentions);return true}
  const letters=text.replace(/[^a-z]/gi,'')
  if(letters.length>=12){const caps=letters.replace(/[^A-Z]/g,'').length,pct=Math.round(caps/letters.length*100);if(pct>=Number(cfg.caps_percentage||80)){await enforceViolation(db,message,'Caps percentage '+pct+'%');return true}}
  const key=message.guild.id+':'+message.author.id,now=Date.now(),windowMs=Number(cfg.flood_window_seconds||10)*1000
  const times=(messageWindows.get(key)||[]).filter(t=>now-t<=windowMs);times.push(now);messageWindows.set(key,times)
  const contents=(messageContentWindows.get(key)||[]).filter(x=>now-x.time<=windowMs);contents.push({time:now,text:lower.trim()});messageContentWindows.set(key,contents)
  if(times.length>Number(cfg.flood_limit||6)){messageWindows.set(key,[]);await enforceViolation(db,message,times.length+' messages in '+Math.round(windowMs/1000)+' seconds');return true}
  if(lower.trim().length>=4&&contents.filter(x=>x.text===lower.trim()).length>=3){await enforceViolation(db,message,'Repeated duplicate message spam');return true}
  if(Number(cfg.block_invites)&&/(?:discord\.gg|discord(?:app)?\.com\/invite)\//i.test(text)){await enforceViolation(db,message,'Discord invite blocked');return true}
  if(Number(cfg.strict_links)){
    const allowed=new Set(db.all('SELECT domain FROM allowed_domains WHERE guild_id=?',BigInt(message.guild.id)).map(r=>String(r.domain).toLowerCase()))
    const denied=extractDomains(text).filter(domain=>![...allowed].some(base=>domain===base||domain.endsWith('.'+base)))
    if(denied.length){await enforceViolation(db,message,'Blocked domains: '+denied.join(', '),!staff);return true}
  }
  return false
}
async function blockExternalApp(db,guild,appId){
  if(!appId)return
  db.run('INSERT INTO blocked_external_apps (guild_id,application_id,reason,last_detected_at) VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id,application_id) DO UPDATE SET reason=excluded.reason,last_detected_at=CURRENT_TIMESTAMP',BigInt(guild.id),BigInt(appId),'Zero-tolerance external app use detected')
  const appMember=guild.members.cache.get(String(appId));if(appMember?.user.bot&&appMember.bannable)await appMember.ban({reason:'Blocked external application'}).catch(()=>{})
  try{
    const integrations=await guild.fetchIntegrations()
    for(const integration of integrations.values())if(String(integration.application?.id||'')===String(appId)&&typeof integration.delete==='function')await integration.delete('ESN Guardian blocked external app').catch(()=>{})
  }catch{}
}
async function detectExternalApp(db,message){
  if(!message.guild)return false
  const meta=message.interactionMetadata||message.interaction
  let isUserIntegration=false
  try{isUserIntegration=Boolean(meta?.isUserIntegration?.())}catch{}
  const appId=message.applicationId||meta?.applicationId
  const invoker=meta?.user
  if(!appId||!invoker||invoker.id===message.client.user?.id)return false
  if(!isUserIntegration&&message.interactionMetadata?.integrationOwners?.size===0)return false
  await blockExternalApp(db,message.guild,appId)
  await message.delete().catch(()=>{})
  const member=await message.guild.members.fetch(invoker.id).catch(()=>null),reason='Zero-tolerance external app use detected; application_id='+appId
  if(member&&member.id!==message.guild.ownerId&&member.bannable){
    const banned=await member.ban({reason:'ESN Guardian: '+reason}).then(()=>true).catch(()=>false)
    await securityCase(db,message.guild,member,banned?'EXTERNAL_APP_BAN':'EXTERNAL_APP_BAN_FAILED',banned?reason:reason+'; Guardian could not ban the invoking member',message.channelId)
  }else await securityCase(db,message.guild,invoker,'EXTERNAL_APP_BAN_FAILED',reason+'; invoking member could not be banned',message.channelId)
  return true
}
function pruneWindow(map,key,windowMs){const now=Date.now(),a=(map.get(key)||[]).filter(t=>now-t<=windowMs);map.set(key,a);return a}
function persistRaidRuntime(db,guildId,until){
  db.run('INSERT INTO guardian_raid_runtime (guild_id,active_until_epoch,blocked_count,trigger_count,updated_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(guild_id) DO UPDATE SET active_until_epoch=excluded.active_until_epoch,blocked_count=excluded.blocked_count,trigger_count=excluded.trigger_count,updated_at=CURRENT_TIMESTAMP',BigInt(guildId),Math.floor(until/1000),Number(db.get("SELECT COUNT(*) AS c FROM cases WHERE guild_id=? AND action='RAID_JOIN_BLOCKED' AND created_at>=datetime('now','-1 hour')",BigInt(guildId))?.c||0),Number(db.get("SELECT COUNT(*) AS c FROM cases WHERE guild_id=? AND action='RAID_CONTAINMENT' AND created_at>=datetime('now','-1 day')",BigInt(guildId))?.c||0))
}
async function kickRaidMember(db,member,reason){
  const key=member.guild.id+':'+member.id
  try{
    if(member.user.bot||member.id===member.guild.ownerId)return
    if(member.roles.highest.comparePositionTo(member.guild.members.me.roles.highest)>=0){await securityCase(db,member.guild,member,'RAID_CONTAINMENT_DEGRADED','Could not remove raid member because target role is not below Guardian');return}
    markInternalRemoval(member.guild.id,member.id)
    const ok=await member.kick('ESN Guardian raid containment: '+reason).then(()=>true).catch(()=>false)
    if(ok||!member.guild.members.cache.has(member.id))db.createCase(member.guild.id,member.id,member.client.user?.id,'RAID_JOIN_BLOCKED',reason)
    else{internalRemovals.delete(key);await securityCase(db,member.guild,member,'RAID_CONTAINMENT_DEGRADED','Raid removal failed; check Kick Members and role hierarchy')}
  }finally{raidQueued.delete(key)}
}
async function raidWorker(db){
  if(raidWorkersRunning)return;raidWorkersRunning=true
  while(raidQueue.length){
    const item=raidQueue.shift()
    if(item)await kickRaidMember(db,item.member,item.reason)
  }
  raidWorkersRunning=false
}
function queueRaidKick(db,member,reason){
  if(member.user.bot||member.id===member.guild.ownerId)return false
  const key=member.guild.id+':'+member.id
  if(raidQueued.has(key)||isInternalRemoval(member.guild.id,member.id))return false
  raidQueued.add(key)
  if(raidQueue.length>=RAID_QUEUE_MAX){raidQueued.delete(key);kickRaidMember(db,member,reason);return true}
  raidQueue.push({member,reason})
  for(let i=0;i<5;i++)raidWorker(db)
  return true
}
async function activateRaid(db,guild,reason){
  const until=Date.now()+RAID_CONTAINMENT_MS;raidModeUntil.set(String(guild.id),until);persistRaidRuntime(db,guild.id,until)
  await lockdownGuild(db,guild,'ESN Guardian raid containment')
  db.createCase(guild.id,null,guild.client.user?.id,'RAID_CONTAINMENT',reason)
  await logEvent(db,guild,'security_log_channel_id','RAID CONTAINMENT ACTIVE',reason+'\nContainment is active for 5 minutes.')
  const recent=recentJoinMembers.get(String(guild.id))||[]
  for(const item of recent.filter(x=>Date.now()-x.time<=15000)){
    const member=guild.members.cache.get(item.id);if(member)queueRaidKick(db,member,reason)
  }
}
async function handleRaidJoin(db,member){
  const guild=member.guild;db.ensureGuild(guild.id)
  const cfg=db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(guild.id));if(!cfg||!Number(cfg.enabled)||member.user.bot)return
  const now=Date.now(),g=String(guild.id),windowMs=Number(cfg.join_window_seconds||60)*1000
  const normal=pruneWindow(joins,g,windowMs);normal.push(now);joins.set(g,normal)
  const fast=pruneWindow(fastJoins,g,RAID_FAST_WINDOW_MS);fast.push(now);fastJoins.set(g,fast)
  const age=now-member.user.createdTimestamp
  const isYoung=Number(cfg.min_account_age_days||3)>0&&age<Number(cfg.min_account_age_days)*86400000
  const young=pruneWindow(youngJoins,g,RAID_YOUNG_WINDOW_MS);if(isYoung)young.push(now);youngJoins.set(g,young)
  const recent=(recentJoinMembers.get(g)||[]).filter(x=>now-x.time<=Math.max(windowMs,15000));recent.push({time:now,id:member.id});recentJoinMembers.set(g,recent)
  if(isRaidModeActive(guild.id)){queueRaidKick(db,member,'Active raid containment');return}
  let reason=null
  if(fast.length>=fastBurstLimit(Number(cfg.join_limit||10)))reason='Fast join burst: '+fast.length+' members/5s'
  else if(isYoung&&young.length>=3)reason='Young-account burst: '+young.length+' accounts under '+cfg.min_account_age_days+' days/15s'
  else if(normal.length>=Number(cfg.join_limit||10))reason='Join surge: '+normal.length+' members reached configured limit '+cfg.join_limit
  else if(isYoung&&cfg.quarantine_role_id){
    const role=guild.roles.cache.get(String(cfg.quarantine_role_id));if(role?.editable)await member.roles.add(role,'ESN Guardian suspicious account quarantine').catch(()=>{})
  }
  if(reason)await activateRaid(db,guild,reason)
}
async function restoreRaidRuntime(db,client){
  const now=Math.floor(Date.now()/1000)
  const rows=db.all('SELECT guild_id,active_until_epoch FROM guardian_raid_runtime WHERE active_until_epoch>?',now)
  for(const row of rows)raidModeUntil.set(String(row.guild_id),Number(row.active_until_epoch)*1000)
}
function securityAudit(db,guild){
  db.ensureGuild(guild.id)
  const me=guild.members.me,required=[['View Audit Log',PermissionFlagsBits.ViewAuditLog],['Manage Roles',PermissionFlagsBits.ManageRoles],['Manage Channels',PermissionFlagsBits.ManageChannels],['Manage Webhooks',PermissionFlagsBits.ManageWebhooks],['Ban Members',PermissionFlagsBits.BanMembers],['Kick Members',PermissionFlagsBits.KickMembers],['Moderate Members',PermissionFlagsBits.ModerateMembers],['Manage Messages',PermissionFlagsBits.ManageMessages]]
  const missing=required.filter(([,bit])=>!me?.permissions.has(bit)).map(([name])=>name)
  const riskyRoles=guild.roles.cache.filter(r=>r.id!==guild.id&&dangerousRole(r))
  const unknownBots=guild.members.cache.filter(m=>m.user.bot&&m.id!==me?.id&&!isApprovedBot(db,guild.id,m.id))
  const externalRoles=guild.roles.cache.filter(r=>r.permissions.has(PermissionFlagsBits.UseExternalApps))
  const anti=db.get('SELECT * FROM anti_nuke_config WHERE guild_id=?',BigInt(guild.id)),raid=db.get('SELECT * FROM raid_config WHERE guild_id=?',BigInt(guild.id)),guardian=db.get('SELECT * FROM guardian_config WHERE guild_id=?',BigInt(guild.id))
  const deductions=Math.min(100,missing.length*10+unknownBots.size*12+externalRoles.size*5+(!Number(guardian?.rollback_enabled)?10:0)+(!Number(guardian?.webhook_guard)?10:0))
  return{score:100-deductions,missing,riskyRoles:riskyRoles.size,unapprovedBots:unknownBots.size,externalEnabled:externalRoles.size,antiNuke:Boolean(anti&&Number(anti.enabled)),raid:Boolean(raid&&Number(raid.enabled)),snapshot:Boolean(getSnapshot(db,guild.id)),guardian}
}
function attachSecurity(client,db){
  client.guardianSecurity={isRaidModeActive,isInternalRemoval,lockdownGuild:(g,r)=>lockdownGuild(db,g,r),unlockdownGuild:(g,r)=>unlockdownGuild(db,g,r),saveSnapshot:(g,a=true)=>saveSnapshot(db,g,a),hardenGuild:g=>hardenGuild(db,g),panicGuild:(g,e)=>panicGuild(db,g,e),securityAudit:g=>securityAudit(db,g),ensureSafeBaseline:g=>ensureSafeBaseline(db,g)}

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
        const config=db.get('SELECT bot_approval FROM guardian_config WHERE guild_id=?',BigInt(member.guild.id))
        if(Number(config?.bot_approval??1)&&!isApprovedBot(db,member.guild.id,member.id)){
          const actor=await auditActor(member.guild,AuditLogEvent.BotAdd,member.id)
          const banned=member.bannable?await member.ban({reason:'ESN Guardian: unapproved bot addition'}).then(()=>true).catch(()=>false):false
          await securityCase(db,member.guild,actor,banned?'UNAPPROVED_BOT_BANNED':'UNAPPROVED_BOT_BAN_FAILED','Unapproved bot '+member.id+' joined')
          if(!trustedUser(db,member.guild,actor?.id))await containActor(db,member.guild,actor,'Added unapproved bot '+member.id)
        }
        return
      }
      await handleRaidJoin(db,member)
    }catch(error){console.error('[Guardian] member join security error',error)}
  })
  client.on(Events.ChannelCreate,async channel=>{
    try{const actor=await auditActor(channel.guild,AuditLogEvent.ChannelCreate,channel.id);await registerDestructiveAction(db,channel.guild,actor,'CHANNEL_CREATE',channel.id)}catch{}
  })
  client.on(Events.ChannelDelete,async channel=>{
    try{
      db.createCase(channel.guild.id,null,client.user?.id,'CHANNEL_DELETE','Channel deleted: '+channel.name,channel.id)
      const actor=await auditActor(channel.guild,AuditLogEvent.ChannelDelete,channel.id)
      await registerDestructiveAction(db,channel.guild,actor,'CHANNEL_DELETE',channel.id)
      const cfg=db.get('SELECT rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(channel.guild.id))
      if(Number(cfg?.rollback_enabled??1)&&!trustedUser(db,channel.guild,actor?.id))await restoreDeletedChannel(db,channel.guild,channel)
    }catch(error){console.error('[Guardian] channel delete handler error',error)}
  })
  client.on(Events.ChannelUpdate,async(before,after)=>{
    try{
      const critical=before.name!==after.name||before.rawPosition!==after.rawPosition||JSON.stringify(before.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})))!==JSON.stringify(after.permissionOverwrites.cache.map(x=>jsonSafe(x.toJSON?.()||{})))
      if(!critical)return
      const actor=await auditActor(after.guild,AuditLogEvent.ChannelUpdate,after.id)
      await registerDestructiveAction(db,after.guild,actor,'CHANNEL_UPDATE',after.id)
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
    try{const actor=await auditActor(role.guild,AuditLogEvent.RoleCreate,role.id);await registerDestructiveAction(db,role.guild,actor,'ROLE_CREATE',role.id)}catch{}
  })
  client.on(Events.GuildRoleDelete,async role=>{
    try{
      db.createCase(role.guild.id,null,client.user?.id,'ROLE_DELETE','Role deleted: '+role.name)
      const actor=await auditActor(role.guild,AuditLogEvent.RoleDelete,role.id)
      await registerDestructiveAction(db,role.guild,actor,'ROLE_DELETE',role.id)
      const cfg=db.get('SELECT rollback_enabled FROM guardian_config WHERE guild_id=?',BigInt(role.guild.id))
      if(Number(cfg?.rollback_enabled??1)&&!trustedUser(db,role.guild,actor?.id))await restoreDeletedRole(db,role.guild,role)
    }catch{}
  })
  client.on(Events.GuildRoleUpdate,async(before,after)=>{
    try{
      if(before.permissions.bitfield===after.permissions.bitfield&&before.position===after.position)return
      db.createCase(after.guild.id,null,client.user?.id,'ROLE_PERMISSION_CHANGE','Permissions or position changed for '+after.name)
      const actor=await auditActor(after.guild,AuditLogEvent.RoleUpdate,after.id)
      const anti=db.get('SELECT enabled FROM anti_nuke_config WHERE guild_id=?',BigInt(after.guild.id))
      const gained=[PermissionFlagsBits.Administrator,PermissionFlagsBits.ManageGuild,PermissionFlagsBits.ManageRoles,PermissionFlagsBits.ManageChannels,PermissionFlagsBits.ManageWebhooks,PermissionFlagsBits.BanMembers,PermissionFlagsBits.KickMembers,PermissionFlagsBits.ModerateMembers].some(bit=>after.permissions.has(bit)&&!before.permissions.has(bit))
      if(Number(anti?.enabled)&&gained&&!trustedUser(db,after.guild,actor?.id)){
        const reverted=await after.edit({permissions:before.permissions,reason:'ESN Guardian anti-nuke: reverted dangerous role permission escalation'}).then(()=>true).catch(()=>false)
        await securityCase(db,after.guild,actor,reverted?'ANTINUKE_ROLE_REVERT':'ANTINUKE_ROLE_REVERT_FAILED',(reverted?'Reverted':'Could not revert')+' dangerous permissions on '+after.name)
      }
      await registerDestructiveAction(db,after.guild,actor,'ROLE_PERMISSION_CHANGE',after.id)
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
          const actor=await auditActor(after.guild,AuditLogEvent.MemberRoleUpdate,after.id)
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
        const actor=await auditActor(after.guild,AuditLogEvent.MemberRoleUpdate,after.id)
        if(trustedUser(db,after.guild,actor?.id))return
        const removable=added.filter(r=>r.editable)
        if(removable.size){
          const ok=await after.roles.remove([...removable.values()],'ESN Guardian anti-nuke: reverted dangerous role assignment').then(()=>true).catch(()=>false)
          await securityCase(db,after.guild,actor,ok?'ANTINUKE_ROLE_ASSIGNMENT_REVERT':'ANTINUKE_ROLE_ASSIGNMENT_REVERT_FAILED',(ok?'Removed':'Could not remove')+' dangerous roles from '+after.user.tag)
        }else await securityCase(db,after.guild,actor,'ANTINUKE_ROLE_ASSIGNMENT_UNMANAGEABLE','Dangerous role assigned to '+after.user.tag+', but it is above Guardian role')
        await registerDestructiveAction(db,after.guild,actor,'DANGEROUS_ROLE_ASSIGNMENT',after.id)
      }
    }catch{}
  })
  client.on(Events.GuildBanAdd,async ban=>{try{await logEvent(db,ban.guild,'member_log_channel_id','Member banned','User: <@'+ban.user.id+'> ('+ban.user.id+')');const actor=await auditActor(ban.guild,AuditLogEvent.MemberBanAdd,ban.user.id);await registerDestructiveAction(db,ban.guild,actor,'MEMBER_BAN',ban.user.id)}catch{}})
  client.on(Events.GuildMemberRemove,async member=>{if(isInternalRemoval(member.guild.id,member.id))return;try{const actor=await auditActor(member.guild,AuditLogEvent.MemberKick,member.id);if(actor)await registerDestructiveAction(db,member.guild,actor,'MEMBER_KICK',member.id)}catch{}})
  client.on(Events.GuildBanRemove,async ban=>{try{const actor=await auditActor(ban.guild,AuditLogEvent.MemberBanRemove,ban.user.id);if(actor)await registerDestructiveAction(db,ban.guild,actor,'MEMBER_UNBAN',ban.user.id)}catch{}})
  client.on(Events.WebhooksUpdate,async channel=>{
    try{
      db.createCase(channel.guild.id,null,client.user?.id,'WEBHOOK_CHANGE','Webhook update in #'+channel.name,channel.id)
      const cfg=db.get('SELECT webhook_guard FROM guardian_config WHERE guild_id=?',BigInt(channel.guild.id));if(!Number(cfg?.webhook_guard??1))return
      const actor=await auditActor(channel.guild,AuditLogEvent.WebhookCreate,null)
      if(trustedUser(db,channel.guild,actor?.id)){
        const hooks=await channel.fetchWebhooks().catch(()=>null);if(hooks)for(const hook of hooks.values())db.run('INSERT OR IGNORE INTO approved_webhooks (guild_id,webhook_id) VALUES (?,?)',BigInt(channel.guild.id),BigInt(hook.id))
      }else{
        const removed=await deleteUnapprovedWebhooks(db,channel.guild,channel)
        if(removed){await registerDestructiveAction(db,channel.guild,actor,'WEBHOOK_CHANGE',channel.id);await securityCase(db,channel.guild,actor,'WEBHOOK_DESTROYED','Deleted '+removed+' unauthorized webhook(s)',channel.id)}
      }
    }catch(error){console.error('[Guardian] webhook guard error',error)}
  })
  client.on(Events.GuildIntegrationsUpdate,async guild=>{
    try{
      const cfg=db.get('SELECT integration_guard FROM guardian_config WHERE guild_id=?',BigInt(guild.id));if(!Number(cfg?.integration_guard??1))return
      const actor=await auditActor(guild,AuditLogEvent.IntegrationCreate,null)
      if(trustedUser(db,guild,actor?.id)){const integrations=await guild.fetchIntegrations().catch(()=>null);if(integrations)for(const integration of integrations.values())db.run('INSERT OR IGNORE INTO approved_integrations (guild_id,integration_id,application_id) VALUES (?,?,?)',BigInt(guild.id),BigInt(integration.id),integration.application?.id?BigInt(integration.application.id):null)}
      else{const removed=await removeUnapprovedIntegrations(db,guild);if(removed){await registerDestructiveAction(db,guild,actor,'INTEGRATION_CHANGE',guild.id);await securityCase(db,guild,actor,'INTEGRATION_REMOVED','Removed '+removed+' unauthorized integration(s)')}}
    }catch(error){console.error('[Guardian] integration guard error',error)}
  })

  const snapshotTimer=setInterval(async()=>{for(const guild of client.guilds.cache.values()){try{const existing=db.get('SELECT 1 AS ok FROM guardian_snapshots WHERE guild_id=?',BigInt(guild.id));await saveSnapshot(db,guild,!existing)}catch{}}},30*60*1000)
  snapshotTimer.unref?.()
  const integrationTimer=setInterval(async()=>{for(const guild of client.guilds.cache.values()){try{const cfg=db.get('SELECT integration_guard FROM guardian_config WHERE guild_id=?',BigInt(guild.id));if(Number(cfg?.integration_guard??1))await removeUnapprovedIntegrations(db,guild)}catch{}}},5*60*1000)
  integrationTimer.unref?.()
  const raidExpiry=setInterval(()=>{for(const [id,until] of raidModeUntil){if(until<=Date.now()){raidModeUntil.delete(id);db.run('UPDATE guardian_raid_runtime SET active_until_epoch=0,updated_at=CURRENT_TIMESTAMP WHERE guild_id=?',BigInt(id))}}},30000)
  raidExpiry.unref?.()
}
module.exports={attachSecurity,saveSnapshot,getSnapshot,hardenGuild,panicGuild,lockdownGuild,unlockdownGuild,containActor,securityAudit,trustedUser,isApprovedBot,isRaidModeActive,isInternalRemoval}
