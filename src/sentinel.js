'use strict'

const { logEvent } = require('./utils')
const { caseWeight } = require('./intelligence')

function classifyAction(action) {
  const a=String(action||'').toUpperCase()
  if(/DELETE|BAN|KICK|NUKE|LOCKDOWN|MASS_|DESTROY/.test(a))return'destructive'
  if(/ROLE|PERMISSION|ADMIN|PRIVILEGE|OWNER/.test(a))return'privilege'
  if(/WEBHOOK|INTEGRATION|BOT_|EXTERNAL_APP|AUTOMATION/.test(a))return'automation'
  if(/TAMPER|INTEGRITY|POLICY_DRIFT|LEDGER/.test(a))return'tamper'
  if(/PANIC|ROLLBACK|RESTORE|RECOVERY|BACKUP/.test(a))return'recovery'
  if(/RAID|FLOOD|SPAM|MENTION|INVITE|LINK/.test(a))return'abuse'
  if(/CREDENTIAL|TOKEN|SECRET/.test(a))return'credential'
  return'other'
}
function anomalyScore({baseWeight,burstCount,categoryCount,surfaceCount,subjectCaseCount,rareAction}) {
  let score=Math.max(0,Number(baseWeight)||0)*5
  score+=Math.max(0,(Number(burstCount)||0)-2)*4
  score+=Math.max(0,(Number(categoryCount)||0)-1)*9
  score+=Math.max(0,(Number(surfaceCount)||0)-2)*3
  score+=Math.min(15,Math.max(0,(Number(subjectCaseCount)||0)-3)*2)
  if(rareAction)score+=8
  return Math.max(0,Math.min(100,score))
}
function severityFromScore(score){if(score>=80)return'CRITICAL';if(score>=60)return'HIGH';if(score>=35)return'ELEVATED';if(score>=15)return'WATCH';return'NORMAL'}
function chainSummary(categories){
  const order=['privilege','automation','tamper','destructive','recovery','credential','abuse','other']
  return order.filter(x=>categories.has(x)).join(' -> ')||'none'
}
function initializeState(db,guild){
  const row=db.get('SELECT 1 AS ok FROM guardian_sentinel_state WHERE guild_id=?',BigInt(guild.id))
  if(row)return
  const latest=db.get('SELECT COALESCE(MAX(case_id),0) AS max_case_id FROM cases WHERE guild_id=?',BigInt(guild.id))
  db.run('INSERT OR IGNORE INTO guardian_sentinel_state (guild_id,last_case_id) VALUES (?,?)',BigInt(guild.id),Number(latest?.max_case_id||0))
}
function recentContext(db,guildId,subjectId,caseId){
  if(subjectId==null)return{burst_count:1,category_count:1,surface_count:0,subject_case_count:0,categories:new Set()}
  const sid=BigInt(subjectId)
  const rows=db.all("SELECT action,target_id,channel_id FROM cases WHERE guild_id=? AND (target_id=? OR (target_id IS NULL AND moderator_id=?)) AND case_id<=? AND created_at>=datetime('now','-5 minutes') ORDER BY case_id DESC LIMIT 50",BigInt(guildId),sid,sid,caseId)
  const categories=new Set(rows.map(r=>classifyAction(r.action)))
  const surfaces=new Set(rows.filter(r=>r.channel_id!=null).map(r=>String(r.channel_id)))
  const profile=db.get('SELECT total_cases FROM guardian_sentinel_subject_profile WHERE guild_id=? AND subject_id=?',BigInt(guildId),sid)
  return{burst_count:Math.max(1,rows.length),category_count:Math.max(1,categories.size),surface_count:surfaces.size,subject_case_count:Number(profile?.total_cases||0),categories}
}
async function analyzeCase(client,db,guild,row){
  const action=String(row.action)
  if(action.startsWith('SENTINEL_'))return null
  const caseId=Number(row.case_id)
  const targetId=row.target_id!=null?String(row.target_id):null
  const moderatorId=row.moderator_id!=null?String(row.moderator_id):null
  const subjectId=targetId??(moderatorId&&moderatorId!==client.user?.id?moderatorId:null)
  const category=classifyAction(action)
  const context=recentContext(db,guild.id,subjectId,caseId)
  const baseline=db.get('SELECT seen_count FROM guardian_sentinel_action_baseline WHERE guild_id=? AND action=?',BigInt(guild.id),action)
  const rare=Number(baseline?.seen_count||0)<2
  const score=anomalyScore({baseWeight:caseWeight(action),burstCount:context.burst_count,categoryCount:context.category_count,surfaceCount:context.surface_count,subjectCaseCount:context.subject_case_count,rareAction:rare})
  const severity=severityFromScore(score)
  const categories=new Set(context.categories);categories.add(category)
  const explanation={base_weight:caseWeight(action),burst_count:context.burst_count,category_count:context.category_count,surface_count:context.surface_count,subject_case_count:context.subject_case_count,rare_action:rare,chain:chainSummary(categories)}
  db.run('INSERT OR IGNORE INTO guardian_sentinel_signals (guild_id,case_id,subject_id,target_id,action,category,score,severity,explanation_json) VALUES (?,?,?,?,?,?,?,?,?)',BigInt(guild.id),caseId,subjectId?BigInt(subjectId):null,targetId?BigInt(targetId):null,action,category,score,severity,JSON.stringify(explanation))
  db.run('INSERT INTO guardian_sentinel_action_baseline (guild_id,action,seen_count) VALUES (?,?,1) ON CONFLICT(guild_id,action) DO UPDATE SET seen_count=seen_count+1,last_seen_at=CURRENT_TIMESTAMP',BigInt(guild.id),action)
  if(subjectId)db.run('INSERT INTO guardian_sentinel_subject_profile (guild_id,subject_id,total_cases,weighted_score,last_action) VALUES (?,?,1,?,?) ON CONFLICT(guild_id,subject_id) DO UPDATE SET total_cases=total_cases+1,weighted_score=weighted_score+excluded.weighted_score,last_action=excluded.last_action,last_seen_at=CURRENT_TIMESTAMP',BigInt(guild.id),BigInt(subjectId),score,action)
  if(score>=60)await logEvent(db,guild,'security_log_channel_id','Guardian Sentinel — '+severity,'Case #'+caseId+': '+action+'\nSubject: '+(subjectId||'unknown')+' • Target: '+(targetId||'none')+'\nSentinel score: '+score+'/100\nCorrelation chain: '+explanation.chain+'\nSentinel is advisory; deterministic Guardian protections remain responsible for enforcement.')
  return{case_id:caseId,subject_id:subjectId,target_id:targetId,action,category,score,severity,explanation}
}
async function scanGuild(client,db,guild){
  initializeState(db,guild)
  const state=db.get('SELECT last_case_id FROM guardian_sentinel_state WHERE guild_id=?',BigInt(guild.id))
  const last=Number(state?.last_case_id||0)
  const rows=db.all('SELECT case_id,target_id,moderator_id,action,reason,created_at FROM cases WHERE guild_id=? AND case_id>? ORDER BY case_id ASC LIMIT 250',BigInt(guild.id),last)
  let newest=last,processed=0
  for(const row of rows){newest=Math.max(newest,Number(row.case_id));try{await analyzeCase(client,db,guild,row);processed++}catch(error){console.error('[Guardian] Sentinel failed case '+row.case_id,error)}}
  if(newest!==last)db.run('INSERT INTO guardian_sentinel_state (guild_id,last_case_id) VALUES (?,?) ON CONFLICT(guild_id) DO UPDATE SET last_case_id=excluded.last_case_id,updated_at=CURRENT_TIMESTAMP',BigInt(guild.id),newest)
  return processed
}
function liveReport(db,guild){
  const rows=db.all("SELECT signal_id,case_id,subject_id,target_id,action,category,score,severity,created_at FROM guardian_sentinel_signals WHERE guild_id=? AND created_at>=datetime('now','-30 minutes') ORDER BY signal_id DESC LIMIT 100",BigInt(guild.id))
  if(!rows.length)return'**Guardian Sentinel**\nNo Sentinel signals were recorded in the last 30 minutes.\nDeterministic Guardian protections remain active independently of Sentinel.'
  const highest=Math.max(...rows.map(r=>Number(r.score))),subjects=new Map(),categories=new Map()
  for(const row of rows){if(row.subject_id!=null)subjects.set(String(row.subject_id),(subjects.get(String(row.subject_id))||0)+1);categories.set(String(row.category),(categories.get(String(row.category))||0)+1)}
  const topCats=[...categories.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5).map(([n,c])=>n+'='+c).join(', ')||'none'
  const topSubjects=[...subjects.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5).map(([n,c])=>n+' ('+c+')').join(', ')||'none'
  return'**Guardian Sentinel live intelligence**\n30-minute signals: '+rows.length+'\nHighest anomaly score: '+highest+'/100 ('+severityFromScore(highest)+')\nHigh/critical signals: '+rows.filter(r=>Number(r.score)>=60).length+'\nDistinct subjects: '+subjects.size+'\nTop categories: '+topCats+'\nMost active subjects: '+topSubjects
}
function subjectReport(db,guild,subjectId){
  const sid=BigInt(subjectId)
  const profile=db.get('SELECT total_cases,weighted_score,last_action,last_seen_at FROM guardian_sentinel_subject_profile WHERE guild_id=? AND subject_id=?',BigInt(guild.id),sid)
  const rows=db.all('SELECT case_id,action,category,score,severity,created_at FROM guardian_sentinel_signals WHERE guild_id=? AND subject_id=? ORDER BY signal_id DESC LIMIT 12',BigInt(guild.id),sid)
  if(!profile&&!rows.length)return'Sentinel has no behavioral profile for subject '+subjectId+' in this server.'
  const categories=new Map();for(const row of rows)categories.set(String(row.category),(categories.get(String(row.category))||0)+1)
  const peak=Math.max(0,...rows.map(r=>Number(r.score)))
  return'**Sentinel subject profile — '+subjectId+'**\nObserved cases: '+Number(profile?.total_cases||rows.length)+'\nAccumulated anomaly weight: '+Number(profile?.weighted_score||rows.reduce((n,r)=>n+Number(r.score),0))+'\nRecent peak: '+peak+'/100 ('+severityFromScore(peak)+')\nRecent categories: '+([...categories.entries()].map(([k,v])=>k+'='+v).join(', ')||'none')+'\nLast action: '+(profile?.last_action||rows[0]?.action||'none')+'\nLast seen: '+(profile?.last_seen_at||rows[0]?.created_at||'unknown')+' UTC'
}
function signalsReport(db,guildId,limit=8){
  const rows=db.all('SELECT signal_id,case_id,subject_id,action,score,severity,explanation_json,created_at FROM guardian_sentinel_signals WHERE guild_id=? ORDER BY signal_id DESC LIMIT ?',BigInt(guildId),Math.max(1,Math.min(limit,15)))
  if(!rows.length)return'No Sentinel signals have been recorded yet.'
  return'**Recent Guardian Sentinel signals**\n'+rows.map(row=>{let e={};try{e=JSON.parse(String(row.explanation_json))}catch{};return'#'+row.signal_id+' • case #'+row.case_id+' • '+row.severity+' '+row.score+'/100 • subject '+(row.subject_id||'unknown')+' • '+row.action+' • chain '+(e.chain||'unknown')}).join('\n')
}
function explainSignal(db,guildId,signalId){
  const row=db.get('SELECT * FROM guardian_sentinel_signals WHERE guild_id=? AND signal_id=?',BigInt(guildId),signalId)
  if(!row)return null
  let e={};try{e=JSON.parse(String(row.explanation_json))}catch{}
  return'**Sentinel signal #'+signalId+'**\nCase: #'+row.case_id+'\nAction: '+row.action+' ('+row.category+')\nSubject: '+(row.subject_id||'unknown')+' • Target: '+(row.target_id||'none')+'\nScore: '+row.score+'/100 ('+row.severity+')\n5-minute burst: '+(e.burst_count??'unknown')+'\nDistinct correlated categories: '+(e.category_count??'unknown')+'\nSurface spread: '+(e.surface_count??'unknown')+'\nRare action bonus: '+(e.rare_action?'yes':'no')+'\nCorrelation chain: '+(e.chain||'unknown')+'\nThis score is explainable advisory intelligence; Guardian deterministic protections make enforcement decisions.'
}
function attachSentinel(client,db){
  const api={scanGuild:g=>scanGuild(client,db,g),liveReport:g=>liveReport(db,g),subjectReport:(g,id)=>subjectReport(db,g,id),signalsReport:(id,l)=>signalsReport(db,id,l),explainSignal:(id,s)=>explainSignal(db,id,s)}
  client.guardianSentinel=api
  client.once('clientReady',()=>{for(const guild of client.guilds.cache.values())initializeState(db,guild)})
  const timer=setInterval(async()=>{for(const guild of client.guilds.cache.values()){if(client.guardianSecurity?.isRaidModeActive?.(guild.id))continue;try{await scanGuild(client,db,guild)}catch(error){console.error('[Guardian] Sentinel scan failed',error)}}},90000)
  timer.unref?.()
  return api
}
module.exports={attachSentinel,classifyAction,anomalyScore,severityFromScore,chainSummary}
