'use strict'

const { EmbedBuilder }=require('discord.js')

const WEBSITE_URL='https://esnoffical.com'
const DISCORD_URL='https://discord.gg/3gxA66KZ8'
const STORE_AI_URL=WEBSITE_URL+'/store-ai'
const CATALOG=[
{name:'20 Realm 100 Keys',kind:'SMP',price:1.25,priceLabel:'$1.25',checkout:'https://buy.stripe.com/4gM14o5pxgaP9Nl2dNdnW00',status:'AVAILABLE',tags:['keys','realm','minecraft','smp']},
{name:'ESN Season Pass Relic Bundle',kind:'SMP',price:.50,priceLabel:'$0.50',checkout:'https://buy.stripe.com/bJe14o8BJbUz4t1dWvdnW01',status:'AVAILABLE',tags:['season','relic','angel','scepter','crystal','tideheart','celestial']},
{name:'ESN Riftwalker Bundle',kind:'SMP',price:.50,priceLabel:'$0.50',checkout:'https://buy.stripe.com/00w3cw6tB7Ej9Nl19JdnW02',status:'AVAILABLE',tags:['rift','riftwalker','elytra','phase','bow','compass']},
{name:'ESN Immortal Warden Bundle',kind:'SMP',price:1.30,priceLabel:'$1.30',checkout:'https://buy.stripe.com/bJefZi9FN9Mr6B905FdnW03',status:'AVAILABLE',tags:['warden','immortal','armor','blade','longbow','totem']},
{name:'Void Warrior Bundle',kind:'SMP',price:.50,priceLabel:'$0.50',checkout:null,status:'CHECKOUT NOT CONNECTED',tags:['void','warrior','armor','blade']},
{name:'Fortnite Coaching',kind:'SERVICE',price:null,priceLabel:'QUOTE THROUGH ESN',checkout:null,status:'DISCORD ORDER',tags:['fortnite','coaching','gaming']},
{name:'Editing Services',kind:'SERVICE',price:null,priceLabel:'QUOTE THROUGH ESN',checkout:null,status:'DISCORD ORDER',tags:['editing','video','creator','anime']},
{name:'Discord Server Setups',kind:'SERVICE',price:null,priceLabel:'QUOTE THROUGH ESN',checkout:null,status:'DISCORD ORDER',tags:['discord','setup','roles','channels','moderation']},
{name:'Website Creation',kind:'SERVICE',price:null,priceLabel:'ESTIMATE / QUOTE',checkout:null,status:'DISCORD ORDER',tags:['website','web','site','startup','enterprise']},
{name:'Memberships',kind:'SERVICE',price:null,priceLabel:'PRICE NOT VERIFIED',checkout:null,status:'ASK STAFF',tags:['membership']},
{name:'Hashtag Packs',kind:'SERVICE',price:null,priceLabel:'PRICE NOT VERIFIED',checkout:null,status:'ASK STAFF',tags:['hashtag','growth','creator']},
{name:'Stream Branding',kind:'SERVICE',price:null,priceLabel:'PRICE NOT VERIFIED',checkout:null,status:'ASK STAFF',tags:['stream','branding','creator']},
{name:'Custom Services',kind:'SERVICE',price:null,priceLabel:'CUSTOM QUOTE',checkout:null,status:'DISCORD ORDER',tags:['custom','project','service']},
{name:'ESN Domains',kind:'SERVICE',price:null,priceLabel:'PRICING NOT ACTIVATED',checkout:null,status:'SETUP MODE',tags:['domain','domains','subdomain','dns']}
]
const ROUTES={
'store ai':['/store-ai','ESN products, services, prices, delivery, and checkout help'],
'website builder':['/website-builder','Account-free ESN Website Builder'],
'builder':['/website-builder','Account-free ESN Website Builder'],
'domains':['/domains','ESN Domains and custom-domain controls'],
'arcade':['/arcade','ESN Arcade and original browser games'],
'tools':['/free-browser-tools','Free ES browser tools'],
'status':['/status','ESN network status center'],
'operations':['/operations','Connected ESN system operations map'],
'diagnostics':['/diagnostics','Browser, cache, service worker, SMP, plugin, and Discord diagnostics'],
'nexus':['/nexus','ESN Network Nexus'],
'updates':['/updates','Website, SMP, Arcade, and network release center'],
'timeline':['/timeline','Interactive ESN history timeline'],
'about':['/about','About ES Network'],
'leadership':['/leadership','ES Network leadership'],
'faq':['/faq','ESN FAQ and support information'],
'guides':['/guides','ESN Guides and News'],
'smp':['/minecraft-smp','ESN SMP information'],
'smp connection':['/smpconnection','ESN SMP connection help'],
'support':['/support','Website problem reporting and diagnostics'],
'explore':['/explore','ESN feature discovery'],
'gallery':['/gallery','Official ESN visuals and milestones']
}
const GAMES=['ES Clicker','ES Factory','ES Mines','ES MOTO','ES Tower','ES Tower Defense']

function normalize(value){return String(value||'').toLowerCase().replace(/[^a-z0-9.$ ]/g,' ').replace(/\s+/g,' ').trim()}
function contains(text,...terms){const p=String(text||'').toLowerCase();return terms.some(x=>p.includes(x))}
function promptFrom(content){const m=String(content||'').trim().match(/^ESNG(?:\s*[:,-]\s*|\s+|$)/i);return m?String(content).trim().slice(m[0].length).trim():null}
function budgetFrom(prompt){const m=String(prompt).match(/\$\s*(\d+(?:\.\d{1,2})?)|(?:under|below|less than|budget(?: of)?|for)\s*\$?\s*(\d+(?:\.\d{1,2})?)/i);if(!m)return null;const n=Number(m[1]||m[2]);return Number.isFinite(n)?n:null}
function catalogMatches(prompt){
  const n=normalize(prompt),tokens=n.split(' ').filter(x=>x.length>2),scored=[]
  for(const item of CATALOG){
    const hay=normalize([item.name,item.kind,...item.tags].join(' '))
    let score=tokens.reduce((v,t)=>v+(hay.includes(t)?3:0),0)
    if(n&&hay.includes(n))score+=20
    if(n.includes('smp')&&item.kind==='SMP')score+=5
    if(n.includes('service')&&item.kind==='SERVICE')score+=5
    if(score)scored.push([score,item])
  }
  return scored.sort((a,b)=>b[0]-a[0]).map(x=>x[1])
}
function catalogLine(item,checkout=false){
  let line='**'+item.name+'** — '+item.priceLabel+' — '+item.status
  if(checkout){
    if(item.checkout)line+='\nCheckout: '+item.checkout
    else if(item.kind==='SERVICE')line+='\nOrder/support: '+DISCORD_URL
    else line+='\nCheckout is not connected; ESNG will not invent a payment link.'
  }
  return line
}
function storeAnswer(prompt){
  const n=normalize(prompt),matches=catalogMatches(prompt),budget=budgetFrom(prompt)
  const purchasable=CATALOG.filter(x=>x.price!=null&&x.status==='AVAILABLE').sort((a,b)=>a.price-b.price)
  if(contains(n,'delivery','minecraft username','leading dot','prefix'))return'For SMP purchases, enter the exact Minecraft Username at checkout. If the server username uses a leading period, include it. Be online on the SMP when possible for automatic delivery.'
  if(contains(n,'all products','catalog','what do you sell','show everything'))return'**ESN catalog**\n'+CATALOG.map(x=>'• '+x.name+' — '+x.priceLabel+' ('+x.status+')').join('\n')
  if(contains(n,'cheapest','lowest price','least expensive')){const min=Math.min(...purchasable.map(x=>x.price));return'Cheapest verified direct-checkout items:\n'+purchasable.filter(x=>x.price===min).map(x=>catalogLine(x,true)).join('\n')}
  if(budget!=null){const items=purchasable.filter(x=>x.price<=budget);if(!items.length)return'I do not have a verified direct-checkout product at or below $'+budget.toFixed(2)+'. Some ESN services use custom quotes through Discord.';return'Verified products at or below $'+budget.toFixed(2)+':\n'+items.map(x=>catalogLine(x,true)).join('\n\n')}
  if(contains(n,'compare','versus','difference')&&matches.length>=2)return'Closest verified catalog comparison:\n'+matches.slice(0,3).map(x=>catalogLine(x)).join('\n')
  if(contains(n,'checkout','buy','purchase','order','payment link')&&matches.length)return catalogLine(matches[0],true)
  if(contains(n,'services','service','editing','coaching','branding','hashtag','membership','custom')){const items=matches.length?matches.slice(0,6):CATALOG.filter(x=>x.kind==='SERVICE');return'**ESN services**\n'+items.slice(0,6).map(x=>catalogLine(x,true)).join('\n')}
  if(contains(n,'smp product','minecraft product','bundle','keys','relic','warden','rift','void warrior')){const items=matches.length?matches.slice(0,5):CATALOG.filter(x=>x.kind==='SMP');return'**ESN SMP catalog**\n'+items.slice(0,5).map(x=>catalogLine(x,true)).join('\n')}
  if(matches.length&&contains(n,'price','cost','product','store'))return matches.slice(0,4).map(x=>catalogLine(x,true)).join('\n')
  return null
}
function websiteAnswer(prompt){
  const n=normalize(prompt)
  if(contains(n,'website links','site links','pages','routes')){
    const keys=['store ai','website builder','domains','arcade','tools','status','diagnostics','nexus','updates','guides']
    return'**Popular ESN website pages**\n'+keys.map(name=>'• '+name.replace(/\b\w/g,c=>c.toUpperCase())+': '+WEBSITE_URL+ROUTES[name][0]).join('\n')
  }
  for(const [name,[route,desc]] of Object.entries(ROUTES))if(n.includes(normalize(name)))return'**'+name.replace(/\b\w/g,c=>c.toUpperCase())+'**\n'+desc+'\n'+WEBSITE_URL+route
  if(contains(n,'website','esn site','official site'))return'Official ES Network website: '+WEBSITE_URL+'\nStore AI: '+STORE_AI_URL+'\nWebsite Builder: '+WEBSITE_URL+'/website-builder\nStatus: '+WEBSITE_URL+'/status'
  return null
}
function baseAnswer(client,db,guild,prompt){
  const p=String(prompt||'').toLowerCase().trim()
  if(!p||contains(p,'help','what can you do','commands'))return'**ESNG Intelligence v4**\nI can reason across Guardian live security state and ESN knowledge.\nTry: ESNG full security report • ESNG sentinel status • ESNG explain signal #3 • ESNG analyze subject 123456789012345678 • ESNG explain case #12'
  if(contains(p,'security status','guardian status','protection status')){const d=client.guardianIntelligence?.snapshot(guild);return d?'**Guardian security status**\nAutoMod: '+(d.automod?'ON':'OFF')+'\nAnti-nuke: '+(d.antinuke?'ON':'OFF')+'\nRaid protection: '+(d.raid?'ON':'OFF')+'\nVerification: '+(d.verification?'ON':'OFF')+'\nLockdown: '+(d.lockdown?'ACTIVE':'inactive'):'Guardian security status is not ready yet.'}
  if(contains(p,'bot status','online','uptime','latency')){const sec=Math.floor((Date.now()-client.guardianStartedAt)/1000),days=Math.floor(sec/86400),hours=Math.floor(sec%86400/3600),mins=Math.floor(sec%3600/60);return'**Guardian bot status**\nOnline: yes\nLatency: '+Math.round(client.ws.ping)+' ms\nUptime: '+days+'d '+hours+'h '+mins+'m\nServers: '+client.guilds.cache.size}
  if(contains(p,'anti-nuke','antinuke','nuke'))return'**Anti-nuke** watches destructive Discord audit-log actions, dangerous permission escalation, mass moderation activity, webhook abuse, and untrusted bot additions. Trusted users and the server owner are exempt. The server owner controls it with /antinuke commands.'
  if(contains(p,'raid','join flood','mass join'))return'**Raid protection** watches rapid joins and suspiciously new accounts. It can quarantine or remove suspicious members and trigger emergency containment when configured thresholds are exceeded.'
  if(contains(p,'automod','spam','phishing','dangerous link','link security','invite blocking'))return'**AutoMod** checks flood spam, repeated messages, mass mentions, caps, blocked words, Discord invites, strict-link allowlists, and phishing-style links.'
  if(contains(p,'verification','verify'))return'**Verification** gives approved members the configured verified role after server checks. It can enforce minimum account age and safely rejects privileged or unmanageable role configurations.'
  if(contains(p,'ticket','support'))return'**Tickets** create private support channels for the member, configured support role, and Guardian. Use /ticket to open one and /ticket-close inside the ticket.'
  if(contains(p,'moderation','mod commands','ban','kick','timeout','warn'))return'**Moderation** includes warnings, timeouts, kicks, bans, unbans, role changes, nickname changes, slowmode, clearing, cases, and member history with permission and hierarchy checks.'
  if(contains(p,'lockdown','lock down'))return'**Lockdown** blocks @everyone from sending messages across text channels during an incident and restores saved permissions when released.'
  if(contains(p,'token','bot token','password','secret','staff code','environment variable'))return'I will not reveal Discord tokens, passwords, staff codes, environment-variable secrets, or other private credentials.'
  if(contains(p,'backup','database save','database persistence','save settings'))return'**Guardian persistence**\nServer configuration is stored in SQLite. Guardian creates verified backups at startup, shutdown, on schedule, and supports recovery from a valid backup if the main database is corrupt.'
  if(contains(p,'who is esn','what is esn','ep1c','epic services','brand'))return'**ES Network (ESN)** is the current brand. EP1C Services was the former name. ESN connects creator services, the SMP, Arcade, free browser tools, website creation, community resources, and other network projects.'
  if(contains(p,'official discord','community invite','discord link'))return'Official ES Network Discord: '+DISCORD_URL
  if(contains(p,'arcade games','browser games','games'))return'**ESN Arcade**\n'+GAMES.map(x=>'• '+x).join('\n')+'\n'+WEBSITE_URL+'/arcade'
  const store=storeAnswer(prompt);if(store)return store
  const website=websiteAnswer(prompt);if(website)return website
  if(contains(p,'privacy','data','database'))return'Guardian stores server-scoped settings, moderation/security cases, ticket state, and verification state in SQLite. Bot tokens belong in environment variables and should never be posted in Discord or committed to GitHub.'
  return'I do not have a verified answer for that yet. Try ESNG help. For live ESN information, use '+WEBSITE_URL+'. I will not invent prices, checkout links, security settings, commands, or private data.'
}
async function advancedAnswer(client,db,guild,prompt){
  const p=String(prompt||'').toLowerCase().trim()
  const intel=client.guardianIntelligence,over=client.guardianOverwatch,sentinel=client.guardianSentinel,res=client.guardianResilience
  const signal=String(prompt).match(/\bsignal\s*#?\s*(\d+)\b/i)
  const caseMatch=String(prompt).match(/\bcase\s*#?\s*(\d+)\b/i)
  const memberMatch=String(prompt).match(/(?:<@!?(\d{15,22})>|\b(?:user|member|account|actor|subject)\s+(\d{15,22})\b)/i)
  const memberId=memberMatch?(memberMatch[1]||memberMatch[2]):null

  if(res&&contains(p,'resilience status','recovery readiness','guardian readiness','are backups ready','self health','self-health','defense readiness'))return res.statusReport(guild)
  if(res&&contains(p,'security drill','resilience drill','run a drill','test defenses','test guardian','readiness drill'))return res.drillReport(guild)
  if(res&&contains(p,'recovery plan','recovery steps','how do we recover','what if guardian fails'))return res.recoveryPlan(guild)
  if(sentinel&&signal&&contains(p,'signal','explain','why','details','analyze','analyse','score'))return sentinel.explainSignal(guild.id,Number(signal[1]))||'I cannot find Sentinel signal #'+signal[1]+' in this server.'
  if(sentinel&&memberId&&contains(p,'analyze subject','analyse subject','subject profile','subject risk','subject behavior','subject behaviour','check subject','behavior profile','behaviour profile'))return sentinel.subjectReport(guild,memberId)
  if(sentinel&&contains(p,'sentinel status','sentinel report','anomaly report','anomaly status','behavioral security','behavioural security','behavior analysis','behaviour analysis','correlation report'))return sentinel.liveReport(guild)
  if(sentinel&&contains(p,'sentinel signals','recent anomalies','latest anomalies','recent signals','latest signals','suspicious activity','high anomaly'))return sentinel.signalsReport(guild.id)
  if(sentinel&&contains(p,'are events correlated','attack chain','correlated attack','multi step attack','multi-step attack','is this coordinated','coordinated attack','behavior chain','behaviour chain'))return('**Guardian correlation analysis**\nSentinel correlates recent Guardian cases by subject, surface spread, action category, rarity, and five-minute bursts. It does not auto-punish from anomaly scoring alone.\n\n'+sentinel.liveReport(guild)+'\n\n'+sentinel.signalsReport(guild.id,5)).slice(0,4000)

  if(over&&memberId&&contains(p,'analyze member','analyse member','member risk','user risk','security profile','check member','check user','is this user dangerous','is this member dangerous'))return over.memberRiskReport(guild,memberId)
  if(over&&contains(p,'full security report','complete security report','everything security','full guardian report','guardian overview','deep security report')){
    const sections=[over.postureReport(guild),over.integrityReport(guild)]
    if(sentinel)sections.push(sentinel.liveReport(guild))
    if(res)sections.push(res.statusReport(guild))
    if(intel){sections.push(intel.threatReport(guild));sections.push('**Guardian next actions**\n'+intel.recommendations(guild).map(x=>'• '+x).join('\n'))}
    return sections.join('\n\n').slice(0,4000)
  }
  if(over&&contains(p,'integrity','tamper','tampering','case ledger','security ledger','ledger check','verify cases','was the database changed'))return over.integrityReport(guild)
  if(over&&contains(p,'defense posture','security posture','guardian posture','shield status','protection score','security score','how protected are we','how secure are we'))return over.postureReport(guild)
  if(over&&contains(p,'security trend','threat trend','getting worse','getting better','activity rising','activity falling','is risk increasing')){const t=over.trendReport(guild);return'**Guardian threat trend**\nTrend: '+t.label+'\nLast 10 minutes: '+t.recent_cases+' cases / weighted score '+t.recent_score+'\nPrevious 50 minutes: '+t.previous_cases+' cases / weighted score '+t.previous_score+'\nThe trend is based on Guardian recorded security cases.'}
  if(over&&contains(p,'policy drift','security drift','security settings changed','did settings change','guardian settings changed','protection changed','configuration changed'))return over.driftReport(guild)
  if(over&&contains(p,'incident sessions','active incident','incident report','security incidents','guardian incidents'))return over.incidentReport(guild.id)
  if(contains(p,'seal policy','approve security baseline','save security baseline'))return'ESNG chat will not silently approve a new security baseline. The server owner must use /overwatch seal.'
  if(contains(p,'make backup','create backup','security backup now','incident backup'))return'Use /overwatch backup as the server owner. ESNG chat does not execute privileged recovery actions from normal messages.'

  if(intel&&caseMatch&&contains(p,'case','explain','why','what happened','details','analyze','analyse'))return'**Guardian case analysis**\n'+(intel.explainCase(guild.id,Number(caseMatch[1]))||('I cannot find Guardian case #'+caseMatch[1]+' in this server.'))
  if(intel&&contains(p,'threat report','threat level','risk report','risk level','security intelligence','analyze server','analyse server','server risk','are we under attack','under attack','attack happening'))return(intel.threatReport(guild)+(sentinel?'\n\n'+sentinel.liveReport(guild):'')).slice(0,4000)
  if(intel&&contains(p,'recent incidents','recent security','security timeline','what happened recently','latest cases','latest security cases','incident history','what happened today'))return intel.timeline(guild.id)
  if(intel&&contains(p,'security health','guardian health','protection health','security diagnostics','guardian diagnostics','system health'))return([intel.healthReport(guild),over?.postureReport(guild),sentinel?.liveReport(guild)].filter(Boolean).join('\n\n')).slice(0,4000)
  if(intel&&contains(p,'what should we do','what should i do','next steps','security recommendations','how do we secure','how can we secure','improve security','harden this server','fix security'))return('**Guardian next actions**\n'+intel.recommendations(guild).map(x=>'• '+x).join('\n')+(sentinel?'\n\nSentinel anomaly scores are advisory. Review supporting cases/signals before manual action.':'')).slice(0,4000)
  if(intel&&contains(p,'blocked external apps','blocked apps','external app blocks','external apps blocked')){const d=intel.snapshot(guild);return'**External-app defense**\nExternal-app lock: '+(d.external_app_lock?'ON':'OFF')+'\nPersistently blocked application IDs: '+d.blocked_apps+'\nGuardian stores blocked application IDs in SQLite, so the block survives restarts.'}
  if(intel&&contains(p,'why did guardian','why was i banned','why did it ban','why did it lockdown','why did it lock down','why did it quarantine'))return'**Why Guardian acted**\nGuardian records security actions as server-scoped cases. Sentinel can add explainable behavioral context, but enforcement comes from Guardian deterministic rules and permission-checked controls.\n'+intel.timeline(guild.id,5)
  if(contains(p,'ai version','esng version','how smart are you','what changed with ai','new ai'))return'**ESNG Intelligence v4**\nI combine live configuration, threat history, tamper-evident case verification, policy drift, persistent incident sessions, threat trends, Sentinel behavioral correlation, subject profiles, Guardian Resilience self-health, attack-chain context, member history, backups, and ESN knowledge.'
  if(contains(p,'enable panic','turn on panic','activate panic','start panic'))return'For safety, ESNG chat does not execute emergency moderation actions. The server owner can use /guardian panic enabled:true.'
  if(contains(p,'disable security','turn off security','disable guardian','remove protection'))return'ESNG chat will not disable protection from a normal message. Security changes must go through permission-checked slash commands.'
  if(contains(p,'should we panic','should i panic','activate panic now','do we need panic')){const report=over?over.postureReport(guild):intel?.threatReport(guild)||'Live report unavailable.';return('Review the live evidence below and use /guardian panic only if the owner decides emergency containment is necessary.\n\n'+report).slice(0,4000)}
  return baseAnswer(client,db,guild,prompt)
}
function attachESNGAI(client,db){
  const cooldowns=new Map()
  client.on('messageCreate',async message=>{
    if(!message.guild||message.author.bot)return
    const prompt=promptFrom(message.content);if(prompt===null)return
    const key=message.guild.id+':'+message.author.id,now=Date.now()
    if(now-(cooldowns.get(key)||0)<3000)return
    cooldowns.set(key,now)
    try{
      const answer=await advancedAnswer(client,db,message.guild,prompt.slice(0,1000))
      const embed=new EmbedBuilder().setTitle('ESNG AI').setDescription(String(answer).slice(0,4096)).setColor(0x0B3D91).setTimestamp().setFooter({text:'Protected by ESN Guardian • Trigger: ESNG'})
      await message.reply({embeds:[embed],allowedMentions:{repliedUser:false,parse:[]}}).catch(()=>{})
    }catch(error){console.error('[Guardian] ESNG AI error',error)}
  })
}
module.exports={attachESNGAI,baseAnswer,advancedAnswer}
