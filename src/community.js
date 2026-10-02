'use strict'

const dgram=require('node:dgram')
const crypto=require('node:crypto')
const {ActionRowBuilder,ButtonBuilder,ButtonStyle,Events,AuditLogEvent}=require('discord.js')
const {embed,logEvent,auditActor}=require('./utils')

const BEDROCK_MAGIC=Buffer.from('00ffff00fefefefefdfdfdfd12345678','hex')
const MC_HOST=process.env.MC_HOST?.trim()||'esn.ggwp.cc'
const MC_PORT=Number(process.env.MC_PORT||17429)
const DISCORD_URL='https://discord.gg/3gxA66KZ8'

function formatMemberDetails(member){
  const roles=member.roles?.cache?.filter(r=>r.id!==member.guild.id).sort((a,b)=>b.position-a.position).map(r=>r.toString()).join(', ')||'None'
  const joined=member.joinedTimestamp?'<t:'+Math.floor(member.joinedTimestamp/1000)+':F>':'Unknown'
  const created='<t:'+Math.floor(member.user.createdTimestamp/1000)+':F>'
  return [
    'User: '+member.toString()+' ('+member.id+')',
    'Username: '+member.user.username,
    'Global name: '+(member.user.globalName||'None'),
    'Display name: '+member.displayName,
    'Bot: '+(member.user.bot?'yes':'no'),
    'Account created: '+created,
    'Joined server: '+joined,
    'Roles: '+roles,
    'Pending screening: '+(member.pending?'yes':'no'),
    'Timeout: '+(member.communicationDisabledUntilTimestamp?'<t:'+Math.floor(member.communicationDisabledUntilTimestamp/1000)+':F>':'None'),
    'Timezone: Unknown (Discord does not expose a user timezone via the API)'
  ].join('\n').slice(0,4096)
}
async function sendMemberNotice(channel,member,title){
  const e=embed(formatMemberDetails(member),title).setThumbnail(member.displayAvatarURL())
  try{return await channel.send({embeds:[e],allowedMentions:{parse:[]}})}
  catch{return channel.send({content:('**'+title+'**\n'+formatMemberDetails(member)).slice(0,2000),allowedMentions:{parse:[]}}).catch(()=>null)}
}
function panelComponents(){
  const buttons=[['Security','security'],['AutoMod','automod'],['Verification','verification'],['Logs','logs'],['Settings','settings'],['Lockdown','lockdown'],['Statistics','statistics'],['Help','help']]
  const rows=[]
  for(let i=0;i<buttons.length;i+=4){
    const row=new ActionRowBuilder()
    for(const [label,action] of buttons.slice(i,i+4))row.addComponents(new ButtonBuilder().setLabel(label).setCustomId('esn_guardian:control:'+action).setStyle(action==='lockdown'?ButtonStyle.Danger:ButtonStyle.Secondary))
    rows.push(row)
  }
  return rows
}
async function postPanel(db,interaction){
  if(!interaction.channel?.isTextBased?.())throw new Error('This command requires a text channel.')
  const message=await interaction.channel.send({embeds:[embed('Use the buttons below for Guardian information and shortcuts.','ESN GUARDIAN CONTROL PANEL')],components:panelComponents(),allowedMentions:{parse:[]}})
  db.run("INSERT OR REPLACE INTO panel_messages (guild_id,panel_type,channel_id,message_id) VALUES (?,'panel',?,?)",BigInt(interaction.guildId),BigInt(message.channel.id),BigInt(message.id))
  return message
}
function raknetPing(host=MC_HOST,port=MC_PORT,timeout=5000){
  return new Promise((resolve,reject)=>{
    const socket=dgram.createSocket('udp4')
    const timer=setTimeout(()=>{socket.close();reject(new Error('timeout'))},timeout)
    const payload=Buffer.alloc(33)
    payload[0]=0x01
    payload.writeBigInt64BE(BigInt(Date.now()),1)
    BEDROCK_MAGIC.copy(payload,9)
    crypto.randomBytes(8).copy(payload,25)
    socket.once('error',err=>{clearTimeout(timer);socket.close();reject(err)})
    socket.once('message',data=>{
      clearTimeout(timer);socket.close()
      try{
        if(data.length<35||data[0]!==0x1c||!data.subarray(17,33).equals(BEDROCK_MAGIC))throw new Error('invalid pong')
        const len=data.readUInt16BE(33),text=data.subarray(35,35+len).toString('utf8'),fields=text.split(';')
        if(fields.length<6||fields[0]!=='MCPE')throw new Error('invalid MCPE pong')
        resolve(fields)
      }catch(error){reject(error)}
    })
    socket.send(payload,port,host)
  })
}
async function bedrockStatus(){
  try{
    const fields=await raknetPing()
    return{online:true,fields,text:'Online: yes\nPlayers: '+fields[4]+'/'+fields[5]+'\nMOTD: '+fields[1]+'\nMinecraft Bedrock\nServer: ESN SMP\nIP: '+MC_HOST+'\nPort: '+MC_PORT+'\nDiscord: '+DISCORD_URL}
  }catch{
    return{online:false,fields:null,text:'Online: unavailable\nThe Bedrock server did not respond to a status query.\nMinecraft Bedrock\nServer: ESN SMP\nIP: '+MC_HOST+'\nPort: '+MC_PORT+'\nDiscord: '+DISCORD_URL}
  }
}
async function handleButton(interaction){
  if(!interaction.customId?.startsWith('esn_guardian:control:'))return false
  const action=interaction.customId.split(':')[2]
  if(action==='lockdown'){
    if(!interaction.memberPermissions?.has('ManageGuild'))await interaction.reply({content:'Staff permission is required.',ephemeral:true})
    else await interaction.reply({content:'Use /lockdown to confirm the incident reason and lock channels.',ephemeral:true})
    return true
  }
  const text={
    security:'Security controls: /guardian audit, /security status, /antinuke status, /lockdown, /unlockdown.',
    automod:'AutoMod monitors flood, mentions, caps, links, invites, phishing-style links, and configured blocked words.',
    verification:'Configure with /verification setup, then /verification enable.',
    logs:'Set each route with /logs category:<name> channel:<channel>.',
    settings:'Use /config to inspect current server settings.',
    statistics:'Serving '+interaction.client.guilds.cache.size+' servers.',
    help:'Use /help for setup instructions and the full command guide.'
  }[action]||'Guardian control panel.'
  await interaction.reply({content:text,ephemeral:true,allowedMentions:{parse:[]}})
  return true
}
function attachCommunity(client,db){
  let smpOnline=null
  client.guardianCommunity={postPanel:interaction=>postPanel(db,interaction),handleButton,bedrockStatus}

  client.on(Events.GuildMemberAdd,async member=>{
    try{
      if(client.guardianSecurity?.isRaidModeActive?.(member.guild.id)&&!member.user.bot)return
      const settings=db.setting(member.guild.id)
      if(settings.autorole_id){
        const role=member.guild.roles.cache.get(String(settings.autorole_id))
        if(role?.editable&&!role.permissions.has('Administrator'))await member.roles.add(role,'ESN Guardian autorole').catch(()=>{})
      }
      const channel=settings.welcome_channel_id?member.guild.channels.cache.get(String(settings.welcome_channel_id)):null
      if(channel?.isTextBased())await sendMemberNotice(channel,member,'Member joined')
      await logEvent(db,member.guild,'member_log_channel_id','Member joined',formatMemberDetails(member))
    }catch(error){console.error('[Guardian] community join handler failed',error)}
  })
  client.on(Events.GuildMemberRemove,async member=>{
    try{
      if(client.guardianSecurity?.isInternalRemoval?.(member.guild.id,member.id))return
      const settings=db.setting(member.guild.id)
      const channel=settings.goodbye_channel_id?member.guild.channels.cache.get(String(settings.goodbye_channel_id)):null
      if(channel?.isTextBased())await sendMemberNotice(channel,member,'Member left')
      await logEvent(db,member.guild,'member_log_channel_id','Member left',formatMemberDetails(member))
    }catch{}
  })
  client.on(Events.GuildMemberUpdate,async(before,after)=>{
    try{
      if(before.nickname!==after.nickname)await logEvent(db,after.guild,'member_log_channel_id','Member nickname changed','User: <@'+after.id+'> ('+after.id+')\nBefore: '+(before.nickname||'None')+'\nAfter: '+(after.nickname||'None')+'\nTimezone: Unknown (Discord does not expose a user timezone via the API)')
      const added=after.roles.cache.filter(r=>!before.roles.cache.has(r.id)),removed=before.roles.cache.filter(r=>!after.roles.cache.has(r.id))
      if(added.size||removed.size){
        const actor=await auditActor(after.guild,AuditLogEvent.MemberRoleUpdate,after.id)
        await logEvent(db,after.guild,'member_log_channel_id','Member roles updated','User: <@'+after.id+'> ('+after.id+')\nAdded: '+(added.map(r=>r.toString()).join(', ')||'None')+'\nRemoved: '+(removed.map(r=>r.toString()).join(', ')||'None')+'\nUpdated by: '+(actor?'<@'+actor.id+'>':'Unknown'))
      }
      if(before.communicationDisabledUntilTimestamp!==after.communicationDisabledUntilTimestamp)await logEvent(db,after.guild,'member_log_channel_id','Member timeout updated','User: <@'+after.id+'> ('+after.id+')\nBefore: '+(before.communicationDisabledUntilTimestamp||'None')+'\nAfter: '+(after.communicationDisabledUntilTimestamp||'None'))
    }catch{}
  })
  client.on(Events.UserUpdate,async(before,after)=>{
    if(before.username===after.username&&before.globalName===after.globalName)return
    for(const guild of client.guilds.cache.values()){
      const member=guild.members.cache.get(after.id)
      if(!member)continue
      await logEvent(db,guild,'member_log_channel_id','User profile updated','User: <@'+member.id+'> ('+member.id+')\nUsername: '+before.username+' -> '+after.username+'\nGlobal name: '+(before.globalName||'None')+' -> '+(after.globalName||'None')+'\nTimezone: Unknown (Discord does not expose a user timezone via the API)')
    }
  })
  client.on(Events.VoiceStateUpdate,async(before,after)=>{
    if(before.channelId===after.channelId&&before.serverMute===after.serverMute&&before.serverDeaf===after.serverDeaf&&before.selfMute===after.selfMute&&before.selfDeaf===after.selfDeaf)return
    const guild=after.guild||before.guild
    await logEvent(db,guild,'voice_log_channel_id','Voice state updated','User: <@'+after.id+'>\nBefore: '+(before.channelId?'<#'+before.channelId+'>':'No voice channel')+'\nAfter: '+(after.channelId?'<#'+after.channelId+'>':'No voice channel')+'\nMute: '+before.serverMute+' -> '+after.serverMute+'\nDeaf: '+before.serverDeaf+' -> '+after.serverDeaf+'\nSelf mute: '+before.selfMute+' -> '+after.selfMute+'\nSelf deaf: '+before.selfDeaf+' -> '+after.selfDeaf+'\nTimezone: Unknown (Discord does not expose a user timezone via the API)')
  })
  client.on(Events.ChannelCreate,async channel=>{const actor=await auditActor(channel.guild,AuditLogEvent.ChannelCreate,channel.id);await logEvent(db,channel.guild,'guild_log_channel_id','Channel created','Channel: <#'+channel.id+'>\nType: '+channel.type+'\nCreated by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.ChannelDelete,async channel=>{const actor=await auditActor(channel.guild,AuditLogEvent.ChannelDelete,channel.id);await logEvent(db,channel.guild,'guild_log_channel_id','Channel deleted','Channel: #'+channel.name+'\nType: '+channel.type+'\nDeleted by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.ChannelUpdate,async(before,after)=>{if(before.name===after.name&&before.rawPosition===after.rawPosition)return;const actor=await auditActor(after.guild,AuditLogEvent.ChannelUpdate,after.id);await logEvent(db,after.guild,'guild_log_channel_id','Channel updated','Channel: #'+before.name+' -> #'+after.name+'\nType: '+after.type+'\nPosition: '+before.rawPosition+' -> '+after.rawPosition+'\nUpdated by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.GuildRoleCreate,async role=>{const actor=await auditActor(role.guild,AuditLogEvent.RoleCreate,role.id);await logEvent(db,role.guild,'role_log_channel_id','Role created','Role: <@&'+role.id+'>\nName: '+role.name+'\nColor: '+role.hexColor+'\nPermissions: '+role.permissions.bitfield+'\nCreated by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.GuildRoleDelete,async role=>{const actor=await auditActor(role.guild,AuditLogEvent.RoleDelete,role.id);await logEvent(db,role.guild,'role_log_channel_id','Role deleted','Role: '+role.name+'\nColor: '+role.hexColor+'\nPermissions: '+role.permissions.bitfield+'\nDeleted by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.GuildRoleUpdate,async(before,after)=>{if(before.name===after.name&&before.color===after.color&&before.permissions.bitfield===after.permissions.bitfield)return;const actor=await auditActor(after.guild,AuditLogEvent.RoleUpdate,after.id);await logEvent(db,after.guild,'role_log_channel_id','Role updated','Role: <@&'+after.id+'>\nBefore: '+before.name+' | '+before.hexColor+' | '+before.permissions.bitfield+'\nAfter: '+after.name+' | '+after.hexColor+' | '+after.permissions.bitfield+'\nUpdated by: '+(actor?'<@'+actor.id+'>':'Unknown'))})
  client.on(Events.InviteCreate,async invite=>{if(!invite.guild)return;await logEvent(db,invite.guild,'invite_log_channel_id','Invite created','Code: '+invite.code+'\nChannel: '+(invite.channelId?'<#'+invite.channelId+'>':'Unknown')+'\nCreated by: '+(invite.inviter?'<@'+invite.inviter.id+'>':'Unknown')+'\nMax age: '+invite.maxAge+'s\nMax uses: '+invite.maxUses+'\nTemporary: '+invite.temporary)})
  client.on(Events.InviteDelete,async invite=>{if(!invite.guild)return;await logEvent(db,invite.guild,'invite_log_channel_id','Invite deleted','Code: '+invite.code+'\nChannel: '+(invite.channelId?'<#'+invite.channelId+'>':'Unknown')+'\nUses: '+invite.uses)})
  client.on(Events.MessageDelete,async message=>{if(!message.guild||!message.author||message.author.bot)return;const attachments=message.attachments?.map(x=>x.url).join(', ')||'None';await logEvent(db,message.guild,'message_log_channel_id','Message deleted','User: <@'+message.author.id+'> ('+message.author.id+')\nChannel: <#'+message.channelId+'>\nMessage ID: '+message.id+'\nContent: '+(message.content||'[no text]')+'\nAttachments: '+attachments)})
  client.on(Events.MessageBulkDelete,async messages=>{const first=messages.first();if(!first?.guild)return;const authors=[...new Set(messages.filter(x=>x.author&&!x.author.bot).map(x=>x.author.id))];await logEvent(db,first.guild,'message_log_channel_id','Bulk messages deleted','Count: '+messages.size+'\nChannel: <#'+first.channelId+'>\nAuthor IDs: '+(authors.join(', ')||'No non-bot authors'))})
  client.on(Events.MessageUpdate,async(before,after)=>{if(!after.guild||!after.author||after.author.bot||before.content===after.content)return;await logEvent(db,after.guild,'message_log_channel_id','Message edited','User: <@'+after.author.id+'> ('+after.author.id+')\nChannel: <#'+after.channelId+'>\nMessage ID: '+after.id+'\nBefore: '+(before.content||'[no text]')+'\nAfter: '+(after.content||'[no text]'))})

  const monitor=setInterval(async()=>{
    const status=await bedrockStatus()
    if(smpOnline===null){smpOnline=status.online;return}
    if(smpOnline===status.online)return
    smpOnline=status.online
    for(const userId of db.statusSubscriberIds('smp')){
      const user=await client.users.fetch(String(userId)).catch(()=>null)
      if(user)await user.send({content:(status.online?'ESN SMP is online again.\n':'ESN SMP is currently unavailable.\n')+status.text,allowedMentions:{parse:[]}}).catch(()=>{})
    }
  },180000)
  monitor.unref?.()
}
module.exports={attachCommunity,formatMemberDetails,bedrockStatus,postPanel,handleButton}
