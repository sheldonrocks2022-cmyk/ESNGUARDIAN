from __future__ import annotations
import hashlib, random
import discord
from discord.ext import commands
from esn_guardian.cogs.common import command_embed

def target_id(raw: str):
    raw=raw.strip()
    if raw.startswith("<@") and raw.endswith(">"): raw=raw[2:-1].lstrip("!")
    return int(raw) if raw.isdecimal() else None

class GuardianFun(commands.Cog):
    """Harmless ESP fun commands. No moderation/security side effects."""
    def __init__(self,bot): self.bot=bot
    def rng(self,*parts):
        seed="|".join(map(str,parts))+"|"+str(random.SystemRandom().randrange(1<<63))
        return random.Random(hashlib.sha256(seed.encode()).digest())
    async def member(self,ctx,raw):
        u=target_id(raw)
        if not u:return None
        return ctx.guild.get_member(u) if ctx.guild else self.bot.get_user(u)
    async def send(self,ctx,title,body,user=None):
        e=command_embed(body,title=title)
        if user and getattr(user,"display_avatar",None): e.set_thumbnail(url=user.display_avatar.url)
        await ctx.reply(embed=e,mention_author=False,allowed_mentions=discord.AllowedMentions.none())

    @commands.group(name="ESP",aliases=["esp"],invoke_without_command=True)
    async def esp(self,ctx):
        await self.send(ctx,"ESP • FUN ENGINE","Use `!ESP code 61-80`. These commands are entertainment only and never change Guardian security/moderation state.")

    @esp.command(name="codex")
    async def codex(self,ctx):
        pages=[
          ("ESP CODEX • 1/2","**01** Roast — randomized roast\\n**02** Rate — ridiculous 0-100 analysis\\n**03** Aura — Guardian aura score\\n**04** Wanted — fake most-wanted poster\\n**05** Bounty — fictional Guardian bounty\\n**06** Mugshot — fake intake profile\\n**07** Yap Detector — yapping level\\n**08** NPC Scan — NPC percentage\\n**09** Sus Meter — suspiciousness scan\\n**10** Cooked — cooked analysis"),
          ("ESP CODEX • 2/2","**11** Rizz Scan — randomized rizz rating\\n**12** Brain Scan — fake brain statistics\\n**13** Dossier — fictional classified file\\n**14** Crime Generator — absurd fictional charge\\n**15** Sentence — absurd fictional punishment\\n**16** 1V1 — randomized battle\\n**17** Boss Fight — turn a user into a boss\\n**18** Loot Drop — randomized crate\\n**19** Chaos — harmless random event\\n**20** Guardian Roulette — random ESP engine")]
        class CodexView(discord.ui.View):
            def __init__(self): super().__init__(timeout=120);self.page=0
            async def draw(self,i):
                self.page=max(0,min(1,self.page+i));self.prev.disabled=self.page==0;self.next.disabled=self.page==1
            @discord.ui.button(label="Previous",style=discord.ButtonStyle.secondary)
            async def prev(self,i:discord.Interaction,b:discord.ui.Button):
                if i.user.id!=ctx.author.id:return await i.response.send_message("This ESP Codex belongs to the person who opened it.",ephemeral=True)
                await self.draw(-1);t,bod=pages[self.page];await i.response.edit_message(embed=command_embed(bod,title=t),view=self)
            @discord.ui.button(label="Next",style=discord.ButtonStyle.primary)
            async def next(self,i:discord.Interaction,b:discord.ui.Button):
                if i.user.id!=ctx.author.id:return await i.response.send_message("This ESP Codex belongs to the person who opened it.",ephemeral=True)
                await self.draw(1);t,bod=pages[self.page];await i.response.edit_message(embed=command_embed(bod,title=t),view=self)
        v=CodexView();v.prev.disabled=True;t,bod=pages[0];await ctx.reply(embed=command_embed(bod,title=t),view=v,mention_author=False)

    @esp.group(name="code",invoke_without_command=True)
    async def code(self,ctx):
        await self.send(ctx,"ESP • FUN ENGINE","Available fun codes: **1-20**. Use \`!ESP codex\` for the full Luxury directory.")

    @code.command(name="1")
    async def roast(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        lines=["Your Wi-Fi has better decision-making skills.","You look like you skip the tutorial and blame the game.","Your comeback is still buffering.","Guardian searched for your aura and got a 404.","Even your autocorrect gave up.","You bring tutorial-level energy to boss fights.","Your loading screen has more personality.","Guardian recommends downloading common sense."]
        await self.send(ctx,"ESP 1 • ROAST",f"**Target:** {u.mention if u else target}\n\n{r.choice(lines)}",u)

    @code.command(name="2")
    async def rate(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,100)
        reasons=["certified chaos","suspiciously functional","main-character behavior","questionable decision architecture","unexpectedly elite","Guardian cannot explain the results"]
        await self.send(ctx,"ESP 2 • RATE",f"**Subject:** {u.mention if u else target}\n**Rating:** **{n}/100**\n**Analysis:** {r.choice(reasons)}.",u)

    @code.command(name="3")
    async def aura(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(-1000000,1000000)
        tier="COSMIC" if n>750000 else "ELITE" if n>250000 else "NORMAL" if n>=0 else "AURA DEBT"
        await self.send(ctx,"ESP 3 • AURA SCAN",f"**Subject:** {u.mention if u else target}\n**Aura:** **{n:+,}**\n**Classification:** {tier}",u)

    @code.command(name="4")
    async def wanted(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        crimes=["excessive yapping","stealing the last chicken nugget","criminally bad timing","refusing to touch grass","unauthorized meme possession","first-degree refrigerator theft"]
        await self.send(ctx,"ESP 4 • GUARDIAN MOST WANTED",f"**SUSPECT:** {u.mention if u else target}\n**WANTED FOR:** {r.choice(crimes).upper()}\n**DANGER LEVEL:** {r.randint(1,10)}/10\n\n*Fictional. Please do not actually arrest them.*",u)

    @code.command(name="5")
    async def bounty(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(5,9999999)
        await self.send(ctx,"ESP 5 • FICTIONAL BOUNTY",f"**Target:** {u.mention if u else target}\n**Bounty:** **{n:,} Guardian Coins**\n**Reason:** Crimes against the group chat.\n\nEntertainment only.",u)

    @code.command(name="6")
    async def mugshot(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        await self.send(ctx,"ESP 6 • FAKE INTAKE FILE",f"**Subject:** {u.mention if u else target}\n**Intake #:** ESP-{r.randint(100000,999999)}\n**Charge:** Being unbelievably suspicious\n**Status:** RELEASED INTO THE GROUP CHAT\n\nFictional parody profile.",u)

    @code.command(name="7")
    async def yap(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,100)
        tier="INTERNATIONAL YAPPER" if n>=90 else "PROFESSIONAL YAPPER" if n>=70 else "CASUAL YAPPER" if n>=40 else "SURPRISINGLY QUIET"
        await self.send(ctx,"ESP 7 • YAP DETECTOR",f"**Subject:** {u.mention if u else target}\n**Yap Level:** **{n}%**\n**Rank:** {tier}",u)

    @code.command(name="8")
    async def npc(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,100)
        await self.send(ctx,"ESP 8 • NPC SCAN",f"**Subject:** {u.mention if u else target}\n**NPC Probability:** **{n}%**\n**Dialogue Options:** {r.randint(1,4)}\n**Quest Value:** {r.choice(['3 XP','a potato','legendary','absolutely nothing'])}",u)

    @code.command(name="9")
    async def sus(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,100)
        await self.send(ctx,"ESP 9 • SUS METER",f"**Subject:** {u.mention if u else target}\n**Suspiciousness:** **{n}%**\n**Guardian Verdict:** {r.choice(['Probably innocent','Keep one eye open','Extremely questionable','Caught in 4K'])}",u)

    @code.command(name="10")
    async def cooked(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,1000)/10
        tier="FUCKING INCINERATED" if n>=95 else "BURNT" if n>=75 else "COOKED" if n>=50 else "SLIGHTLY TOASTED" if n>=25 else "SAFE"
        await self.send(ctx,"ESP 10 • COOKED ANALYSIS",f"**Subject:** {u.mention if u else target}\n**Cooked:** **{n:.1f}%**\n**Temperature:** {r.randint(70,2400):,}°F\n**Status:** {tier}",u)

    @code.command(name="11")
    async def rizz(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target);n=r.randint(0,100)
        tier="INTERGALACTIC" if n>=90 else "CERTIFIED" if n>=70 else "DEVELOPING" if n>=40 else "REQUIRES PATCH"
        await self.send(ctx,"ESP 11 • RIZZ SCAN",f"**Subject:** {u.mention if u else target}\n**Rizz:** **{n}%**\n**Classification:** {tier}",u)

    @code.command(name="12")
    async def brain(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        await self.send(ctx,"ESP 12 • BRAIN SCAN",f"**Subject:** {u.mention if u else target}\n🧠 Common Sense: **{r.randint(0,100)}%**\n🌪️ Chaos: **{r.randint(0,100)}%**\n🗣️ Yapping: **{r.randint(0,100)}%**\n⚙️ Processing Power: **{r.randint(1,999)} MHz**",u)

    @code.command(name="13")
    async def dossier(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        aliases=["The Wi-Fi Bandit","Agent Yapper","The Nugget Thief","Unknown Entity","Definitely Not Suspicious"]
        await self.send(ctx,"ESP 13 • FICTIONAL DOSSIER",f"**SUBJECT:** {u.mention if u else target}\n**ALIAS:** {r.choice(aliases)}\n**THREAT:** {r.choice(['LOW','MEDIUM','HIGH','ABSURD'])}\n**LAST SEEN:** avoiding grass\n**FILE STATUS:** CLASSIFIED-ish\n\nParody only.",u)

    @code.command(name="14")
    async def crime(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        crimes=["First-Degree Refrigerator Theft","Aggravated Yapping","Illegal Possession of 37 Memes","Grand Theft Chicken Nugget","Operating Without Common Sense","Felony Side-Eye"]
        await self.send(ctx,"ESP 14 • CRIME GENERATOR",f"**Defendant:** {u.mention if u else target}\n**Fictional charge:** **{r.choice(crimes)}**\n**Evidence:** trust me bro",u)

    @code.command(name="15")
    async def sentence(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        punish=["47 years of touching grass","900 hours in the tutorial","three consecutive Monday mornings","life without Wi-Fi","12 minutes listening to hold music","community service in the group chat"]
        await self.send(ctx,"ESP 15 • ABSURD SENTENCE",f"**Defendant:** {u.mention if u else target}\n**Sentence:** {r.choice(punish)}\n\nCompletely fictional.",u)

    @code.command(name="16")
    async def duel(self,ctx,first:str,second:str):
        a=await self.member(ctx,first);b=await self.member(ctx,second);r=self.rng(ctx.message.id,first,second)
        an=a.display_name if a else first;bn=b.display_name if b else second;winner=r.choice([an,bn])
        moves=["launched the forbidden meme","activated Wi-Fi rage","used emotional damage","threw a suspicious chicken nugget","summoned the Yap Storm"]
        await self.send(ctx,"ESP 16 • 1V1",f"⚔️ **{discord.utils.escape_markdown(an)} VS {discord.utils.escape_markdown(bn)}**\n\n{discord.utils.escape_markdown(an)} {r.choice(moves)}.\n{discord.utils.escape_markdown(bn)} {r.choice(moves)}.\n\n🏆 **WINNER: {discord.utils.escape_markdown(winner)}**")

    @code.command(name="17")
    async def boss(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        names=["THE FINAL YAPPER","LORD OF BAD DECISIONS","THE WIFI DESTROYER","CHAOS INCARNATE","THE UNTOUCHABLE NPC"]
        abilities=r.sample(["Yap Storm","Emotional Damage","Wi-Fi Disconnector","Side-Eye Beam","Touch-Grass Immunity","Nugget Barrage"],3)
        await self.send(ctx,"ESP 17 • BOSS FIGHT",f"👑 **{r.choice(names)}**\n**Subject:** {u.mention if u else target}\n❤️ **{r.randint(10000,999999):,} HP**\n⚔️ Level **{r.randint(50,999)}**\n💎 {r.choice(['RARE','EPIC','MYTHIC','ABSURD'])}\n\n**Abilities:** {' • '.join(abilities)}\n**Loot:** {r.choice(['Touch-Grass Fragment','Mythic Nugget','Infinite Wi-Fi','Aura Shard'])}",u)

    @code.command(name="18")
    async def loot(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        items=["Bent Spoon","Legendary Chicken Nugget","Mythic Aura Shard","Infinite Wi-Fi Router","Common Rock","Crown of Yapping","Golden Touch-Grass Coupon"]
        rarity=r.choices(["COMMON","UNCOMMON","RARE","EPIC","MYTHIC"],weights=[40,25,18,12,5])[0]
        await self.send(ctx,"ESP 18 • LOOT DROP",f"**Player:** {u.mention if u else target}\n🎁 **{r.choice(items)}**\n**Rarity:** {rarity}\n**Quantity:** {r.randint(1,64)}",u)

    @code.command(name="19")
    async def chaos(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        events=["Their aura suddenly doubled.","A legendary nugget fell from the sky.","Guardian revoked their NPC license.","They gained +9000 yap resistance.","A boss health bar appeared above them.","Their Wi-Fi survived an impossible attack.","They have been chosen by the Council of Memes.","Nothing happened. Somehow this is more concerning."]
        await self.send(ctx,"ESP 19 • CHAOS EVENT",f"**Target:** {u.mention if u else target}\n\n🎰 {r.choice(events)}",u)

    @code.command(name="20")
    async def roulette(self,ctx,target:str):
        u=await self.member(ctx,target);r=self.rng(ctx.message.id,target)
        outcomes=[("ROAST","Guardian searched for their comeback. Still loading."),("AURA",f"Aura changed by {r.randint(-99999,99999):+,}."),("COOKED",f"Cooked level: {r.randint(0,100)}%."),("NPC",f"NPC probability: {r.randint(0,100)}%."),("LOOT",f"Dropped: {r.choice(['Mythic Nugget','Common Rock','Aura Shard'])}."),("CHAOS","A completely unnecessary boss theme started playing.")]
        name,msg=r.choice(outcomes)
        await self.send(ctx,"ESP 20 • GUARDIAN ROULETTE",f"🎰 **RESULT: {name}**\n**Target:** {u.mention if u else target}\n\n{msg}",u)

async def setup(bot): await bot.add_cog(GuardianFun(bot))
