(()=>{
const $=id=>document.getElementById(id);
async function api(url,opts={}){const r=await fetch(url,{...opts,headers:{"Content-Type":"application/json",...(opts.headers||{})},cache:"no-store"});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d;}
const say=(id,t)=>$(id).textContent=t;
function fmt(ms){if(!ms)return"—";return new Date(ms).toLocaleString();}
function dur(sec){sec=Math.max(0,Math.floor(sec||0));const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60),s=sec%60;return (d?d+"d ":"")+(h? h+"h ":"")+(m?m+"m ":"")+s+"s";}
function cell(tr,text){const td=document.createElement("td");td.textContent=text;tr.append(td);return td;}
function action(parent,text,cls,fn){const b=document.createElement("button");b.textContent=text;b.className=cls;b.onclick=fn;parent.append(b);}
async function load(){
 const d=await api("/api/admin/overview");
 $("total").textContent=d.members.length;$("online").textContent=d.online;$("offline").textContent=d.offline;$("banned").textContent=d.members.filter(m=>m.banned).length;
 $("members").innerHTML="";
 d.members.forEach(m=>{
  const tr=document.createElement("tr");const idtd=cell(tr,m.label);const sub=document.createElement("div");sub.className="muted";sub.textContent=m.id;idtd.append(sub);
  const status=cell(tr,"");const badge=document.createElement("span");badge.className="badge"+(m.online?"":" off");badge.textContent=m.banned?"BANNED":(!m.active?"BLOCKED":(m.online?"ONLINE":"OFFLINE"));status.append(badge);
  cell(tr,m.deviceCount+" / "+m.maxDevices);cell(tr,fmt(m.expiresAt));cell(tr,dur(m.totalOnlineSeconds));cell(tr,fmt(m.lastSeen));cell(tr,m.hasApiOverride?"Individual":"Global");
  const td=cell(tr,"");td.className="row-actions";
  action(td,m.active?"BLOCK":"UNBLOCK","alt",async()=>{await api("/api/admin/members/"+m.id,{method:"PATCH",body:JSON.stringify({active:!m.active})});await load();});
  action(td,m.banned?"UNBAN":"BAN","danger",async()=>{await api("/api/admin/members/"+m.id,{method:"PATCH",body:JSON.stringify({banned:!m.banned,active:m.banned?true:false})});await load();});
  action(td,"+1 DAY","alt",async()=>{await api("/api/admin/members/"+m.id,{method:"PATCH",body:JSON.stringify({extendMinutes:1440})});await load();});
  action(td,"SET API","alt",async()=>{const k=prompt("Individual API key. Blank = global key.");if(k!==null){await api("/api/admin/members/"+m.id+"/api",{method:"POST",body:JSON.stringify({apiKey:k})});await load();}});
  action(td,"DELETE","danger",async()=>{if(confirm("Permanently delete this member?")){await api("/api/admin/members/"+m.id,{method:"DELETE"});await load();}});
  $("members").append(tr);
 });
 const [ss,ac]=await Promise.all([api("/api/admin/sessions"),api("/api/admin/activity")]);
 $("sessions").innerHTML="";
 ss.sessions.forEach(s=>{const tr=document.createElement("tr");cell(tr,s.label||"Unknown");cell(tr,s.online?"ONLINE":"OFFLINE");cell(tr,fmt(s.created_at));cell(tr,fmt(s.last_seen));cell(tr,dur(s.durationSeconds));$("sessions").append(tr);});
 $("activity").innerHTML="";
 ac.activity.forEach(a=>{const tr=document.createElement("tr");cell(tr,fmt(a.created_at));cell(tr,a.label||"System/Admin");cell(tr,a.event);cell(tr,a.detail||"");$("activity").append(tr);});
}
function generateKey(){const bytes=crypto.getRandomValues(new Uint8Array(10));const k="HACKII-"+Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();$("memberKey").value=k;return k;}
$("generate").onclick=generateKey;
$("copyKey").onclick=async()=>{const v=$("memberKey").value;if(!v){say("createMsg","Generate a key first.");return;}try{await navigator.clipboard.writeText(v);say("createMsg","Key copied.");}catch(e){$("memberKey").select();say("createMsg","Select and copy the key manually.");}};
$("loginBtn").onclick=async()=>{try{await api("/api/admin/login",{method:"POST",body:JSON.stringify({key:$("adminKey").value})});$("login").classList.add("hidden");$("dashboard").classList.remove("hidden");await load();setInterval(()=>load().catch(e=>say("loginMsg",e.message)),15000);}catch(e){say("loginMsg",e.message);}};
$("create").onclick=async()=>{try{const body={label:$("label").value,key:$("memberKey").value,maxDevices:Number($("devices").value),days:Number($("days").value),hours:Number($("hours").value),minutes:Number($("minutes").value)};const d=await api("/api/admin/members",{method:"POST",body:JSON.stringify(body)});$("memberKey").value=d.key;say("createMsg","SUCCESS: Key created: "+d.key+" · Copy and save it now.");await load();}catch(e){say("createMsg",e.message);}};
$("saveSettings").onclick=async()=>{try{await api("/api/admin/settings",{method:"POST",body:JSON.stringify({globalMemberKey:$("globalMember").value,globalApiKey:$("globalApi").value})});say("settingsMsg","Global settings saved successfully.");$("globalMember").value="";$("globalApi").value="";}catch(e){say("settingsMsg",e.message);}};
$("refresh").onclick=()=>load().catch(e=>say("loginMsg",e.message));
$("logout").onclick=async()=>{await api("/api/logout",{method:"POST",body:"{}"});location.reload();};
})();