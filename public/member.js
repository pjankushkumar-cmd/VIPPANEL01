(()=>{
const $=id=>document.getElementById(id);
let deviceId=localStorage.getItem("hackii_device_id");
if(!deviceId){deviceId=Array.from(crypto.getRandomValues(new Uint8Array(24)),b=>b.toString(16).padStart(2,"0")).join("");localStorage.setItem("hackii_device_id",deviceId);}
async function api(url,opts={}){const r=await fetch(url,{...opts,headers:{"Content-Type":"application/json",...(opts.headers||{})},cache:"no-store"});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Request failed");return d;}
function findRows(payload){
 const possible=[payload?.data?.list,payload?.data?.records,payload?.data?.items,payload?.list,payload?.records,payload?.items,payload?.data?.data];
 for(const a of possible)if(Array.isArray(a))return a;
 // fallback: walk nested JSON objects and locate an array of issue/number records
 const seen=new Set(),stack=[payload];
 while(stack.length){const v=stack.pop();if(!v||typeof v!=="object"||seen.has(v))continue;seen.add(v);
  if(Array.isArray(v)){if(v.length&&v.some(x=>x&&typeof x==="object"&&(x.issueNumber||x.issue||x.period||x.issue_no)))return v;continue;}
  for(const x of Object.values(v))if(x&&typeof x==="object")stack.push(x);
 }
 return [];
}
function readIssue(row){return String(row.issueNumber??row.issue_no??row.issue??row.period??row.drawId??row.periodNumber??"");}
function readNumber(row){
 const candidates=[row.number,row.result,row.openNumber,row.winNumber,row.lotteryNumber,row.value,row.resultNumber];
 for(const v of candidates){if(v===undefined||v===null)continue;const m=String(v).match(/^\s*(\d{1,2})/);if(m){const n=Number(m[1]);if(n>=0&&n<=9)return n;}}
 return null;
}
function nextIssue(issue){const m=String(issue).match(/^(.*?)(\d+)$/);if(!m)return "—";return m[1]+String(BigInt(m[2])+1n).padStart(m[2].length,"0");}
async function sha256(s){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(s));return Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");}
let polling=false,latestEstimatePeriod="";
async function updateEstimate(){
 if(polling)return;polling=true;
 try{
  const payload=await api("/api/results");
  const rows=findRows(payload).slice(0,10).map(r=>({issue:readIssue(r),number:readNumber(r)})).filter(r=>r.issue&&Number.isInteger(r.number));
  if(!rows.length)throw Error("API connected, but its result format was not recognized. Check API fields in server.js.");
  const upcoming=nextIssue(rows[0].issue);
  if(upcoming==="—")throw Error("Latest API issue number could not be read.");
  const fingerprint=rows.map(x=>x.issue+":"+x.number).join("|");
  const digest=await sha256("HACKII-SHA256|"+upcoming+"|"+fingerprint);
  const digit=parseInt(digest.slice(0,8),16)%10;
  $("period").textContent=upcoming;$("digit").textContent=String(digit);$("size").textContent=digit<=4?"SMALL":"BIG";
  $("status").textContent="Live API scan: "+rows.length+" valid results · Updated "+new Date().toLocaleTimeString()+" · Estimate only, not guaranteed";
  latestEstimatePeriod=upcoming;
 }catch(e){$("status").textContent=e.message;}
 finally{polling=false;}
}
let timers=[];
$("start").onclick=async()=>{
 $("msg").textContent="";
 try{
  const result=await api("/api/member/login",{method:"POST",body:JSON.stringify({key:$("key").value,deviceId})});
  $("login").classList.add("hide");$("app").classList.remove("hide");
  $("welcome").textContent="Welcome, "+result.member.label;
  await updateEstimate();
  timers.push(setInterval(updateEstimate,8000));
  timers.push(setInterval(()=>api("/api/member/heartbeat",{method:"POST",body:"{}"}).catch(e=>{$("status").textContent=e.message;}),20000));
 }catch(e){$("msg").textContent=e.message;}
};
$("key").onkeydown=e=>{if(e.key==="Enter")$("start").click();};
$("logout").onclick=async()=>{timers.forEach(clearInterval);await api("/api/logout",{method:"POST",body:"{}"}).catch(()=>{});location.reload();};
})();