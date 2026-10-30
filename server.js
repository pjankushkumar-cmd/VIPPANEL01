const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const { DatabaseSync } = require("node:sqlite");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_KEY = String(process.env.ADMIN_KEY || "");
// Keep service configuration in code as requested. Change API URL/header here if provider changes.
const RESULT_API_URL = "https://draw.ar-lottery01.com/WinGo/WinGo_1M/GetHistoryIssuePage.json?pageNo=1";
const RESULT_API_KEY_HEADER = "X-API-Key";
const DATABASE_FILE = path.join(__dirname, "data", "hackii.sqlite");
const SESSION_HOURS = 24;
const ONLINE_WINDOW_MS = 75_000;
const MAX_DEVICE_LIMIT = 100_000;

if (ADMIN_KEY.length < 24) {
  console.error("Startup blocked: set ADMIN_KEY in hosting Environment (minimum 24 characters).");
  process.exit(1);
}
fs.mkdirSync(path.dirname(DATABASE_FILE), { recursive: true });
const db = new DatabaseSync(DATABASE_FILE);
db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");

db.exec(`
CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY, label TEXT NOT NULL, key_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, banned INTEGER NOT NULL DEFAULT 0,
  max_devices INTEGER NOT NULL DEFAULT 1, expires_at INTEGER,
  created_at INTEGER NOT NULL, last_seen INTEGER, api_override TEXT,
  total_online_seconds INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  device_hash TEXT NOT NULL, user_agent TEXT, created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL, UNIQUE(member_id,device_hash)
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, member_id TEXT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  device_hash TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL, ended_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT, member_id TEXT, event TEXT NOT NULL,
  detail TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_member ON sessions(member_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity(created_at);
`);

function addColumnIfMissing(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(x => x.name);
  if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
addColumnIfMissing("members","banned","INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("members","total_online_seconds","INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("sessions","last_seen","INTEGER NOT NULL DEFAULT 0");
addColumnIfMissing("sessions","ended_at","INTEGER");

const now = () => Date.now();
const sha = value => crypto.createHash("sha256").update(String(value)).digest("hex");
const makeToken = () => crypto.randomBytes(36).toString("base64url");
const normalizeKey = value => String(value ?? "").normalize("NFKC").trim();
const getSetting = key => db.prepare("SELECT value FROM settings WHERE key=?").get(key)?.value || "";
const setSetting = (key,value) => db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key,String(value));
const logEvent = (memberId,event,detail="") => db.prepare("INSERT INTO activity(member_id,event,detail,created_at) VALUES(?,?,?,?)").run(memberId || null,event,String(detail).slice(0,300),now());

app.disable("x-powered-by");
app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:{directives:{
  defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],
  connectSrc:["'self'"],imgSrc:["'self'","data:"],objectSrc:["'none'"],baseUri:["'self'"],
  upgradeInsecureRequests:[]
}}}));
app.use(express.json({limit:"25kb"}));
app.use(cookieParser());
app.use((req,res,next)=>{res.setHeader("Cache-Control","no-store");next();});
app.use(express.static(path.join(__dirname,"public")));
app.use("/api",rateLimit({windowMs:60_000,limit:180,standardHeaders:true,legacyHeaders:false}));

function setSessionCookie(res,token) {
  res.cookie("hackii_session",token,{httpOnly:true,secure:true,sameSite:"strict",maxAge:SESSION_HOURS*3600000,path:"/"});
}
function createSession(memberId,deviceHash,role,req,res) {
  const token=makeToken(), t=now();
  db.prepare("INSERT INTO sessions(token_hash,member_id,device_hash,role,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?,?)")
    .run(sha(token),memberId,deviceHash,role,t,t,t+SESSION_HOURS*3600000);
  setSessionCookie(res,token);
}
function getSession(req) {
  const token=req.cookies?.hackii_session;
  if(!token) return null;
  return db.prepare("SELECT * FROM sessions WHERE token_hash=? AND expires_at>? AND ended_at IS NULL").get(sha(token),now()) || null;
}
function requireRole(role) {
  return (req,res,next)=>{
    const session=getSession(req);
    if(!session || session.role!==role) return res.status(401).json({error:"Please log in again."});
    req.session=session;
    if(role==="member") {
      const m=db.prepare("SELECT * FROM members WHERE id=?").get(session.member_id);
      if(!m || !m.active || m.banned || (m.expires_at && m.expires_at<=now())) {
        return res.status(403).json({error:m?.banned?"Membership banned. Contact admin.":"Membership inactive or expired."});
      }
      const device=db.prepare("SELECT id FROM devices WHERE member_id=? AND device_hash=?").get(m.id,session.device_hash);
      if(!device) return res.status(403).json({error:"This device is not registered."});
      const elapsed=Math.max(0,Math.min(60,Math.floor((now()-session.last_seen)/1000)));
      if(elapsed>0) db.prepare("UPDATE members SET total_online_seconds=total_online_seconds+? WHERE id=?").run(elapsed,m.id);
      db.prepare("UPDATE sessions SET last_seen=? WHERE token_hash=?").run(now(),sha(req.cookies.hackii_session));
      db.prepare("UPDATE members SET last_seen=? WHERE id=?").run(now(),m.id);
      db.prepare("UPDATE devices SET last_seen=? WHERE member_id=? AND device_hash=?").run(now(),m.id,session.device_hash);
    }
    next();
  };
}
const adminOnly=requireRole("admin");
const memberOnly=requireRole("member");
const loginLimiter=rateLimit({windowMs:15*60_000,limit:20,standardHeaders:true,legacyHeaders:false});

app.post("/api/admin/login",loginLimiter,(req,res)=>{
  const supplied=Buffer.from(sha(normalizeKey(req.body?.key)));
  const expected=Buffer.from(sha(ADMIN_KEY));
  if(!crypto.timingSafeEqual(supplied,expected)) return res.status(401).json({error:"Invalid admin key."});
  // Keep compatibility with earlier SQLite schemas where sessions.member_id is NOT NULL.
  db.prepare("INSERT OR IGNORE INTO members(id,label,key_hash,active,banned,max_devices,created_at) VALUES('ADMIN','System Admin',?,0,1,0,?)")
    .run("SYSTEM-ACCOUNT-NO-LOGIN",now());
  createSession("ADMIN","","admin",req,res);
  logEvent(null,"ADMIN_LOGIN","Admin signed in");
  res.json({ok:true});
});

app.post("/api/member/login",loginLimiter,async(req,res)=>{
  const key=normalizeKey(req.body?.key);
  const deviceId=String(req.body?.deviceId||"");
  if(key.length<6 || key.length>128 || !/^[a-f0-9]{32,100}$/i.test(deviceId))
    return res.status(400).json({error:"Enter a valid member key."});

  let member=null;
  const candidates=db.prepare("SELECT * FROM members WHERE active=1 AND banned=0 AND id<>'GLOBAL'").all();
  for(const candidate of candidates) {
    if(await bcrypt.compare(key,candidate.key_hash)){member=candidate;break;}
  }
  if(!member) {
    const globalHash=getSetting("global_member_hash");
    if(globalHash && await bcrypt.compare(key,globalHash)) {
      member=db.prepare("SELECT * FROM members WHERE id='GLOBAL'").get();
      if(!member) {
        const placeholder=await bcrypt.hash(makeToken(),12);
        db.prepare("INSERT INTO members(id,label,key_hash,active,banned,max_devices,created_at) VALUES('GLOBAL','Global Access',?,1,0,100000,?)").run(placeholder,now());
        member=db.prepare("SELECT * FROM members WHERE id='GLOBAL'").get();
      }
    }
  }
  if(!member) return res.status(401).json({error:"Invalid member key. Check the key in Admin Panel."});
  if(!member.active || member.banned) return res.status(403).json({error:"This member is blocked or banned."});
  if(member.expires_at && member.expires_at<=now()) return res.status(403).json({error:"Membership expired."});

  const deviceHash=sha(deviceId);
  const existing=db.prepare("SELECT id FROM devices WHERE member_id=? AND device_hash=?").get(member.id,deviceHash);
  if(!existing) {
    const count=db.prepare("SELECT COUNT(*) AS n FROM devices WHERE member_id=?").get(member.id).n;
    if(count>=member.max_devices) return res.status(403).json({error:"Device limit reached. Contact admin."});
    db.prepare("INSERT INTO devices(id,member_id,device_hash,user_agent,created_at,last_seen) VALUES(?,?,?,?,?,?)")
      .run(crypto.randomUUID(),member.id,deviceHash,String(req.headers["user-agent"]||"").slice(0,250),now(),now());
    logEvent(member.id,"DEVICE_REGISTERED","New device registered");
  } else {
    db.prepare("UPDATE devices SET last_seen=?,user_agent=? WHERE member_id=? AND device_hash=?")
      .run(now(),String(req.headers["user-agent"]||"").slice(0,250),member.id,deviceHash);
  }
  db.prepare("UPDATE members SET last_seen=? WHERE id=?").run(now(),member.id);
  createSession(member.id,deviceHash,"member",req,res);
  logEvent(member.id,"LOGIN","Member logged in");
  res.json({ok:true,member:{id:member.id,label:member.label,expiresAt:member.expires_at}});
});

app.post("/api/member/heartbeat",memberOnly,(req,res)=>{
  logEvent(req.session.member_id,"HEARTBEAT","Member active");
  res.json({ok:true,serverTime:now()});
});

app.post("/api/logout",(req,res)=>{
  const token=req.cookies?.hackii_session;
  if(token) {
    const s=db.prepare("SELECT * FROM sessions WHERE token_hash=? AND ended_at IS NULL").get(sha(token));
    if(s) {
      db.prepare("UPDATE sessions SET ended_at=?,last_seen=? WHERE token_hash=?").run(now(),now(),sha(token));
      if(s.role==="member") logEvent(s.member_id,"LOGOUT","Member logged out");
    }
  }
  res.clearCookie("hackii_session",{path:"/",secure:true,sameSite:"strict"});
  res.json({ok:true});
});

app.get("/api/admin/overview",adminOnly,(req,res)=>{
  const members=db.prepare("SELECT * FROM members WHERE id<>'ADMIN' ORDER BY created_at DESC").all().map(m=>{
    const deviceCount=db.prepare("SELECT COUNT(*) AS n FROM devices WHERE member_id=?").get(m.id).n;
    const onlineSessions=db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE member_id=? AND ended_at IS NULL AND expires_at>? AND last_seen>?").get(m.id,now(),now()-ONLINE_WINDOW_MS).n;
    const currentOnlineSeconds=db.prepare("SELECT COALESCE(SUM(MAX(0,MIN(60,CAST((?-last_seen)/1000 AS INTEGER)))),0) AS n FROM sessions WHERE member_id=? AND ended_at IS NULL").get(now(),m.id).n;
    return {id:m.id,label:m.label,active:!!m.active,banned:!!m.banned,maxDevices:m.max_devices,
      expiresAt:m.expires_at,createdAt:m.created_at,lastSeen:m.last_seen,
      online:onlineSessions>0,onlineSessions,deviceCount,
      totalOnlineSeconds:m.total_online_seconds+currentOnlineSeconds,
      hasApiOverride:!!m.api_override};
  });
  res.json({members,online:members.filter(m=>m.online).length,offline:members.filter(m=>!m.online).length});
});

app.post("/api/admin/members",adminOnly,async(req,res)=>{
  const label=String(req.body?.label||"").trim().slice(0,80);
  let key=normalizeKey(req.body?.key);
  if(!key) key="HK-"+crypto.randomBytes(9).toString("hex").toUpperCase();
  const maxDevices=Number(req.body?.maxDevices);
  const days=Number(req.body?.days||0),hours=Number(req.body?.hours||0),minutes=Number(req.body?.minutes||0);
  if(!label || key.length<8 || key.length>128 || !Number.isSafeInteger(maxDevices) || maxDevices<1 || maxDevices>MAX_DEVICE_LIMIT ||
     ![days,hours,minutes].every(Number.isFinite) || days<0 || hours<0 || minutes<0 || days+hours+minutes<=0 ||
     days>36500 || hours>875000 || minutes>52560000) {
    return res.status(400).json({error:"Check name, key, device limit (1–100000) and positive expiry duration."});
  }
  const id=crypto.randomUUID(), expires=now()+((days*24+hours)*60+minutes)*60000;
  db.prepare("INSERT INTO members(id,label,key_hash,active,banned,max_devices,expires_at,created_at) VALUES(?,?,?,1,0,?,?,?)")
    .run(id,label,await bcrypt.hash(key,12),maxDevices,expires,now());
  logEvent(id,"MEMBER_CREATED","Member key created by admin");
  res.json({ok:true,id,label,key});
});

app.patch("/api/admin/members/:id",adminOnly,(req,res)=>{
  const m=db.prepare("SELECT * FROM members WHERE id=?").get(req.params.id);
  if(!m) return res.status(404).json({error:"Member not found"});
  if(typeof req.body?.active==="boolean") db.prepare("UPDATE members SET active=? WHERE id=?").run(req.body.active?1:0,m.id);
  if(typeof req.body?.banned==="boolean") db.prepare("UPDATE members SET banned=? WHERE id=?").run(req.body.banned?1:0,m.id);
  if(req.body?.maxDevices!==undefined) {
    const n=Number(req.body.maxDevices);
    if(!Number.isSafeInteger(n)||n<1||n>MAX_DEVICE_LIMIT) return res.status(400).json({error:"Device limit must be 1–100000."});
    db.prepare("UPDATE members SET max_devices=? WHERE id=?").run(n,m.id);
  }
  if(req.body?.extendMinutes!==undefined) {
    const mins=Number(req.body.extendMinutes);
    if(!Number.isFinite(mins)||mins<=0||mins>52560000) return res.status(400).json({error:"Invalid extension."});
    db.prepare("UPDATE members SET expires_at=? WHERE id=?").run(Math.max(m.expires_at||now(),now())+mins*60000,m.id);
  }
  if(req.body?.expiresAt!==undefined) {
    const expiry=Number(req.body.expiresAt);
    if(!Number.isFinite(expiry)||expiry<=now()) return res.status(400).json({error:"Expiry must be a future timestamp."});
    db.prepare("UPDATE members SET expires_at=? WHERE id=?").run(expiry,m.id);
  }
  logEvent(m.id,"MEMBER_UPDATED","Member settings changed");
  res.json({ok:true});
});

app.delete("/api/admin/members/:id",adminOnly,(req,res)=>{
  const id=req.params.id;
  db.prepare("DELETE FROM sessions WHERE member_id=?").run(id);
  db.prepare("DELETE FROM devices WHERE member_id=?").run(id);
  db.prepare("DELETE FROM members WHERE id=?").run(id);
  logEvent(id,"MEMBER_DELETED","Member deleted");
  res.json({ok:true});
});

app.post("/api/admin/settings",adminOnly,async(req,res)=>{
  if(req.body?.globalMemberKey!==undefined) {
    const key=normalizeKey(req.body.globalMemberKey);
    if(key) setSetting("global_member_hash",await bcrypt.hash(key,12));
    else db.prepare("DELETE FROM settings WHERE key='global_member_hash'").run();
  }
  if(req.body?.globalApiKey!==undefined) setSetting("global_api_key",String(req.body.globalApiKey).slice(0,512));
  res.json({ok:true});
});
app.post("/api/admin/members/:id/api",adminOnly,(req,res)=>{
  const key=String(req.body?.apiKey||"").trim().slice(0,512);
  db.prepare("UPDATE members SET api_override=? WHERE id=?").run(key||null,req.params.id);
  res.json({ok:true});
});
app.get("/api/admin/activity",adminOnly,(req,res)=>{
  const rows=db.prepare(`SELECT a.*,m.label FROM activity a LEFT JOIN members m ON m.id=a.member_id ORDER BY a.id DESC LIMIT 250`).all();
  res.json({activity:rows});
});
app.get("/api/admin/sessions",adminOnly,(req,res)=>{
  const rows=db.prepare(`SELECT s.member_id,m.label,s.created_at,s.last_seen,s.ended_at,s.expires_at
    FROM sessions s LEFT JOIN members m ON m.id=s.member_id WHERE s.role='member'
    ORDER BY s.created_at DESC LIMIT 200`).all();
  res.json({sessions:rows.map(s=>({...s,online:!s.ended_at && s.expires_at>now() && s.last_seen>now()-ONLINE_WINDOW_MS,
    durationSeconds:Math.max(0,Math.floor(((s.ended_at||s.last_seen)-s.created_at)/1000))}))});
});

let apiCache={at:0,data:null};
app.get("/api/results",memberOnly,async(req,res)=>{
  const m=db.prepare("SELECT api_override FROM members WHERE id=?").get(req.session.member_id);
  const apiKey=m.api_override||getSetting("global_api_key");
  if(apiCache.data && now()-apiCache.at<2500) return res.json(apiCache.data);
  const headers={"Accept":"application/json"};
  if(apiKey) headers[RESULT_API_KEY_HEADER]=apiKey;
  try {
    const upstream=await fetch(RESULT_API_URL,{headers,cache:"no-store",signal:AbortSignal.timeout(9000)});
    if(!upstream.ok) return res.status(502).json({error:"Result API HTTP "+upstream.status});
    const data=await upstream.json();
    apiCache={at:now(),data};
    logEvent(req.session.member_id,"RESULT_API_READ","Result source checked");
    res.json(data);
  } catch(error) {
    res.status(502).json({error:"Result API connection failed. Check the server API endpoint."});
  }
});
app.get("/health",(req,res)=>res.json({ok:true,time:now()}));
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log("HACKII server listening on port "+PORT));
