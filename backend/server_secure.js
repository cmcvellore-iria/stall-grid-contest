// backend/server_secure.js  — sqlite3 version for Render

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const path = require("path");
require("dotenv").config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc_secret_change_me";
const ADMIN_PASS = process.env.ADMIN_PASS || "change_admin_pass";

// open DB
const db = new sqlite3.Database(path.join(__dirname, "secure_data.db"));

// helpers for sqlite3 → promise
function run(sql, params=[]) {
  return new Promise((resolve, reject)=>{
    db.run(sql, params, function(err){
      if(err) reject(err);
      else resolve(this);
    });
  });
}
function get(sql, params=[]) {
  return new Promise((resolve, reject)=>{
    db.get(sql, params, (err,row)=>{
      if(err) reject(err);
      else resolve(row);
    });
  });
}
function all(sql, params=[]) {
  return new Promise((resolve, reject)=>{
    db.all(sql, params, (err,rows)=>{
      if(err) reject(err);
      else resolve(rows);
    });
  });
}

// tables
(async ()=>{
  await run(`
  CREATE TABLE IF NOT EXISTS delegates(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emailHash TEXT UNIQUE,
    emailEncrypted TEXT,
    name TEXT,
    delegateId TEXT UNIQUE,
    isApproved INTEGER DEFAULT 0
  )`);

  await run(`
  CREATE TABLE IF NOT EXISTS visits(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    delegateId TEXT,
    stall INTEGER,
    ts INTEGER
  )`);

  await run(`
  CREATE TABLE IF NOT EXISTS otp_codes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    emailHash TEXT,
    codeHash TEXT,
    expiresAt INTEGER
  )`);

  await run(`
  CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER,
    ip TEXT,
    action TEXT,
    details TEXT
  )`);
})();

// utils
function emailHash(email){
  return crypto.createHash("sha256")
    .update(String(email).toLowerCase().trim())
    .digest("hex");
}

function encrypt(text){
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash("sha256").update(ENC_SECRET).digest();
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let enc = cipher.update(String(text), "utf8", "base64");
  enc += cipher.final("base64");
  return iv.toString("base64") + ":" + enc;
}

async function logAction(req, action, details){
  try{
    await run(
      `INSERT INTO audit_logs(ts,ip,action,details) VALUES(?,?,?,?)`,
      [Date.now(), req.ip||"", action, JSON.stringify(details||{})]
    );
  }catch(e){}
}

// app
const app = express();
app.use(express.json());

// CORS
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization,x-admin-pass");
  if(req.method==="OPTIONS"){res.status(204).end();return;}
  next();
});

// rate limit
const otpRequestLimiter = rateLimit({
  windowMs: 15*60*1000,
  max: 20,
  message: {error:"too many requests"}
});
const otpVerifyLimiter = rateLimit({
  windowMs: 15*60*1000,
  max: 60,
  message: {error:"slow down"}
});

// admin auth
function adminAuth(req,res,next){
  if(req.headers["x-admin-pass"]!==ADMIN_PASS){
    return res.status(403).json({error:"forbidden"});
  }
  next();
}

// jwt auth
function authMiddleware(req,res,next){
  const h=req.headers.authorization||"";
  const m=h.match(/^Bearer\s+(.+)$/);
  if(!m) return res.status(401).json({error:"auth required"});
  try{
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  }catch(e){
    return res.status(401).json({error:"invalid token"});
  }
}

// request OTP
app.post("/api/request-otp", otpRequestLimiter, async (req,res)=>{
  const {email}=req.body||{};
  if(!email) return res.status(400).json({error:"email required"});

  const eHash=emailHash(email);
  let delegate=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);

  if(!delegate){
    const delegateId="D"+Math.floor(100000+Math.random()*900000);
    await run(
      `INSERT INTO delegates(emailHash,emailEncrypted,name,delegateId,isApproved)
       VALUES (?,?,?,?,0)`,
      [eHash,encrypt(email),email,delegateId]
    );
    delegate=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
    await logAction(req,"SIGNUP_PENDING",{email,delegateId});
  }

  const code = Math.floor(100000+Math.random()*900000).toString();
  const codeHash = crypto.createHash("sha256").update(code).digest("hex");
  const expiresAt = Date.now()+5*60*1000;

  await run(
    `INSERT INTO otp_codes(emailHash,codeHash,expiresAt) VALUES(?,?,?)`,
    [eHash,codeHash,expiresAt]
  );

  console.log("OTP",email,code); // TODO email
  await logAction(req,"OTP_REQUEST",{email});
  res.json({ok:true});
});

// login OTP
app.post("/api/login-otp", otpVerifyLimiter, async (req,res)=>{
  const {email,code}=req.body||{};
  if(!email||!code) return res.status(400).json({error:"email/code required"});

  const eHash=emailHash(email);
  const delegate=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
  if(!delegate) return res.status(400).json({error:"no user"});

  const codeHash=crypto.createHash("sha256").update(code).digest("hex");
  const row=await get(
    `SELECT * FROM otp_codes WHERE emailHash=? AND codeHash=? AND expiresAt>? ORDER BY id DESC`,
    [eHash,codeHash,Date.now()]
  );
  if(!row){
    await logAction(req,"OTP_FAIL",{email});
    return res.status(400).json({error:"invalid"});
  }

  await run(`DELETE FROM otp_codes WHERE id=?`,[row.id]);

  const token=jwt.sign({
    id:delegate.id,
    delegateId:delegate.delegateId,
    emailHash:delegate.emailHash
  },JWT_SECRET,{expiresIn:"3d"});

  await logAction(req,"OTP_SUCCESS",{delegateId:delegate.delegateId});
  res.json({
    token,
    delegateId:delegate.delegateId,
    name:delegate.name,
    isApproved:!!delegate.isApproved
  });
});

// verify scan
app.post("/api/verify", authMiddleware, async (req,res)=>{
  const {stall,token,exp}=req.body||{};
  if(!stall||!token||!exp) return res.status(400).json({error:"missing"});

  const delegateId=req.user.delegateId;
  const delegate=await get(`SELECT * FROM delegates WHERE delegateId=?`,[delegateId]);
  if(!delegate) return res.status(400).json({error:"no delegate"});
  if(!delegate.isApproved) return res.status(403).json({error:"pending"});

  const expected=crypto.createHmac("sha256",TOKEN_SECRET)
    .update(`${delegateId}|${stall}|${exp}`)
    .digest("hex");

  if(expected!==token) return res.status(400).json({error:"bad token"});
  if(Number(exp)<Date.now()) return res.status(400).json({error:"expired"});

  const exists=await get(
    `SELECT 1 FROM visits WHERE delegateId=? AND stall=?`,
    [delegateId,stall]
  );
  if(!exists){
    await run(
      `INSERT INTO visits(delegateId,stall,ts) VALUES (?,?,?)`,
      [delegateId,stall,Date.now()]
    );
    await logAction(req,"VISIT",{delegateId,stall});
  }

  res.json({ok:true});
});

// visits
app.get("/api/visits/:delegateId", authMiddleware, async (req,res)=>{
  const delegateId=req.params.delegateId;
  if(delegateId!==req.user.delegateId) return res.status(403).json({error:"forbidden"});
  const rows=await all(`SELECT stall FROM visits WHERE delegateId=? ORDER BY stall ASC`,[delegateId]);
  res.json({visits:rows.map(r=>r.stall)});
});

// leaderboard
app.get("/api/leaderboard", async (req,res)=>{
  const rows=await all(`
    SELECT delegateId,COUNT(*) as cnt
    FROM visits
    GROUP BY delegateId
    ORDER BY cnt DESC LIMIT 50
  `);
  const out=[];
  for(const r of rows){
    const d=await get(`SELECT name FROM delegates WHERE delegateId=?`,[r.delegateId]);
    out.push({delegateId:r.delegateId,name:d&&d.name,count:r.cnt});
  }
  res.json({top:out});
});

// admin pending
app.get("/api/admin/pending", adminAuth, async (req,res)=>{
  const rows=await all(`SELECT id,name,delegateId,emailEncrypted,isApproved FROM delegates WHERE isApproved=0`);
  res.json({pending:rows});
});

// admin approve
app.post("/api/admin/approve", adminAuth, async (req,res)=>{
  const {delegateId}=req.body||{};
  if(!delegateId) return res.status(400).json({error:"missing"});
  await run(`UPDATE delegates SET isApproved=1 WHERE delegateId=?`,[delegateId]);
  await logAction(req,"APPROVE",{delegateId});
  res.json({ok:true});
});

// admin cleanup
app.post("/api/admin/cleanup", adminAuth, async (req,res)=>{
  await run(`DELETE FROM visits`);
  await run(`DELETE FROM delegates`);
  await run(`DELETE FROM otp_codes`);
  await run(`DELETE FROM audit_logs`);
  res.json({ok:true});
});

app.get("/",(req,res)=>res.json({status:"ok",service:"secure-stall-backend"}));

app.listen(PORT,()=>{
  console.log("Secure backend listening on",PORT);
});
