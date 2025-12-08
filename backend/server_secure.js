// ===============================
// Secure Stall Backend – FINAL
// ===============================

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const path = require("path");
const nodemailer = require("nodemailer");

require("dotenv").config();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc_secret_change_me";
const ADMIN_PASS = process.env.ADMIN_PASS || "cmcvsgc";

// *** your Netlify URL ***
const FRONTEND = "https://cmcv-sgc-iria2025.netlify.app";

// =================================
//    Express app
// =================================
const app = express();
app.use(express.json());

// Required for Render proxy + rate limit
app.set("trust proxy", 1);

// =================================
// CORS – only allow your Netlify
// =================================
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin", FRONTEND);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization,x-admin-pass");
  
  if(req.method==="OPTIONS"){
    return res.status(200).end();
  }
  next();
});

// =================================
// DB setup
// =================================
const db = new sqlite3.Database(path.join(__dirname, "secure_data.db"));

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

// =================================
// tables
// =================================
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

// =================================
// utils
// =================================
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

// =================================
// Nodemailer Gmail
// =================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  connectionTimeout: 30000
});

// =================================
// rate limit
// =================================
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

// =================================
// request OTP
// =================================
app.post("/api/request-otp", otpRequestLimiter, async (req,res)=>{
  try{
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

    // send email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "CMC IRIA Login OTP",
      text: `Your OTP code is: ${code}\nValid for 5 minutes.`
    });

    await logAction(req,"OTP_REQUEST",{email});
    res.json({ok:true});
  }catch(e){
    console.error("OTP Email Error:",e);
    res.status(500).json({error:"smtp_fail"});
  }
});

// =================================
// login-otp
// =================================
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

// =================================
// the rest (verify, visits, leaderboard, admin)
// =================================

// scan verify
app.post("/api/verify", async (req,res)=>{
  res.json({error:"todo"});
});

// leaderboard
app.get("/api/leaderboard", async (req,res)=>{
  res.json({top:[]});
});

// admin stub
app.get("/api/admin/pending", (req,res)=>{
  res.json({pending:[]});
});

app.get("/",(req,res)=>{
  res.json({status:"ok"});
});

app.listen(PORT,()=>{
  console.log("Secure backend listening on",PORT);
});
