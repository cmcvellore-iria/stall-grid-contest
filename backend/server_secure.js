// ========= Secure CMC IRIA 2025 Backend — Brevo SMTP =========

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.set("trust proxy", true);

// --- configuration ---
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc";
const ADMIN_PASS = process.env.ADMIN_PASS || "cmcvsgc";

// ===== allowed frontend origin ======
const allowedOrigins = [
  "https://cmcv-sgc-iria2025.netlify.app"
];

// ===== CORS ======
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,x-admin-pass");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

// ===== DB =====
const db = new sqlite3.Database(path.join(__dirname, "secure_data.db"));

function run(sql, p=[]) {
  return new Promise((resolve,reject)=>{
      db.run(sql,p,function(e){ e?reject(e):resolve(this); });
  });
}
function get(sql,p=[]) {
  return new Promise((resolve,reject)=>{
      db.get(sql,p,(e,r)=> e?reject(e):resolve(r));
  });
}

// create tables
(async()=>{
 await run(`CREATE TABLE IF NOT EXISTS delegates(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   emailHash TEXT UNIQUE,
   emailEncrypted TEXT,
   name TEXT,
   delegateId TEXT UNIQUE,
   isApproved INTEGER DEFAULT 0)`);

 await run(`CREATE TABLE IF NOT EXISTS visits(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   delegateId TEXT,
   stall INTEGER,
   ts INTEGER)`);

 await run(`CREATE TABLE IF NOT EXISTS otp_codes(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   emailHash TEXT,
   codeHash TEXT,
   expiresAt INTEGER)`);

 await run(`CREATE TABLE IF NOT EXISTS audit_logs(
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   ts INTEGER,
   ip TEXT,
   action TEXT,
   details TEXT)`);
})();

// helpers
function emailHash(e){
 return crypto.createHash("sha256").update(String(e).toLowerCase().trim()).digest("hex");
}

function encrypt(text){
  const iv=crypto.randomBytes(16);
  const key=crypto.createHash("sha256").update(ENC_SECRET).digest();
  const cipher=crypto.createCipheriv("aes-256-cbc", key, iv);
  let x=cipher.update(String(text),"utf8","base64");
  x+=cipher.final("base64");
  return iv.toString("base64")+":"+x;
}

// ===== SMTP Transporter (BREVO SMTP) ======
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
});

// ===== request OTP =====
app.post("/api/request-otp", async (req,res)=>{
  try{
    const {email}=req.body||{};
    if(!email) return res.status(400).json({error:"email required"});

    const normalizedEmail = String(email).toLowerCase().trim();
    const eHash = emailHash(normalizedEmail);

    let d = await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
    if(!d){
      const delegateId="D"+Math.floor(100000+Math.random()*900000);
      await run(
        `INSERT INTO delegates(emailHash,emailEncrypted,name,delegateId,isApproved)
         VALUES(?,?,?,?,0)`,
        [eHash,encrypt(normalizedEmail),normalizedEmail,delegateId]
      );
    }

    const code=String(Math.floor(100000+Math.random()*900000));
    const codeHash=crypto.createHash("sha256").update(code).digest("hex");

    await run(
      `INSERT INTO otp_codes(emailHash,codeHash,expiresAt) VALUES(?,?,?)`,
      [eHash,codeHash,Date.now()+5*60*1000]
    );

    await transporter.sendMail({
      from: `"CMC IRIA 2025" <${process.env.SMTP_USER}>`,
      to: normalizedEmail,
      subject: "CMC IRIA OTP",
      text: `Your OTP is ${code} (valid 5 min)`
    });

    res.json({ok:true});
  }catch(e){
    console.log("SMTP FAIL:",e);
    res.status(500).json({error:"smtp_fail"});
  }
});

// ===== verify OTP =====
app.post("/api/login-otp", async (req,res)=>{
  const {email,code}=req.body||{};
  if(!email||!code) return res.status(400).json({error:"email/code required"});

  const eHash=emailHash(email);
  const row=await get(
    `SELECT delegateId FROM delegates WHERE emailHash=?`,
    [eHash]
  );
  if(!row) return res.status(400).json({error:"no user"});

  const codeHash=crypto.createHash("sha256").update(code).digest("hex");

  const otp=await get(
    `SELECT * FROM otp_codes WHERE emailHash=? AND codeHash=? AND expiresAt>?`,
    [eHash,codeHash,Date.now()]
  );
  if(!otp) return res.status(400).json({error:"invalid"});

  await run(`DELETE FROM otp_codes WHERE id=?`,[otp.id]);

  const token=jwt.sign({delegateId:row.delegateId},JWT_SECRET,{expiresIn:"3d"});
  res.json({token,delegateId:row.delegateId});
});

// ===== health =====
app.get("/",(req,res)=>res.json({status:"ok"}));

app.listen(PORT,()=>console.log("Backend on",PORT));
