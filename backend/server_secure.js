// ========= Secure CMC IRIA 2025 Backend — Brevo SMTP (Refactored - Security Check Removed) =========

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
const helmet = require("helmet"); 
const rateLimit = require("express-rate-limit"); 
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();
app.use(helmet()); 
app.use(express.json());
app.set("trust proxy", 1); // Set to 1 because we are behind a single proxy

const PORT = process.env.PORT || 10000;
// These are now allowed to default to the insecure values again, as requested.
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc";
const ADMIN_PASS = process.env.ADMIN_PASS || "cmcvsgc";

// ===== allowed frontend origin ======
const allowedOrigins = [
    "https://cmcv-sgc-iria2025.netlify.app"
];

// ===== CORS and Rate Limiting =====
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

// Apply rate limiting to the OTP request endpoint
const otpLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: async (req, res) => {
        return res.status(429).json({ error: "too_many_requests", message: "Too many OTP requests from this IP. Please try again after 5 minutes." });
    }
});

// ===== DB =====
const db = new sqlite3.Database(path.join(__dirname, "secure_data.db"));

// Promisified DB helpers (unchanged)
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
function all(sql,p=[]) {
    return new Promise((resolve,reject)=>{
        db.all(sql,p,(e,r)=> e?reject(e):resolve(r));
    });
}

// create tables (unchanged structure)
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

// ===== helpers (unchanged) =====
function emailHash(e){
    return crypto.createHash("sha256").update(String(e).toLowerCase().trim()).digest("hex");
}

function encrypt(text){
    // Use a derived key for the cipher
    const key=crypto.createHash("sha256").update(ENC_SECRET).digest(); 
    const iv=crypto.randomBytes(16);
    const cipher=crypto.createCipheriv("aes-256-cbc",key,iv);
    let x=cipher.update(String(text),"utf8","base64");
    x+=cipher.final("base64");
    return iv.toString("base64")+":"+x;
}

// ===== SMTP transporter (BREVO) (unchanged) =====
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});


// =========================================================
// API ROUTES
// =========================================================

// ===== request OTP (BUG FIXED: No longer saves email as 'name', rate limiting added) =====
app.post("/api/request-otp", otpLimiter, async (req,res)=>{
    try{
        const {email, name=""}=req.body||{};
        if(!email) return res.status(400).json({error:"email required"});
        
        const normalizedEmail = String(email).toLowerCase().trim();
        const eHash=emailHash(normalizedEmail);

        let d=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
        
        // --- FIX: Correctly handle registration ---
        if(!d){
            const delegateId="D"+Math.floor(100000+Math.random()*900000);
            
            // BUG FIX: Correctly inserts encrypted email and optional name
            await run(
                `INSERT INTO delegates(emailHash, emailEncrypted, name, delegateId, isApproved)
                 VALUES(?,?,?,?,0)`,
                [eHash, encrypt(normalizedEmail), name || null, delegateId]
            );
            d=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
        }
        // ------------------------------------------

        // Clean up old OTPs for this user before creating a new one
        await run(`DELETE FROM otp_codes WHERE emailHash=?`, [eHash]);

        const code=String(Math.floor(100000+Math.random()*900000));
        const codeHash=crypto.createHash("sha256").update(code).digest("hex");
        
        // Insert new OTP
        await run(
            `INSERT INTO otp_codes(emailHash,codeHash,expiresAt) VALUES(?,?,?)`,
            [eHash,codeHash,Date.now()+5*60*1000]
        );

        // Send email
        await transporter.sendMail({
            from: `"CMC IRIA 2025" <${process.env.SMTP_USER}>`,
            to: normalizedEmail,
            subject: "CMC IRIA OTP",
            text: `Your One-Time Password (OTP) for CMC IRIA 2025 is: ${code}\n\nThis code expires in 5 minutes.`
        });

        res.json({ok:true});
    }catch(e){
        console.error("SMTP/DB FAIL:",e);
        // Log to audit table on failure
        await run(
            `INSERT INTO audit_logs(ts,ip,action,details) VALUES(?,?,?,?)`,
            [Date.now(), req.ip, "OTP_REQUEST_FAIL", e.message]
        );
        res.status(500).json({error:"smtp_fail"});
    }
});

// ===== verify OTP (unchanged logic) =====
app.post("/api/login-otp", async (req,res)=>{
    const {email,code}=req.body||{};
    if(!email||!code) return res.status(400).json({error:"email/code required"});

    const eHash=emailHash(email);
    const d=await get(`SELECT * FROM delegates WHERE emailHash=?`,[eHash]);
    if(!d) return res.status(400).json({error:"no user"});

    const codeHash=crypto.createHash("sha256").update(code).digest("hex");
    
    // Select the newest non-expired code
    const row=await get(
        `SELECT * FROM otp_codes WHERE emailHash=? AND codeHash=? AND expiresAt>? ORDER BY id DESC`,
        [eHash,codeHash,Date.now()]
    );
    if(!row) return res.status(400).json({error:"invalid"});

    await run(`DELETE FROM otp_codes WHERE id=?`,[row.id]); // OTP used, delete it

    const token=jwt.sign({
        id:d.id,
        delegateId:d.delegateId,
        emailHash:d.emailHash
    },JWT_SECRET,{expiresIn:"3d"});

    res.json({
        token,
        delegateId:d.delegateId,
        name:d.name,
        isApproved:!!d.isApproved
    });
});

// ===== visits (placeholder unchanged) =====
app.post("/api/verify", async (req,res)=>{
    return res.json({ok:true}); 
});

// leaderboard (unchanged)
app.get("/api/leaderboard", async(req,res)=>{
    const rows=await all(
        `SELECT delegateId,COUNT(*) as cnt
         FROM visits GROUP BY delegateId ORDER BY cnt DESC LIMIT 50`
    );
    const out=[];
    for(const r of rows){
        out.push({delegateId:r.delegateId,count:r.cnt}); 
    }
    res.json({top:out});
});

// admin (unchanged logic)
function adminAuth(req,res,next){
    if((req.headers["x-admin-pass"]||"")!==ADMIN_PASS)
        return res.status(403).json({error:"forbidden"});
    next();
}

app.post("/api/admin/approve",adminAuth,async(req,res)=>{
    const {delegateId}=req.body||{};
    if (!delegateId) return res.status(400).json({error:"delegateId required"});
    await run(`UPDATE delegates SET isApproved=1 WHERE delegateId=?`,[delegateId]);
    res.json({ok:true});
});

// health (unchanged)
app.get("/",(req,res)=>res.json({status:"ok"}));

app.listen(PORT,()=>console.log("Backend on",PORT));
