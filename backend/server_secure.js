// secure stall backend with Gmail OTP + proper CORS + trust proxy

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const path = require("path");
const nodemailer = require("nodemailer");
require("dotenv").config();

// EXPRESS
const app = express();
app.set("trust proxy", 1); // <<< IMPORTANT for rate-limit behind proxy (Render)

// CONFIG
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc_secret_change_me";
const ADMIN_PASS = process.env.ADMIN_PASS || "change_admin_pass";

// EMAIL CONFIG (GMAIL)
const emailUser = process.env.EMAIL_USER || "";
const emailPass = process.env.EMAIL_PASS || "";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // required on Render
  auth: { user: emailUser, pass: emailPass },
});

// DB
const db = new sqlite3.Database(path.join(__dirname, "secure_data.db"));

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// TABLES
(async () => {
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

// UTILS
function emailHash(email) {
  return crypto
    .createHash("sha256")
    .update(String(email).toLowerCase().trim())
    .digest("hex");
}

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const key = crypto.createHash("sha256").update(ENC_SECRET).digest();
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let enc = cipher.update(String(text), "utf8", "basebase");
  enc += cipher.final("base64");
  return iv.toString("base64") + ":" + enc;
}

async function logAction(req, action, details) {
  try {
    await run(
      `INSERT INTO audit_logs(ts,ip,action,details) VALUES(?,?,?,?)`,
      [Date.now(), req.ip || "", action, JSON.stringify(details || {})]
    );
  } catch {}
}

// MIDDLEWARE
app.use(express.json());

// CORS
const allowedOrigins = [
  "https://comforting-pudding-ccb24f.netlify.app",
  "https://cmcvellore-stallgridcontest-iria2025.netlify.app",
];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,x-admin-pass");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Vary","Origin");
  if (req.method==="OPTIONS"){return res.status(204).end();}
  next();
});

// RATE LIMIT
const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "too many requests" },
});
const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: "slow down" },
});

// ADMIN AUTH
function adminAuth(req, res, next) {
  if (req.headers["x-admin-pass"] !== ADMIN_PASS) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// JWT AUTH
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

// REQUEST OTP
app.post("/api/request-otp", otpRequestLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  const eHash = emailHash(email);
  let delegate = await get(`SELECT * FROM delegates WHERE emailHash=?`, [eHash]);

  if (!delegate) {
    const delegateId = "D" + Math.floor(100000 + Math.random() * 900000);
    await run(
      `INSERT INTO delegates(emailHash,emailEncrypted,name,delegateId,isApproved)
       VALUES (?,?,?,?,0)`,
      [eHash, encrypt(email), email, delegateId]
    );
    delegate = await get(`SELECT * FROM delegates WHERE emailHash=?`, [eHash]);
    await logAction(req, "SIGNUP_PENDING", { email, delegateId });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const codeHash = crypto.createHash("sha256").update(code).digest("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000;

  await run(
    `INSERT INTO otp_codes(emailHash,codeHash,expiresAt) VALUES(?,?,?)`,
    [eHash, codeHash, expiresAt]
  );

  try {
    if (!emailUser || !emailPass) {
      console.log("OTP (no email config)", email, code);
    } else {
      await transporter.sendMail({
        from: `"IRIA 2025" <${emailUser}>`,
        to: email,
        subject: "IRIA 2025 login code",
        text: `Your login code is: ${code}\nValid for 5 minutes.`,
      });
    }
  } catch (err) {
    console.error("Error sending OTP email:", err);
  }

  await logAction(req, "OTP_REQUEST", { email });
  res.json({ ok: true });
});

async function handleOtpLogin(req, res) {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: "email/code required" });

  const eHash = emailHash(email);
  const delegate = await get(`SELECT * FROM delegates WHERE emailHash=?`, [eHash]);
  if (!delegate) return res.status(400).json({ error: "no user" });

  const codeHash = crypto.createHash("sha256").update(code).digest("hex");
  const row = await get(
    `SELECT * FROM otp_codes WHERE emailHash=? AND codeHash=? AND expiresAt>? ORDER BY id DESC`,
    [eHash, codeHash, Date.now()]
  );
  if (!row) {
    await logAction(req, "OTP_FAIL", { email });
    return res.status(400).json({ error: "invalid" });
  }

  await run(`DELETE FROM otp_codes WHERE id=?`, [row.id]);

  const token = jwt.sign({
      id: delegate.id,
      delegateId: delegate.delegateId,
      emailHash: delegate.emailHash
  }, JWT_SECRET, { expiresIn: "3d" });

  await logAction(req, "OTP_SUCCESS", {
    delegateId: delegate.delegateId
  });

  res.json({
    token,
    delegateId: delegate.delegateId,
    name: delegate.name,
    isApproved: !!delegate.isApproved
  });
}

app.post("/api/login-otp", otpVerifyLimiter, handleOtpLogin);
app.post("/api/verify-otp", otpVerifyLimiter, handleOtpLogin);

// VERIFY SCAN
app.post("/api/verify", authMiddleware, async (req, res) => {
  const { stall, token, exp } = req.body || {};
  if (!stall || !token || !exp) return res.status(400).json({ error: "missing" });

  const delegateId = req.user.delegateId;
  const delegate = await get(`SELECT * FROM delegates WHERE delegateId=?`, [delegateId]);
  if (!delegate) return res.status(400).json({ error: "no delegate" });
  if (!delegate.isApproved) return res.status(403).json({ error: "pending" });

  const expected = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${delegateId}|${stall}|${exp}`)
    .digest("hex");

  if (expected !== token) return res.status(400).json({ error: "bad token" });
  if (Number(exp) < Date.now()) return res.status(400).json({ error: "expired" });

  const exists = await get(
    `SELECT 1 FROM visits WHERE delegateId=? AND stall=?`,
    [delegateId, stall]
  );
  if (!exists) {
    await run(
      `INSERT INTO visits(delegateId,stall,ts) VALUES (?,?,?)`,
      [delegateId, stall, Date.now()]
    );
    await logAction(req, "VISIT", { delegateId, stall });
  }

  res.json({ ok: true });
});

// VISITS
app.get("/api/visits/:delegateId", authMiddleware, async (req, res) => {
  const delegateId = req.params.delegateId;
  if (delegateId !== req.user.delegateId) return res.status(403).json({ error: "forbidden" });
  const rows = await all(
    `SELECT stall FROM visits WHERE delegateId=? ORDER BY stall ASC`,
    [delegateId]
  );
  res.json({ visits: rows.map(r => r.stall) });
});

// LEADERBOARD
app.get("/api/leaderboard", async (req, res) => {
  const rows = await all(`
    SELECT delegateId,COUNT(*) as cnt
    FROM visits
    GROUP BY delegateId
    ORDER BY cnt DESC LIMIT 50
  `);
  const out = [];
  for (const r of rows) {
    const d = await get(`SELECT name FROM delegates WHERE delegateId=?`, [r.delegateId]);
    out.push({ delegateId: r.delegateId, name: d && d.name, count: r.cnt });
  }
  res.json({ top: out });
});

// ADMIN
app.get("/api/admin/pending", adminAuth, async (req, res) => {
  const rows = await all(`SELECT id,name,delegateId,emailEncrypted,isApproved FROM delegates WHERE isApproved=0`);
  res.json({ pending: rows });
});

app.post("/api/admin/approve", adminAuth, async (req, res) => {
  const { delegateId } = req.body || {};
  if (!delegateId) return res.status(400).json({ error: "missing" });
  await run(`UPDATE delegates SET isApproved=1 WHERE delegateId=?`, [delegateId]);
  await logAction(req, "APPROVE", { delegateId });
  res.json({ ok: true });
});

app.post("/api/admin/cleanup", adminAuth, async (req, res) => {
  await run(`DELETE FROM visits`);
  await run(`DELETE FROM delegates`);
  await run(`DELETE FROM otp_codes`);
  await run(`DELETE FROM audit_logs`);
  res.json({ ok:true });
});

app.get("/", (req, res) => res.json({ status:"ok",service:"secure-stall-backend" }));

app.listen(PORT, () => {
  console.log("Secure backend listening on", PORT);
});
