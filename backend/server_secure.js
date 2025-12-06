// backend/server_secure.js
// Secure OTP-only backend for Stall Visit Contest

const express = require("express");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const path = require("path");
require("dotenv").config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc_secret_change_me";
const ADMIN_PASS = process.env.ADMIN_PASS || "change_admin_pass";

const db = new Database(path.join(__dirname, "secure_data.db"));

// --- DB schema -------------------------------------------------
db.prepare(`
CREATE TABLE IF NOT EXISTS delegates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  emailHash TEXT UNIQUE,
  emailEncrypted TEXT,
  name TEXT,
  delegateId TEXT UNIQUE,
  isApproved INTEGER DEFAULT 0
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  delegateId TEXT,
  stall INTEGER,
  ts INTEGER
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS otp_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  emailHash TEXT,
  codeHash TEXT,
  expiresAt INTEGER
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER,
  ip TEXT,
  action TEXT,
  details TEXT
)`).run();

// --- Helpers ---------------------------------------------------
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
  let enc = cipher.update(String(text), "utf8", "base64");
  enc += cipher.final("base64");
  return iv.toString("base64") + ":" + enc;
}

function logAction(req, action, details) {
  try {
    db.prepare(
      "INSERT INTO audit_logs (ts, ip, action, details) VALUES (?,?,?,?)"
    ).run(Date.now(), req.ip || "", action, JSON.stringify(details || {}));
  } catch (e) {
    console.error("logAction error", e);
  }
}

// --- Express setup ---------------------------------------------
const app = express();
app.use(express.json());

// Simple CORS so frontend can call backend
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,x-admin-pass"
  );
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
});

// --- Rate limiters ---------------------------------------------
const otpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many OTP requests, please try later." },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { error: "Too many login attempts, please slow down." },
});

// --- Admin auth (simple header-based) --------------------------
function adminAuth(req, res, next) {
  const pass = req.headers["x-admin-pass"];
  if (!pass || pass !== ADMIN_PASS) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// --- JWT auth --------------------------------------------------
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const m = header.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// --- OTP REQUEST -----------------------------------------------
app.post("/api/request-otp", otpRequestLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: "email required" });

  const eHash = emailHash(email);
  let delegate = db.prepare("SELECT * FROM delegates WHERE emailHash=?").get(
    eHash
  );

  if (!delegate) {
    const delegateId = "D" + Math.floor(100000 + Math.random() * 900000);
    db.prepare(
      "INSERT INTO delegates (emailHash,emailEncrypted,name,delegateId,isApproved) VALUES (?,?,?,?,0)"
    ).run(eHash, encrypt(email), email, delegateId);
    delegate = db.prepare("SELECT * FROM delegates WHERE emailHash=?").get(
      eHash
    );
    logAction(req, "SIGNUP_PENDING", { email, delegateId });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const codeHash = crypto
    .createHash("sha256")
    .update(code)
    .digest("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min

  db.prepare(
    "INSERT INTO otp_codes (emailHash,codeHash,expiresAt) VALUES (?,?,?)"
  ).run(eHash, codeHash, expiresAt);

  logAction(req, "OTP_REQUEST", { email });
  console.log("OTP for", email, "=", code); // replace with email sending later

  res.json({ ok: true, message: "OTP generated and sent" });
});

// --- LOGIN WITH OTP --------------------------------------------
app.post("/api/login-otp", otpVerifyLimiter, (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code)
    return res.status(400).json({ error: "email and code required" });

  const eHash = emailHash(email);
  const delegate = db.prepare("SELECT * FROM delegates WHERE emailHash=?").get(
    eHash
  );
  if (!delegate) return res.status(400).json({ error: "no such user" });

  const codeHash = crypto
    .createHash("sha256")
    .update(code)
    .digest("hex");
  const now = Date.now();

  const row = db
    .prepare(
      "SELECT * FROM otp_codes WHERE emailHash=? AND codeHash=? AND expiresAt>? ORDER BY id DESC"
    )
    .get(eHash, codeHash, now);

  if (!row) {
    logAction(req, "LOGIN_OTP_FAIL", { email });
    return res.status(400).json({ error: "invalid or expired code" });
  }

  db.prepare("DELETE FROM otp_codes WHERE id=?").run(row.id);

  const token = jwt.sign(
    {
      id: delegate.id,
      delegateId: delegate.delegateId,
      emailHash: delegate.emailHash,
    },
    JWT_SECRET,
    { expiresIn: "3d" }
  );

  logAction(req, "LOGIN_OTP_SUCCESS", { delegateId: delegate.delegateId });

  res.json({
    token,
    delegateId: delegate.delegateId,
    name: delegate.name,
    isApproved: !!delegate.isApproved,
  });
});

// --- VERIFY QR + RECORD VISIT ----------------------------------
app.post("/api/verify", authMiddleware, (req, res) => {
  const { stall, token, exp } = req.body || {};
  if (!stall || !token || !exp)
    return res.status(400).json({ error: "missing parameters" });

  const delegateId = req.user.delegateId;
  const delegate = db.prepare("SELECT * FROM delegates WHERE delegateId=?").get(
    delegateId
  );
  if (!delegate) return res.status(400).json({ error: "no such delegate" });

  if (!delegate.isApproved)
    return res.status(403).json({ error: "account pending approval" });

  const expected = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(`${delegateId}|${stall}|${exp}`)
    .digest("hex");

  try {
    if (
      !crypto.timingSafeEqual(
        Buffer.from(expected, "hex"),
        Buffer.from(token, "hex")
      )
    ) {
      return res.status(400).json({ error: "invalid token" });
    }
  } catch (e) {
    return res.status(400).json({ error: "invalid token" });
  }

  if (Number(exp) < Date.now()) {
    return res.status(400).json({ error: "QR expired" });
  }

  const exists = db
    .prepare("SELECT 1 FROM visits WHERE delegateId=? AND stall=?")
    .get(delegateId, stall);
  if (!exists) {
    db.prepare(
      "INSERT INTO visits (delegateId,stall,ts) VALUES (?,?,?)"
    ).run(delegateId, stall, Date.now());
    logAction(req, "VISIT_RECORDED", { delegateId, stall });
  }

  res.json({ ok: true });
});

// --- GET VISITS FOR DELEGATE -----------------------------------
app.get("/api/visits/:delegateId", authMiddleware, (req, res) => {
  const delegateId = req.params.delegateId;
  if (delegateId !== req.user.delegateId)
    return res.status(403).json({ error: "forbidden" });

  const rows = db
    .prepare("SELECT stall FROM visits WHERE delegateId=? ORDER BY stall ASC")
    .all(delegateId);
  const stalls = rows.map((r) => r.stall);
  res.json({ visits: stalls });
});

// --- LEADERBOARD -----------------------------------------------
app.get("/api/leaderboard", (req, res) => {
  const rows = db
    .prepare(
      `
    SELECT delegateId, COUNT(*) as cnt
    FROM visits
    GROUP BY delegateId
    ORDER BY cnt DESC
    LIMIT 50
  `
    )
    .all();

  const out = rows.map((r) => {
    const d = db
      .prepare("SELECT name FROM delegates WHERE delegateId=?")
      .get(r.delegateId);
    return { delegateId: r.delegateId, name: d && d.name, count: r.cnt };
  });

  res.json({ top: out });
});

// --- ADMIN: pending delegates ----------------------------------
app.get("/api/admin/pending", adminAuth, (req, res) => {
  const rows = db
    .prepare(
      "SELECT id, name, delegateId, emailEncrypted, isApproved FROM delegates WHERE isApproved=0"
    )
    .all();
  res.json({ pending: rows });
});

// --- ADMIN: approve delegate -----------------------------------
app.post("/api/admin/approve", adminAuth, (req, res) => {
  const { delegateId } = req.body || {};
  if (!delegateId)
    return res.status(400).json({ error: "delegateId required" });

  db.prepare("UPDATE delegates SET isApproved=1 WHERE delegateId=?").run(
    delegateId
  );
  logAction(req, "ADMIN_APPROVE", { delegateId });
  res.json({ ok: true });
});

// --- ADMIN: cleanup after conference ---------------------------
app.post("/api/admin/cleanup", adminAuth, (req, res) => {
  db.prepare("DELETE FROM visits").run();
  db.prepare("DELETE FROM delegates").run();
  db.prepare("DELETE FROM otp_codes").run();
  db.prepare("DELETE FROM audit_logs").run();
  res.json({ ok: true });
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "stall-visit-backend-secure" });
});

// Start
app.listen(PORT, () => {
  console.log("Secure backend listening on", PORT);
});
