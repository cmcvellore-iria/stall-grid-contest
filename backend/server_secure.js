// ===== CMC IRIA 2025 – Secure Stall Backend (Brevo API version) =====

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json());

// important for Render / proxies (IP + rate-limit etc.)
app.set("trust proxy", true);

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret";
const ENC_SECRET = process.env.ENC_SECRET || "dev_enc_secret";
const ADMIN_PASS = process.env.ADMIN_PASS || "cmcvsgc";

// ======= FRONTEND ORIGINS – EDIT THIS TO MATCH YOUR NETLIFY URL =======
// Example: "https://cmcv-sgc-iria2025.netlify.app"
const allowedOrigins = [
  "https://cmcv-sgc-iria2025.netlify.app"
];

// ======= CORS =======
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization,x-admin-pass"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  next();
});

// ======= DB SETUP (SQLite) =======
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

// create tables (delegates, visits, otps, audit)
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

// ======= UTILS =======
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

async function logAction(req, action, details) {
  try {
    await run(
      `INSERT INTO audit_logs(ts,ip,action,details) VALUES(?,?,?,?)`,
      [Date.now(), req.ip || "", action, JSON.stringify(details || {})]
    );
  } catch (e) {}
}

// ======= Brevo HTTP API (no SMTP) =======
// You will set BREVO_API_KEY and BREVO_SENDER_EMAIL in Render env vars.
async function sendOtpEmail(toEmail, code) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  if (!apiKey || !senderEmail) {
    console.log("BREVO_API_KEY or BREVO_SENDER_EMAIL missing");
    return;
  }

  const payload = {
    sender: { name: "CMC IRIA 2025", email: senderEmail },
    to: [{ email: toEmail }],
    subject: "CMC IRIA 2025 Login OTP",
    textContent: `Your OTP code is: ${code}\nIt is valid for 5 minutes.`
  };

  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const text = await res.text();
    console.error("Brevo email error:", res.status, text);
    throw new Error("brevo_fail");
  }
}

// ======= AUTH HELPERS =======
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

function adminAuth(req, res, next) {
  if ((req.headers["x-admin-pass"] || "") !== ADMIN_PASS) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// ======= ROUTES =======

// health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "cmc-iria-secure-backend" });
});

// --- Request OTP ---
app.post("/api/request-otp", async (req, res) => {
  try {
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

    // send OTP via Brevo HTTP API
    await sendOtpEmail(email, code);

    await logAction(req, "OTP_REQUEST", { email });
    res.json({ ok: true });
  } catch (err) {
    console.error("request-otp error:", err.message || err);
    res.status(500).json({ error: "smtp_fail" });
  }
});

// --- Verify OTP & login ---
app.post("/api/login-otp", async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) {
    return res.status(400).json({ error: "email/code required" });
  }

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

  const token = jwt.sign(
    {
      id: delegate.id,
      delegateId: delegate.delegateId,
      emailHash: delegate.emailHash
    },
    JWT_SECRET,
    { expiresIn: "3d" }
  );

  await logAction(req, "OTP_SUCCESS", { delegateId: delegate.delegateId });
  res.json({
    token,
    delegateId: delegate.delegateId,
    name: delegate.name,
    isApproved: !!delegate.isApproved
  });
});

// --- Visits for a delegate (for later UI) ---
app.get("/api/visits/:delegateId", authMiddleware, async (req, res) => {
  const delegateId = req.params.delegateId;
  if (delegateId !== req.user.delegateId) {
    return res.status(403).json({ error: "forbidden" });
  }
  const rows = await all(
    `SELECT stall FROM visits WHERE delegateId=? ORDER BY stall ASC`,
    [delegateId]
  );
  res.json({ visits: rows.map((r) => r.stall) });
});

// --- Leaderboard basic (for TV page) ---
app.get("/api/leaderboard", async (req, res) => {
  const rows = await all(
    `SELECT delegateId,COUNT(*) as cnt
     FROM visits
     GROUP BY delegateId
     ORDER BY cnt DESC
     LIMIT 50`
  );
  const out = [];
  for (const r of rows) {
    const d = await get(
      `SELECT name FROM delegates WHERE delegateId=?`,
      [r.delegateId]
    );
    out.push({
      delegateId: r.delegateId,
      name: d && d.name,
      count: r.cnt
    });
  }
  res.json({ top: out });
});

// --- Admin: pending approval ---
app.get("/api/admin/pending", adminAuth, async (req, res) => {
  const rows = await all(
    `SELECT id,name,delegateId,emailEncrypted,isApproved
     FROM delegates
     WHERE isApproved=0`
  );
  res.json({ pending: rows });
});

// --- Admin: approve delegate ---
app.post("/api/admin/approve", adminAuth, async (req, res) => {
  const { delegateId } = req.body || {};
  if (!delegateId) return res.status(400).json({ error: "missing" });

  await run(
    `UPDATE delegates SET isApproved=1 WHERE delegateId=?`,
    [delegateId]
  );
  await logAction(req, "APPROVE", { delegateId });
  res.json({ ok: true });
});

// --- Admin: full cleanup (careful) ---
app.post("/api/admin/cleanup", adminAuth, async (req, res) => {
  await run(`DELETE FROM visits`);
  await run(`DELETE FROM delegates`);
  await run(`DELETE FROM otp_codes`);
  await run(`DELETE FROM audit_logs`);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("Backend listening on", PORT);
});
