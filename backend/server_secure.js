// ===== CMC IRIA 2025 – PASSWORD + QR BACKEND (NO EMAIL) =====

const express = require("express");
const crypto = require("crypto");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json());
app.set("trust proxy", true);

// --- config ---
const PORT = process.env.PORT || 10000;
const JWT_SECRET   = process.env.JWT_SECRET   || "dev_jwt_secret_change_me";
const ENC_SECRET   = process.env.ENC_SECRET   || "dev_enc_secret_change_me";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";
const ADMIN_PASS   = process.env.ADMIN_PASS   || "cmcvsgc";

// ===== CORS – keep simple and permissive for Netlify/Render =====
app.use((req,res,next)=>{
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Credentials","true");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization,x-admin-pass");
  if(req.method==="OPTIONS") return res.status(200).end();
  next();
});

// ===== DB (NEW AUTH DB) =====
const db = new sqlite3.Database(path.join(__dirname, "secure_auth.db"));

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

// create tables
(async () => {
  await run(`
    CREATE TABLE IF NOT EXISTS delegates(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      emailHash TEXT UNIQUE,
      emailEncrypted TEXT,
      name TEXT,
      delegateId TEXT UNIQUE,
      passwordHash TEXT,
      isApproved INTEGER DEFAULT 1
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS visits(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      delegateId TEXT,
      stall INTEGER,
      ts INTEGER
    )
  `);
})();

// ===== helpers =====
function emailHash(email) {
  return crypto
    .createHash("sha256")
    .update(String(email).toLowerCase().trim())
    .digest("hex");
}

function encrypt(text) {
  const iv  = crypto.randomBytes(16);
  const key = crypto.createHash("sha256").update(ENC_SECRET).digest();
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let enc = cipher.update(String(text), "utf8", "base64");
  enc += cipher.final("base64");
  return iv.toString("base64") + ":" + enc;
}

// password hash with PBKDF2
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(String(password), salt, 100000, 32, "sha256")
    .toString("hex");
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  if (!stored) return false;
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const testHash = crypto
    .pbkdf2Sync(String(password), salt, 100000, 32, "sha256")
    .toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(testHash, "hex"));
}

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

// ===== health =====
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "cmc-iria-password-qr" });
});

// ===== REGISTER – email OR delegateId + password =====
app.post("/api/register", async (req, res) => {
  try {
    let { name, email, delegateId, password } = req.body || {};
    if (!password) return res.status(400).json({ error: "password required" });
    if (!email && !delegateId) {
      return res.status(400).json({ error: "email or delegateId required" });
    }

    email = email ? String(email).toLowerCase().trim() : "";
    delegateId = delegateId ? String(delegateId).trim() : "";

    const eHash = email ? emailHash(email) : null;

    if (email) {
      const existingByEmail = await get(
        `SELECT id FROM delegates WHERE emailHash=?`,
        [eHash]
      );
      if (existingByEmail) {
        return res.status(400).json({ error: "email already registered" });
      }
    }

    if (delegateId) {
      const existingById = await get(
        `SELECT id FROM delegates WHERE delegateId=?`,
        [delegateId]
      );
      if (existingById) {
        return res.status(400).json({ error: "delegateId already registered" });
      }
    }

    if (!delegateId) {
      delegateId = "D" + Math.floor(100000 + Math.random() * 900000);
    }

    const passHash = hashPassword(password);
    await run(
      `INSERT INTO delegates(emailHash,emailEncrypted,name,delegateId,passwordHash,isApproved)
       VALUES(?,?,?,?,?,1)`,
      [
        email ? eHash : null,
        email ? encrypt(email) : null,
        name || null,
        delegateId,
        passHash
      ]
    );

    res.json({
      ok: true,
      delegateId,
      message: "registered"
    });
  } catch (e) {
    console.error("register error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== LOGIN – email OR delegateId + password =====
app.post("/api/login", async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) {
      return res.status(400).json({ error: "identifier/password required" });
    }

    const idStr = String(identifier).trim();
    let user;

    if (idStr.includes("@")) {
      const eHash = emailHash(idStr);
      user = await get(
        `SELECT * FROM delegates WHERE emailHash=?`,
        [eHash]
      );
    } else {
      user = await get(
        `SELECT * FROM delegates WHERE delegateId=?`,
        [idStr]
      );
    }

    if (!user) return res.status(400).json({ error: "no such user" });
    if (!checkPassword(password, user.passwordHash)) {
      return res.status(400).json({ error: "invalid password" });
    }

    const token = jwt.sign(
      { id: user.id, delegateId: user.delegateId },
      JWT_SECRET,
      { expiresIn: "3d" }
    );

    res.json({
      token,
      delegateId: user.delegateId,
      name: user.name
    });
  } catch (e) {
    console.error("login error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== SIMPLE VISIT – manual (used by current frontend) =====
app.post("/api/visit", authMiddleware, async (req, res) => {
  try {
    const { stall } = req.body || {};
    const delegateId = req.user.delegateId;
    const stallNum = Number(stall);
    if (!stallNum || stallNum < 1) {
      return res.status(400).json({ error: "invalid stall" });
    }

    const existing = await get(
      `SELECT id FROM visits WHERE delegateId=? AND stall=?`,
      [delegateId, stallNum]
    );
    if (!existing) {
      await run(
        `INSERT INTO visits(delegateId,stall,ts) VALUES(?,?,?)`,
        [delegateId, stallNum, Date.now()]
      );
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("visit error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== SECURE QR VERIFY – uses TOKEN_SECRET & HMAC =====
// Expected body: { stall, token, exp }
// frontend/QR generator must compute the same HMAC:
/// token = HMAC_SHA256(TOKEN_SECRET, `${delegateId}|${stall}|${exp}`)
app.post("/api/verify", authMiddleware, async (req, res) => {
  try {
    const { stall, token, exp } = req.body || {};
    const delegateId = req.user.delegateId;
    const stallNum = Number(stall);
    const now = Date.now();

    if (!stallNum || !token || !exp) {
      return res.status(400).json({ error: "missing fields" });
    }
    if (Number(exp) < now) {
      return res.status(400).json({ error: "expired" });
    }

    const expected = crypto
      .createHmac("sha256", TOKEN_SECRET)
      .update(`${delegateId}|${stallNum}|${exp}`)
      .digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(token, "hex"))) {
      return res.status(400).json({ error: "invalid token" });
    }

    const existing = await get(
      `SELECT id FROM visits WHERE delegateId=? AND stall=?`,
      [delegateId, stallNum]
    );
    if (!existing) {
      await run(
        `INSERT INTO visits(delegateId,stall,ts) VALUES(?,?,?)`,
        [delegateId, stallNum, now]
      );
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("verify error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== GET VISITS =====
app.get("/api/visits", authMiddleware, async (req, res) => {
  try {
    const delegateId = req.user.delegateId;
    const rows = await all(
      `SELECT stall FROM visits WHERE delegateId=? ORDER BY stall ASC`,
      [delegateId]
    );
    res.json({ visits: rows.map(r => r.stall) });
  } catch (e) {
    console.error("visits error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== LEADERBOARD =====
app.get("/api/leaderboard", async (req, res) => {
  try {
    const rows = await all(`
      SELECT delegateId, COUNT(*) as cnt
      FROM visits
      GROUP BY delegateId
      ORDER BY cnt DESC
      LIMIT 50
    `);
    res.json({ top: rows });
  } catch (e) {
    console.error("leaderboard error:", e);
    res.status(500).json({ error: "server error" });
  }
});

// ===== ADMIN CLEANUP (optional) =====
app.post("/api/admin/cleanup", adminAuth, async (req, res) => {
  try {
    await run(`DELETE FROM visits`);
    await run(`DELETE FROM delegates`);
    res.json({ ok: true });
  } catch (e) {
    console.error("cleanup error:", e);
    res.status(500).json({ error: "server error" });
  }
});

app.listen(PORT, () => {
  console.log("Password+QR backend listening on", PORT);
});
