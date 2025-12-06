// backend/gen_qrs.js
// Generate QR codes: TOKEN_SECRET=secret node gen_qrs.js delegates.csv 50 outdir
const fs = require("fs");
const QRCode = require("qrcode");
const crypto = require("crypto");
require("dotenv").config();

const TOKEN_SECRET = process.env.TOKEN_SECRET || "dev_token_secret_change_me";

const [,, delegatesCsv, totalStallsArg, outDir] = process.argv;
if (!delegatesCsv || !totalStallsArg || !outDir) {
  console.log("Usage: TOKEN_SECRET=secret node gen_qrs.js delegates.csv 50 ./qr_output");
  process.exit(1);
}
const totalStalls = Number(totalStallsArg);

const delegates = fs
  .readFileSync(delegatesCsv, "utf8")
  .trim()
  .split(/\r?\n/)
  .map((line) => {
    const [email, name, delegateId] = line.split(",");
    return { email, name, delegateId };
  });

if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

(async () => {
  for (const del of delegates) {
    if (!del.delegateId) continue;
    console.log("Generating for", del.delegateId, del.name);
    for (let s = 1; s <= totalStalls; s++) {
      const exp = Date.now() + 10 * 60 * 1000; // 10 min
      const sig = crypto
        .createHmac("sha256", TOKEN_SECRET)
        .update(`${del.delegateId}|${s}|${exp}`)
        .digest("hex");
      const payload = `stall=${s}&delegate=${del.delegateId}&exp=${exp}&token=${sig}`;
      const fname = `${outDir}/${del.delegateId}_stall${s}.png`;
      await QRCode.toFile(fname, payload);
    }
  }
  console.log("All QR codes generated.");
})();
