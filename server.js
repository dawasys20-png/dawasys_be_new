const pg = require("pg");
pg.types.setTypeParser(1114, (str) =>
  str ? str.replace(" ", "T") + "Z" : null,
);
pg.types.setTypeParser(1184, (str) =>
  str ? str.replace(" ", "T") + "Z" : null,
);

require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi");
const morgan = require("morgan");
const { runMigrations } = require("./migrations");
const rateLimit = require("express-rate-limit");
const requireApiKey = require("./middleware/revokeMw");
const {
  sendResetPasswordEmail,
  sendVerificationEmail,
} = require("./middleware/email");
const fs = require("fs");
const authMiddleware = require("./middleware/auth");
const {
  query,
  getMedicineById,
  addMedicine,
  updateMedicine,
  addTransaction,
  getTransactionsByCashierId,
  saveLicense,
  getLicense,
  saveSetting,
  getSetting,
  getInventoryMovementsByMedicineId,
  getUserByUsername,
  getUserByEmail,
  rotateRefreshToken,
  issueTokenPair,
  hashToken,
} = require("./lib/dbFunc");
const uuid = require("uuid");
const axios = require("axios");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.method === "OPTIONS",
  message: { error: "Too many requests" },
});

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

// Test connection and run migrations
(async () => {
  let client;
  try {
    client = await pool.connect();
    console.log("Connected to PostgreSQL");
    await runMigrations(client);
    console.log("Migrations completed");
  } catch (err) {
    console.error("Failed to connect to PostgreSQL", err.stack);
    process.exit(1);
  } finally {
    if (client) client.release();
  }
})();

// ===================== CONFIG =====================
let PRIVATE_KEY;
let DAWASYS_PRIVATE_KEY;
let DENT_PRIVATE_KEY;

try {
  PRIVATE_KEY = process.env.PRIVATE_PRIVATE_KEY.replace(/\\n/g, "\n");
} catch (err) {
  console.log("Generated new private key");
}

try {
  DAWASYS_PRIVATE_KEY = process.env.DAWASYS_PRIVATE_KEY.replace(/\\n/g, "\n");
} catch (err) {
  console.log("DAWASYS private key not found");
}

try {
  DENT_PRIVATE_KEY = process.env.DENT_PRIVATE_KEY.replace(/\\n/g, "\n");
} catch (err) {
  console.log("Dent private key not found");
}

function getPrivateKey(productCode) {
  if (productCode?.toUpperCase().startsWith("DAWASYS")) {
    return DAWASYS_PRIVATE_KEY || PRIVATE_KEY;
  }
  if (productCode?.toUpperCase().startsWith("DENT")) {
    return DENT_PRIVATE_KEY || PRIVATE_KEY;
  }
  return PRIVATE_KEY;
}

function generateLicenseKey(productCode = "DWF") {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return { key: `${productCode}-${timestamp}-${random}`, productCode };
}

function canonicalStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function signLicense(payload, productCode = "DWF") {
  const data = canonicalStringify(payload);
  const privateKey = getPrivateKey(productCode);
  if (!privateKey) throw new Error("Private key not available for signing");
  const privateKeyObject = crypto.createPrivateKey(privateKey);
  const signature = crypto.sign(null, Buffer.from(data), privateKeyObject);
  return signature.toString("base64");
}

function generateMarzPar() {
  return uuid.v4();
}

function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
}

// Every /since/ query param defaults to the epoch so "no cursor yet" pulls
// everything. Sent as ISO from the client; Postgres compares it fine as text
// against a TIMESTAMP column via implicit cast.
function sinceOrEpoch(since) {
  return since || "1970-01-01T00:00:00.000Z";
}

async function recomputeRemoteMedicineQuantity(medicineId) {
  const now = new Date().toISOString();
  await query(
    `UPDATE medicines SET quantity = (
       SELECT COALESCE(SUM(quantity), 0) FROM "inventory_movements"
       WHERE "medicineId" = $1 AND "deletedAt" IS NULL
     ), "updatedAt" = $2 WHERE id = $1`,
    [medicineId, now],
  );
}

// Central authorization lookup: which pharmacies can this authenticated
// user actually see. Used to scope every syncable-entity GET route instead
// of trusting a client-supplied pharmacyId (or, when none is supplied,
// silently returning data for every pharmacy in the system).
async function getAccessiblePharmacyIds(userId) {
  const result = await query('SELECT "pharmacyIds" FROM staff WHERE id = $1', [
    userId,
  ]);
  return result.rows[0]?.pharmacyIds || [];
}

const activateSchema = Joi.object({
  licenseKey: Joi.string().required(),
  machineId: Joi.string().required(),
});

// Admin check middleware
function adminCheck(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// --------------------------
// Express API
// --------------------------
const app = express();

app.set("trust proxy", 1);
app.use(cors());
app.use(morgan("tiny"));
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.status(200).json({ message: "Available" });
});

// ===================== AUTH =====================
app.post("/api/login", limiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await getUserByUsername(username);

  if (!user) return res.status(401).json({ error: "Invalid credential" });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid credentials" });

  const { accessToken, refreshToken } = await issueTokenPair(
    false,
    user,
    user.id,
    "user",
  );
  res.json({ token: accessToken, refreshToken, user });
});

app.post("/api/login-staff", limiter, async (req, res) => {
  try {
    const { username, pin: password, pharmacyCode } = req.body;

    const staffResult = await query(
      `
      SELECT s.*
      FROM staff s
      JOIN "pharmacyInfo" p ON p.id = ANY(
        ARRAY(SELECT jsonb_array_elements_text(s."pharmacyIds")::uuid)
      )
      WHERE s."userName" = $1 AND p."pharmacyCode" = $2 AND s."deletedAt" IS NULL
      `,
      [username, pharmacyCode],
    );

    const staff = staffResult.rows[0];
    if (!staff) return res.status(401).json({ error: "Invalid credentials" });
    if (!password || !staff.pin)
      return res.status(400).json({ error: "Missing password or stored PIN" });
    if (!bcrypt.compareSync(password, staff.pin))
      return res.status(401).json({ error: "Invalid credentials" });

    const pharmacyResult = await query(
      `SELECT * FROM "pharmacyInfo" WHERE "pharmacyCode" = $1`,
      [pharmacyCode],
    );
    const pharmacy = pharmacyResult.rows[0];

    const staffPayload = { ...staff, username: staff.userName };
    delete staffPayload.userName;

    const { accessToken, refreshToken } = await issueTokenPair(
      staffPayload,
      staff.id,
      "staff",
    );
    res.json({ token: accessToken, refreshToken, staff, pharmacy });
  } catch (error) {
    console.error("Login staff error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/register", limiter, async (req, res) => {
  const { username, password, phone, email } = req.body;
  if (await getUserByUsername(username))
    return res.status(400).json({ error: "Username already exists" });
  if (await getUserByEmail(email))
    return res.status(400).json({ error: "Email already exists" });
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    'INSERT INTO users (id, username, password, phone, email, "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [id, username, hashPassword(password), phone, email, now, now],
  );
  res.json({ id, username, phone, email, createdAt: now, updatedAt: now });
});

app.get("/api/auth/verify", async (req, res) => {
  try {
    const { token } = req.query;
    if (!token)
      return res.status(400).json({ error: "Verification token required" });

    const result = await pool.query(
      `SELECT * FROM users WHERE "verificationToken" = $1`,
      [token],
    );
    const user = result.rows[0];
    if (!user)
      return res.status(400).json({ error: "Invalid verification token" });
    if (user.isverified)
      return res.status(400).json({ error: "Account already verified" });
    if (
      user.verificationexpires &&
      new Date(user.verificationexpires) < new Date()
    )
      return res.status(400).json({ error: "Verification token expired" });
    if (user.verificationtoken !== token)
      return res.status(400).json({ error: "Invalid verification token" });

    await pool.query(
      `UPDATE users SET "isVerified" = true, "verifiedAt" = now(), "verificationToken" = NULL, "verificationExpires" = NULL WHERE id = $1`,
      [user.id],
    );
    res.json({ message: "Email verified successfully. You can now login." });
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const result = await pool.query(
      `SELECT id, email, "isVerified" FROM users WHERE email = $1`,
      [email.toLowerCase()],
    );
    const user = result.rows[0];
    if (!user)
      return res.json({
        message: "If that email exists, a verification link has been sent",
      });
    if (user.isverified)
      return res.status(400).json({ error: "Account already verified" });

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await pool.query(
      `UPDATE users SET "verificationToken" = $1, "verificationExpires" = $2 WHERE id = $3`,
      [verificationToken, verificationExpires, user.id],
    );
    await sendVerificationEmail(email.toLowerCase(), verificationToken);
    res.json({
      message:
        "If that email exists and is unverified, a verification link has been sent",
    });
  } catch (err) {
    console.error("Resend verification error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase(),
    ]);
    const user = result.rows[0];
    if (!user)
      return res.json({
        message: "If that email exists, a password reset link has been sent",
      });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query(
      `UPDATE users SET "resetToken" = $1, "resetTokenExpires" = $2 WHERE id = $3`,
      [resetToken, resetTokenExpires, user.id],
    );

    const emailSent = await sendResetPasswordEmail(user.email, resetToken);
    if (!emailSent)
      return res.status(500).json({ error: "Failed to send reset email" });
    res.json({
      message: "If that email exists, a password reset link has been sent",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword)
      return res
        .status(400)
        .json({ error: "Email, token, and new password are required" });
    if (newPassword.length < 6)
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });

    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 AND "resetToken" = $2 AND "resetTokenExpires" > NOW()`,
      [email.toLowerCase(), token],
    );
    const user = result.rows[0];
    if (!user)
      return res.status(400).json({ error: "Invalid or expired reset token" });

    const hashedPassword = await bcrypt.hash(
      newPassword,
      await bcrypt.genSalt(10),
    );
    await pool.query(
      `UPDATE users SET password = $1, "passwordChangedAt" = NOW(), "resetToken" = NULL, "resetTokenExpires" = NULL WHERE id = $2`,
      [hashedPassword, user.id],
    );
    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/refresh-token", limiter, async (req, res) => {
  const Client = await pool.connect();
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: "Refresh token required" });

    await Client.query("BEGIN");

    const record = await rotateRefreshToken(Client, refreshToken);

    if (!record) {
      await Client.query("ROLLBACK");
      return res.status(401).json({
        error: "Invalid or expired refresh token",
        code: "INVALID_REFRESH_TOKEN",
      });
    }

    let payload;
    if (record.subjectType === "staff") {
      const { rows } = await Client.query(
        'SELECT * FROM staff WHERE id = $1 AND "deletedAt" IS NULL',
        [record.subjectId],
      );
      const staff = rows[0];
      if (!staff) {
        await Client.query("ROLLBACK");
        return res.status(401).json({ error: "Staff no longer exists" });
      }
      payload = { ...staff, username: staff.userName };
      delete payload.userName;
    } else {
      const { rows } = await Client.query("SELECT * FROM users WHERE id = $1", [
        record.subjectId,
      ]);
      payload = rows[0];
      if (!payload) {
        await Client.query("ROLLBACK");
        return res.status(401).json({ error: "User no longer exists" });
      }
    }

    const { accessToken, refreshToken: newRefreshToken } = await issueTokenPair(
      Client,
      payload,
      record.subjectId,
      record.subjectType,
    );
    await Client.query("COMMIT");
    res.json({ token: accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    await Client.query("ROLLBACK");
    console.error("Refresh token error:", err);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    Client.release();
  }
});

app.post("/api/auth/logout", async (req, res) => {
  const Client = await pool.connect();
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ error: "Refresh token required" });
    await Client.query("BEGIN");
    await Client.query(
      `UPDATE refresh_tokens SET "revokedAt" = now() WHERE "tokenHash" = $1`,
      [hashToken(refreshToken)],
    );
    await Client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await Client.query("ROLLBACK");
    console.error("Logout error:", err);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    Client.release();
  }
});

// ===================== MEDICINES =====================
// since-filtered: sync pulls call this with ?since=<iso> and expect an
// array (including recently-deleted rows, so other terminals learn about
// deletions too) rather than the "active only" list the plain UI call wants.
app.get("/api/medicines", authMiddleware, async (req, res) => {
  const { pharmacyId, since } = req.query;

  if (since !== undefined) {
    const params = [sinceOrEpoch(since)];
    let sql = `SELECT *, CASE WHEN "isDeleted" = 1 THEN "deletedAt" ELSE NULL END as "deletedAt" FROM medicines WHERE "updatedAt" > $1`;
    if (pharmacyId) {
      params.push(pharmacyId);
      sql += ` AND "pharmacyId" = $2`;
    }
    sql += ` ORDER BY "updatedAt" ASC`;
    const { rows } = await query(sql, params);
    return res.json(rows);
  }

  const params = [];
  let sql = `SELECT * FROM medicines WHERE "isDeleted" = 0`;
  if (pharmacyId) {
    params.push(pharmacyId);
    sql += ` AND "pharmacyId" = $1`;
  }
  sql += ` ORDER BY name`;
  const { rows } = await query(sql, params);
  res.json(rows);
});

app.get("/api/medicines/:id", authMiddleware, async (req, res) => {
  const medicine = await getMedicineById(req.params.id);
  if (!medicine) return res.status(404).json({ error: "Not found" });
  res.json(medicine);
});

app.post("/api/medicines", authMiddleware, async (req, res) => {
  // Bypasses dbFunc.addMedicine deliberately — that function generates
  // its own id via crypto.randomUUID(), discarding the id the sync
  // client already assigned locally. That mismatch is exactly what
  // produced "Medicine not found" on later PUTs: the client marks its
  // own id as SYNCED, but the row that actually exists remotely has a
  // different id nothing will ever look up again.
  const m = req.body;
  const id = m.id || crypto.randomUUID();
  const now = new Date().toISOString();

  try {
    const { rows } = await query(
      `INSERT INTO medicines (
        id, name, "unitType", quantity, boxes, "stripsPerBox", "unitsPerStrip",
        bottles, "mlPerBottle", price, "lowStockThreshold", "restockThreshold",
        "expiryDate", supplier, "batchNumber", "unitBuyingPrice", "isDeleted",
        "wholesaleStripPrice", "wholesaleBoxPrice", "createdAt", "updatedAt",
        "buyingPrice", "sellingPrice", "pharmacyId"
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
      ON CONFLICT (id) DO NOTHING
      RETURNING *`,
      [
        id,
        m.name,
        m.unitType,
        m.quantity || 0,
        m.boxes || null,
        m.stripsPerBox || null,
        m.unitsPerStrip || null,
        m.bottles || null,
        m.mlPerBottle || null,
        m.price,
        m.lowStockThreshold,
        m.restockThreshold,
        m.expiryDate,
        m.supplier || null,
        m.batchNumber || null,
        m.unitBuyingPrice || 0,
        0,
        m.wholesaleStripPrice || 0,
        m.wholesaleBoxPrice || 0,
        m.createdAt || now,
        m.updatedAt || now,
        m.buyingPrice || 0,
        m.sellingPrice || 0,
        m.pharmacyId || null,
      ],
    );
    res.json(rows[0] || { ...m, id });
  } catch (err) {
    if (err.code === "23503") {
      return res.status(409).json({
        error: "PARENT_NOT_SYNCED",
        message: `Referenced pharmacy (${m.pharmacyId}) does not exist on this server yet`,
      });
    }
    console.error("Add medicine error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/medicines/:id", authMiddleware, async (req, res) => {
  try {
    res.json(await updateMedicine(req.params.id, req.body));
  } catch (err) {
    if (err.code === "23503") {
      return res.status(409).json({
        error: "PARENT_NOT_SYNCED",
        message: `Referenced pharmacy (${req.body.pharmacyId}) does not exist on this server yet`,
      });
    }
    res.status(400).json({ error: err.message });
  }
});

app.delete("/api/medicines/:id", authMiddleware, async (req, res) => {
  const now = new Date().toISOString();
  await query(
    `UPDATE medicines SET "isDeleted" = 1, "deletedAt" = $1, "updatedAt" = $1 WHERE id = $2`,
    [now, req.params.id],
  );
  res.json({ success: true });
});

// ===================== TRANSACTIONS =====================
// Append-only: normal GET returns non-deleted only; since-filtered pull
// also returns recently-voided ones so other terminals can reconcile.
app.get("/api/transactions", authMiddleware, async (req, res) => {
  const { pharmacyId, since } = req.query;
  const params = [];
  let sql = `SELECT * FROM transactions WHERE 1=1`;

  if (since !== undefined) {
    params.push(sinceOrEpoch(since));
    sql += ` AND "updatedAt" > $${params.length}`;
  } else {
    sql += ` AND "deletedAt" IS NULL`;
  }
  if (pharmacyId) {
    params.push(pharmacyId);
    sql += ` AND "pharmacyId" = $${params.length}`;
  }
  sql += ` ORDER BY date DESC`;

  const { rows: transactions } = await query(sql, params);
  const withItems = await Promise.all(
    transactions.map(async (tx) => {
      const items = await query(
        `SELECT * FROM "transactionItems" WHERE "transactionId" = $1`,
        [tx.id],
      );
      return { ...tx, items: items.rows };
    }),
  );
  res.json(withItems);
});

app.post("/api/transactions", authMiddleware, async (req, res) => {
  const tx = req.body;
  const id = tx.id || crypto.randomUUID();
  const now = new Date().toISOString();

  try {
    const { rows } = await query(
      `INSERT INTO transactions (
        id, "totalAmount", "paymentMethod", date, notes, "createdAt", "updatedAt", profit,
        "transactionType", "packType", "pharmacyId", "cashierId", "billTotal"
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (id) DO NOTHING
      RETURNING *`,
      [
        id,
        tx.totalAmount,
        tx.paymentMethod,
        tx.date || now,
        tx.notes || null,
        tx.createdAt || now,
        tx.updatedAt || now,
        tx.profit,
        tx.transactionType,
        tx.packType || null,
        tx.pharmacyId || null,
        tx.cashierId || null,
        tx.billTotal ?? tx.totalAmount,
      ],
    );

    // Nothing inserted means this transaction id already exists (a retried
    // push after a lost response) — items are already there too, don't
    // insert them again.
    if (rows.length > 0) {
      for (const item of tx.items || []) {
        const itemId = item.id || crypto.randomUUID();
        await query(
          `INSERT INTO "transactionItems" (
            id, "transactionId", "medicineId", "medicineName", "unitType", quantity,
            "dosageInstructions", "unitPrice", subtotal, "stockQuantity", "pharmacyId", "updatedAt"
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
          ON CONFLICT (id) DO NOTHING`,
          [
            itemId,
            id,
            item.medicineId,
            item.medicineName,
            item.unitType,
            item.quantity,
            item.dosageInstructions || null,
            item.unitPrice,
            item.subtotal,
            item.stockQuantity,
            tx.pharmacyId || null,
            now,
          ],
        );
      }
    }

    res.json(rows[0] || { ...tx, id });
  } catch (err) {
    if (err.code === "23503") {
      return res.status(409).json({
        error: "PARENT_NOT_SYNCED",
        message: `Referenced pharmacy or cashier does not exist on this server yet`,
      });
    }
    console.error("Add transaction error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/transactions/:id", authMiddleware, async (req, res) => {
  const now = new Date().toISOString();
  await query(
    `UPDATE transactions SET "deletedAt" = $1, "updatedAt" = $1 WHERE id = $2`,
    [now, req.params.id],
  );
  await query(
    `UPDATE "transactionItems" SET "deletedAt" = $1, "updatedAt" = $1 WHERE "transactionId" = $2`,
    [now, req.params.id],
  );
  res.json({ success: true });
});

app.get(
  "/api/transactions/cashier/:cashierId",
  authMiddleware,
  async (req, res) =>
    res.json(await getTransactionsByCashierId(req.params.cashierId)),
);

// ===================== INVENTORY MOVEMENTS =====================
// New hyphenated routes matching the sync engine's entity map. Movements
// are append-only and now carry pharmacyId + updatedAt (see migration 028)
// so they can be scoped and since-filtered like everything else.
app.get("/api/inventory-movements", authMiddleware, async (req, res) => {
  const { pharmacyId, since } = req.query;
  const params = [sinceOrEpoch(since)];
  let sql = `SELECT * FROM "inventory_movements" WHERE "updatedAt" > $1`;
  if (pharmacyId) {
    params.push(pharmacyId);
    sql += ` AND "pharmacyId" = $${params.length}`;
  }
  sql += ` ORDER BY "updatedAt" ASC`;
  const { rows } = await query(sql, params);
  res.json(rows);
});

app.post("/api/inventory-movements", authMiddleware, async (req, res) => {
  const { id, medicineId, quantity, unitType, movementType, pharmacyId } =
    req.body;
  const now = new Date().toISOString();
  const movementId = id || crypto.randomUUID();
  await query(
    `INSERT INTO "inventory_movements" (id, "medicineId", quantity, "unitType", "movementType", "pharmacyId", "createdAt", "updatedAt")
     VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
     ON CONFLICT (id) DO NOTHING`,
    [
      movementId,
      medicineId,
      quantity,
      unitType,
      movementType,
      pharmacyId || null,
      now,
    ],
  );

  await recomputeRemoteMedicineQuantity(medicineId);

  res.json({
    id: movementId,
    medicineId,
    quantity,
    unitType,
    movementType,
    pharmacyId,
    createdAt: now,
    updatedAt: now,
  });
});

// Legacy camelCase routes kept for backward compatibility with older
// clients/web builds that haven't switched to the hyphenated path yet.
app.get("/api/inventoryMovements", authMiddleware, async (req, res) => {
  const { rows } = await query(
    `SELECT * FROM "inventory_movements" WHERE "deletedAt" IS NULL ORDER BY "createdAt" DESC`,
  );
  res.json(rows);
});
app.post("/api/inventoryMovements", authMiddleware, async (req, res) => {
  req.url = "/api/inventory-movements";
  app._router.handle(req, res);
});
app.delete("/api/inventoryMovements/:id", authMiddleware, async (req, res) => {
  const now = new Date().toISOString();
  await query(
    `UPDATE "inventory_movements" SET "deletedAt" = $1, "updatedAt" = $1 WHERE id = $2`,
    [now, req.params.id],
  );
  res.json({ success: true });
});
app.get("/api/inventoryMovements/:medicineId", async (req, res) =>
  res.json(await getInventoryMovementsByMedicineId(req.params.medicineId)),
);

// ===================== LICENSE =====================
app.get("/api/license", authMiddleware, async (req, res) =>
  res.json((await getLicense()) || null),
);
app.post("/api/license", authMiddleware, async (req, res) =>
  res.json(await saveLicense(req.body)),
);

// ===================== SETTINGS =====================
app.get("/api/settings/:key", async (req, res) =>
  res.json({ value: await getSetting(req.params.key) }),
);
app.post("/api/settings", async (req, res) => {
  await saveSetting(req.body.key, req.body.value);
  res.json({ success: true });
});

// ===================== PHARMACY REGISTRATION =====================
app.post("/api/register-pharmacy", authMiddleware, async (req, res) => {
  const { name, address, contactNumber, phone, email, pharmacyCode } = req.body;
  const userId = req.user.id;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await query(
    'INSERT INTO "pharmacyInfo" (id, name, address, "contactNumber", phone, email, "userId", "createdAt", "updatedAt", "pharmacyCode") ' +
      "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    [
      id,
      name,
      address,
      contactNumber,
      phone,
      email,
      userId,
      now,
      now,
      pharmacyCode,
    ],
  );

  const result = await query(
    'SELECT COUNT(*) FROM "pharmacyInfo" WHERE "userId" = $1',
    [userId],
  );
  const pharmacyCount = parseInt(result.rows[0].count, 10);
  let staffId = null;

  if (pharmacyCount === 1) {
    staffId = req.user.id;
    const hashedPin = hashPassword("3ZjMHZNQVBnOmA3wxfO3lFpf4");
    await query(
      'INSERT INTO staff (id, "userName", role, "contactNumber", pin, "pharmacyIds", "createdAt", "updatedAt") ' +
        "VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)",
      [
        req.user.id,
        req.user.username,
        "admin",
        contactNumber || null,
        hashedPin,
        JSON.stringify([id]),
        now,
        now,
      ],
    );
  } else {
    const staff = await query('SELECT "pharmacyIds" FROM staff WHERE id = $1', [
      req.user.id,
    ]);
    if (staff.rows.length > 0) {
      const pharmacyIds = staff.rows[0].pharmacyIds || [];
      if (!pharmacyIds.includes(id)) {
        pharmacyIds.push(id);
        await query(
          'UPDATE staff SET "pharmacyIds" = $1::jsonb, "updatedAt" = $2 WHERE id = $3',
          [JSON.stringify(pharmacyIds), now, req.user.id],
        );
      }
    }
  }

  res.json({
    data: {
      id,
      name,
      address,
      contactNumber,
      phone,
      email,
      pharmacyCode,
      createdAt: now,
      updatedAt: now,
    },
    staffId,
  });
});

// ===================== PHARMACY =====================
// Dual-purpose by design: with no `since`, keeps the legacy behavior
// (admin's own single pharmacy, by userId) that existing UI code calls.
// With `since`, returns the array of pharmacies this user's staff record
// has access to that changed after the cursor — what the sync engine needs.
app.get("/api/pharmacy", authMiddleware, async (req, res) => {
  const { since } = req.query;

  if (since !== undefined) {
    const staffResult = await query(
      'SELECT "pharmacyIds" FROM staff WHERE id = $1',
      [req.user.id],
    );
    const pharmacyIds = staffResult.rows[0]?.pharmacyIds || [];
    if (pharmacyIds.length === 0) return res.json([]);

    const { rows } = await query(
      `SELECT * FROM "pharmacyInfo" WHERE ("userId" = $1 OR id = ANY($2::uuid[])) AND "updatedAt" > $3 ORDER BY "updatedAt" ASC`,
      [req.user.id, pharmacyIds, sinceOrEpoch(since)],
    );
    return res.json(rows);
  }

  const result = await query(
    'SELECT * FROM "pharmacyInfo" WHERE "userId" = $1 ORDER BY "createdAt" DESC',
    [req.user.id],
  );
  const pharmacy = result.rows[0];
  if (!pharmacy) return res.status(404).json({ error: "Not found" });
  res.json(pharmacy);
});

app.get("/api/pharmacies", authMiddleware, async (req, res) => {
  const result = await query('SELECT * FROM "pharmacyInfo"');
  res.json(result.rows);
});

app.get("/api/me/pharmacies", authMiddleware, async (req, res) => {
  const staffResult = await query(
    'SELECT "pharmacyIds" FROM staff WHERE id = $1',
    [req.user.id],
  );
  const staffPharmacyIds = staffResult.rows[0]?.pharmacyIds || [];

  const pharmaciesResult = await query(
    `SELECT * FROM "pharmacyInfo"
     WHERE ("userId" = $1 OR id = ANY($2::uuid[]))
       AND "deletedAt" IS NULL`,
    [req.user.id, staffPharmacyIds],
  );

  res.json(pharmaciesResult.rows);
});

app.get("/api/pharmacy/:id", authMiddleware, async (req, res) => {
  const result = await query('SELECT * FROM "pharmacyInfo" WHERE id = $1', [
    req.params.id,
  ]);
  const pharmacy = result.rows[0];
  if (!pharmacy) return res.status(404).json({ error: "Not found" });
  res.json(pharmacy);
});

// Rewritten to use parameterized values — the previous version built the
// SQL string with template literals directly from request body fields
// (`fields.push(\`name = '${name}'\`)`), which is a SQL injection hole:
// a name like `', "isDeleted" = 1) --` would have been executed verbatim.
async function updatePharmacyFields(id, updates) {
  const { name, address, contactNumber, phone, email, pharmacyCode } = updates;
  const now = new Date().toISOString();
  const fields = [];
  const values = [];
  let index = 1;

  if (name !== undefined) {
    fields.push(`name = $${index++}`);
    values.push(name);
  }
  if (address !== undefined) {
    fields.push(`address = $${index++}`);
    values.push(address);
  }
  if (contactNumber !== undefined) {
    fields.push(`"contactNumber" = $${index++}`);
    values.push(contactNumber);
  }
  if (phone !== undefined) {
    fields.push(`phone = $${index++}`);
    values.push(phone);
  }
  if (email !== undefined) {
    fields.push(`email = $${index++}`);
    values.push(email);
  }
  if (pharmacyCode !== undefined) {
    fields.push(`"pharmacyCode" = $${index++}`);
    values.push(pharmacyCode);
  }
  fields.push(`"updatedAt" = $${index++}`);
  values.push(now);
  values.push(id);

  await query(
    `UPDATE "pharmacyInfo" SET ${fields.join(", ")} WHERE id = $${index}`,
    values,
  );
}

// Body-based — kept for the existing web-build caller (data-services.ts's
// updatePharmacy sends pharmacyId in the body, not the URL).
app.put("/api/pharmacy", authMiddleware, async (req, res) => {
  await updatePharmacyFields(req.body.pharmacyId, req.body);
  res.json({ success: true });
});

// Path-based — this is what the generic sync engine calls
// (ENTITY_ENDPOINTS.pharmacy + "/" + record.id) once a pharmacy has
// already been synced at least once (lastSyncedAt is set).
app.put("/api/pharmacy/:id", authMiddleware, async (req, res) => {
  await updatePharmacyFields(req.params.id, req.body);
  res.json({ success: true });
});

// The generic sync engine also needs to CREATE a pharmacy remotely the
// first time it syncs one that originated offline (lastSyncedAt is null).
// This is separate from /api/register-pharmacy, which additionally
// creates the first admin staff row — that side effect stays exclusive
// to the explicit registration flow, not the generic sync path. The
// client already generated the id locally, so this insert is id-idempotent.
app.post("/api/pharmacy", authMiddleware, async (req, res) => {
  const { id, name, address, phone, email, pharmacyCode } = req.body;
  const now = new Date().toISOString();
  const pharmacyId = id || crypto.randomUUID();

  await query(
    `INSERT INTO "pharmacyInfo" (id, name, address, phone, email, "userId", "createdAt", "updatedAt", "pharmacyCode")
     VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
     ON CONFLICT (id) DO NOTHING`,
    [
      pharmacyId,
      name,
      address,
      phone || "",
      email || "",
      req.user.id,
      now,
      pharmacyCode || null,
    ],
  );

  res.json({
    id: pharmacyId,
    name,
    address,
    phone,
    email,
    pharmacyCode,
    userId: req.user.id,
    createdAt: now,
    updatedAt: now,
  });
});

// ===================== STAFF =====================
function isBcryptHash(value) {
  return typeof value === "string" && /^\$2[aby]\$\d{2}\$.{53}$/.test(value);
}

app.post("/api/staff", authMiddleware, async (req, res) => {
  const { id, userName, role, contactNumber, pin, pharmacyId, pharmacyIds } =
    req.body;
  const staffId = id || crypto.randomUUID();
  const now = new Date().toISOString();
  const resolvedPharmacyIds = pharmacyIds || (pharmacyId ? [pharmacyId] : []);
  // The sync engine pushes a PIN that's already bcrypt-hashed locally
  // (see sync-repository.js's addStaff). The plain web registration flow
  // sends a raw PIN needing to be hashed here. Detect which case this is
  // instead of hashing unconditionally, or hashing an already-hashed PIN
  // would double-hash it and break that staff member's login forever.
  const storedPin = isBcryptHash(pin) ? pin : hashPassword(pin);

  await query(
    `INSERT INTO staff (id, "userName", role, "contactNumber", pin, "pharmacyIds", "createdAt", "updatedAt")
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
     ON CONFLICT (id) DO NOTHING`,
    [
      staffId,
      userName,
      role,
      contactNumber,
      storedPin,
      JSON.stringify(resolvedPharmacyIds),
      now,
      now,
    ],
  );
  res.json({
    id: staffId,
    userName,
    role,
    contactNumber,
    pharmacyIds: resolvedPharmacyIds,
    createdAt: now,
    updatedAt: now,
  });
});

// Flat, unscoped-by-path version for the generic sync engine
// (ENTITY_ENDPOINTS.staff = "/api/staff", so it calls this with no id
// segment). Scopes server-side to every pharmacy the authenticated
// user's staff record has access to, rather than requiring the client
// to already know which pharmacyId to ask about.
app.get("/api/staff", authMiddleware, async (req, res) => {
  const { since } = req.query;
  const ownStaffResult = await query(
    'SELECT "pharmacyIds" FROM staff WHERE id = $1',
    [req.user.id],
  );
  const pharmacyIds = ownStaffResult.rows[0]?.pharmacyIds || [];
  if (pharmacyIds.length === 0) return res.json([]);

  const { rows } = await query(
    `SELECT * FROM staff WHERE "pharmacyIds" ?| $1::text[] AND "updatedAt" > $2 ORDER BY "updatedAt" ASC`,
    [pharmacyIds, sinceOrEpoch(since)],
  );
  res.json(rows);
});

// since-filtered pull returns an array (possibly empty — NOT a 404, the
// old behavior broke every sync cycle where nothing had changed since
// last pull, since an empty array is a completely normal, expected result).
app.get("/api/staff/:pharmacyId", authMiddleware, async (req, res) => {
  const { since } = req.query;

  if (since !== undefined) {
    const { rows } = await query(
      `SELECT * FROM staff WHERE "pharmacyIds" ? $1 AND "updatedAt" > $2 ORDER BY "updatedAt" ASC`,
      [req.params.pharmacyId, sinceOrEpoch(since)],
    );
    return res.json(rows);
  }

  const { rows } = await query(
    `SELECT * FROM staff WHERE "pharmacyIds" ? $1 AND "deletedAt" IS NULL ORDER BY "createdAt" DESC`,
    [req.params.pharmacyId],
  );
  res.json(rows);
});

app.post("/api/staff/verify-pin", authMiddleware, async (req, res) => {
  const { staffId, pin, role } = req.body;
  if (role === "admin") {
    const user = await getUserByUsername(req.user.username);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!bcrypt.compareSync(pin, user.password))
      return res.status(401).json({ error: "Invalid PIN" });
    return res.json({ success: true });
  }

  const result = await query(
    'SELECT * FROM staff WHERE id = $1 AND "deletedAt" IS NULL',
    [staffId],
  );
  const staff = result.rows[0];
  if (!staff) return res.status(404).json({ error: "Staff not found" });
  if (staff.role !== role)
    return res.status(404).json({ error: "Staff not found" });
  if (!bcrypt.compareSync(pin, staff.pin))
    return res.status(401).json({ error: "Invalid PIN" });
  res.json({ success: true });
});

app.put("/api/staff/:id", authMiddleware, async (req, res) => {
  const { userName, role, contactNumber, pin } = req.body;
  const now = new Date().toISOString();
  const fields = [];
  const values = [];
  let index = 1;

  if (userName !== undefined) {
    fields.push(`"userName" = $${index++}`);
    values.push(userName);
  }
  if (role !== undefined) {
    fields.push(`role = $${index++}`);
    values.push(role);
  }
  if (contactNumber !== undefined) {
    fields.push(`"contactNumber" = $${index++}`);
    values.push(contactNumber);
  }
  if (pin !== undefined) {
    fields.push(`pin = $${index++}`);
    values.push(pin);
  }
  fields.push(`"updatedAt" = $${index++}`);
  values.push(now);
  values.push(req.params.id);

  await query(
    `UPDATE staff SET ${fields.join(", ")} WHERE id = $${index}`,
    values,
  );
  res.json({ success: true });
});

// Switched from a hard DELETE to a soft delete. A hard delete makes the
// row simply disappear — a since-based pull on another terminal has
// nothing to compare against and never learns the staff member was
// removed. Soft delete gives it an updatedAt/deletedAt to sync.
app.delete("/api/staff/:id", authMiddleware, async (req, res) => {
  const now = new Date().toISOString();
  const result = await query(
    `UPDATE staff SET "deletedAt" = $1, "updatedAt" = $1 WHERE id = $2 RETURNING id`,
    [now, req.params.id],
  );
  if (result.rows.length === 0)
    return res.status(404).json({ error: "Staff not found" });
  res.json({ success: true });
});

// ===================== USERS (admin) =====================
app.get("/api/users/emails", authMiddleware, adminCheck, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, role, "createdAt" FROM users ORDER BY "createdAt" DESC',
    );
    const emails = result.rows.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdat,
    }));
    res.json({ users: emails, count: emails.length });
  } catch (err) {
    console.error("Get emails error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/users", authMiddleware, adminCheck, async (req, res) => {
  try {
    // if (req.user.role !== "admin")
    //   return res.status(403).json({ error: "Admin access required" });
    const result = await pool.query(
      'SELECT id, email, username, role, phone, "createdAt" FROM users ORDER BY "createdAt" DESC',
    );
    const users = result.rows.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.username,
      role: user.role,
      phone: user.phone,
      createdAt: user.createdat,
    }));
    res.json({ users, count: users.length });
  } catch (err) {
    console.error("Get users error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===================== LICENSES (paid) =====================
app.post("/api/licenses", limiter, authMiddleware, async (req, res) => {
  try {
    const { plan, maxMachines, expiresAt, phone, amount, productCode } =
      req.body;
    const reference = generateMarzPar();
    const { key: licenseKey, productCode: storedProductCode } =
      generateLicenseKey(productCode);
    const id = uuid.v4();

    await pool.query(
      `INSERT INTO licenses
       (id, licenseKey, plan, maxMachines, expiresAt, machineIds, status, "paymentReference", amount, phone, "productCode", "userId")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        id,
        licenseKey,
        plan,
        maxMachines,
        expiresAt ? new Date(expiresAt) : null,
        [],
        "inactive",
        reference,
        amount,
        phone,
        storedProductCode,
        req.user.id,
      ],
    );

    await axios.post(
      `${process.env.MARZ_API_URL}/collect-money`,
      {
        amount,
        phone_number: `${phone}`,
        country: "UG",
        reference: `${reference}`,
        description: "Payment for license",
        callback_url: process.env.MARZ_API_CALLBACK_URL,
      },
      {
        headers: {
          Authorization: `Basic ${process.env.MARZ_API_CREDENTIALS}`,
          "Content-Type": "application/json",
        },
      },
    );

    res
      .status(202)
      .json({ message: "Payment initiated", reference, licenseKey, expiresAt });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/marz/callback", async (req, res) => {
  res.status(200).json({ received: true });
  try {
    const { event_type, transaction } = req.body;
    if (event_type !== "collection.completed") return;
    if (transaction?.status !== "completed") return;

    const transactionReference = transaction.uuid;
    const paymentReference = transaction.reference;
    if (!transactionReference) return;

    const verifyRes = await axios.get(
      `${process.env.MARZ_API_URL}/transactions/${transactionReference}`,
      {
        headers: { Authorization: `Basic ${process.env.MARZ_API_CREDENTIALS}` },
      },
    );
    if (verifyRes.data?.transaction?.status !== "completed") return;

    const existing = await pool.query(
      `SELECT status FROM licenses WHERE "paymentReference" = $1`,
      [paymentReference],
    );
    if (existing.rows[0]?.status === "paid") return;

    await pool.query(
      `UPDATE licenses SET status = 'paid', "paymentStatus" = 'completed' WHERE "paymentReference" = $1`,
      [paymentReference],
    );
    console.log("Payment verified and confirmed:", paymentReference);
  } catch (err) {
    console.error("Callback error:", err);
  }
});

app.post("/api/licenses/activate", limiter, async (req, res) => {
  const { error } = activateSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    const { licenseKey, machineId } = req.body;
    const result = await pool.query(
      "SELECT * FROM licenses WHERE licenseKey = $1",
      [licenseKey],
    );
    const license = result.rows[0];

    if (!license) return res.status(404).json({ error: "Invalid license key" });
    if (license.status === "revoked")
      return res.status(403).json({ error: "License revoked" });
    if (license.paymentStatus !== "completed")
      return res.status(402).json({ error: "Payment not completed" });

    let machineIds = license.machineids || [];
    if (!machineIds.includes(machineId)) {
      if (machineIds.length >= license.maxmachines)
        return res.status(403).json({ error: "Max machines reached" });
      machineIds = [...machineIds, machineId];
    }

    await pool.query(
      "UPDATE licenses SET machineIds = $1, status = $2 WHERE licenseKey = $3",
      [machineIds, "active", licenseKey],
    );

    const licensePayload = {
      licenseKey: license.licensekey,
      plan: license.plan,
      machineIds: machineId,
      maxMachines: license.maxmachines,
      expiresAt: license.expiresat,
    };
    const licenseKeyPrefix = (license.licensekey || "DWF").split("-")[0];
    const productCode =
      licenseKeyPrefix === "DENT" || licenseKeyPrefix === "DAWASYS"
        ? licenseKeyPrefix
        : license.productcode || "DWF";
    const signature = signLicense(licensePayload, productCode);

    res.json({ license: licensePayload, signature });
  } catch (err) {
    console.error("Activate error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/licenses/revoke", requireApiKey, async (req, res) => {
  try {
    const { licenseKey } = req.body;
    await pool.query("UPDATE licenses SET status = $1 WHERE licenseKey = $2", [
      "revoked",
      licenseKey,
    ]);
    res.json({ message: "License revoked" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/user/licenses", authMiddleware, async (req, res) => {
  try {
    const { id } = req.user;
    const result = await pool.query(
      `SELECT * FROM licenses WHERE "userId" = $1`,
      [id],
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: "No licenses found" });
    res.json(result.rows);
  } catch (err) {
    console.error("Get licenses error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===================== EXPENSES =====================
// Flat version for the generic sync engine, same reasoning as GET
// /api/staff above — ENTITY_ENDPOINTS.expense = "/api/expenses" with no
// id segment, scoped server-side to the user's accessible pharmacies.
app.get("/api/expenses", authMiddleware, async (req, res) => {
  const { since } = req.query;
  const ownStaffResult = await query(
    'SELECT "pharmacyIds" FROM staff WHERE id = $1',
    [req.user.id],
  );
  const pharmacyIds = ownStaffResult.rows[0]?.pharmacyIds || [];
  if (pharmacyIds.length === 0) return res.json([]);

  const { rows } = await query(
    `SELECT * FROM expenses WHERE "pharmacyId" = ANY($1::uuid[]) AND "updatedAt" > $2 ORDER BY "updatedAt" ASC`,
    [pharmacyIds, sinceOrEpoch(since)],
  );
  res.json(rows);
});

app.get("/api/expenses/:pharmacyId", authMiddleware, async (req, res) => {
  const { since } = req.query;

  if (since !== undefined) {
    const { rows } = await query(
      `SELECT * FROM expenses WHERE "pharmacyId" = $1 AND "updatedAt" > $2 ORDER BY "updatedAt" ASC`,
      [req.params.pharmacyId, sinceOrEpoch(since)],
    );
    return res.json(rows);
  }

  const { rows } = await query(
    `SELECT * FROM expenses WHERE "pharmacyId" = $1 AND "deletedAt" IS NULL ORDER BY "createdAt" DESC`,
    [req.params.pharmacyId],
  );
  res.json(rows);
});

app.post("/api/expenses", authMiddleware, async (req, res) => {
  const { id, description, amount, pharmacyId, notes, category, date } =
    req.body;
  const expenseId = id || crypto.randomUUID();
  const now = new Date().toISOString();
  try {
    await query(
      'INSERT INTO expenses (id, description, amount, notes, category, date, "pharmacyId", "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) ON CONFLICT (id) DO NOTHING',
      [expenseId, description, amount, notes, category, date, pharmacyId, now],
    );
    res.json({
      id: expenseId,
      description,
      amount,
      notes,
      category,
      date,
      pharmacyId,
      createdAt: now,
      updatedAt: now,
    });
  } catch (err) {
    if (err.code === "23503") {
      return res.status(409).json({
        error: "PARENT_NOT_SYNCED",
        message: `Referenced pharmacy (${pharmacyId}) does not exist on this server yet`,
      });
    }
    console.error("Add expense error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Switched to soft delete — same reasoning as staff above.
app.delete("/api/expenses/:id", authMiddleware, async (req, res) => {
  const now = new Date().toISOString();
  await query(
    `UPDATE expenses SET "deletedAt" = $1, "updatedAt" = $1 WHERE id = $2`,
    [now, req.params.id],
  );
  res.json({ success: true });
});

// ==================== demo ==================

app.get("/api/demo", async (req, res) => {
  try {
    const { rows } = await query(`SELECT * FROM demo_pharmacies`);
    res.json(rows);
  } catch (err) {
    console.error("Get demo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/demo-booking", async (req, res) => {
  const { name, phone, pharmacy, preferredDate, preferredTime, email } =
    req.body;

  const demoId = crypto.randomUUID();

  try {
    await query(
      `INSERT INTO demo_pharmacies (id, name, phone, pharmacy, "preferredDate", "preferredTime", email) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [demoId, name, phone, pharmacy, preferredDate, preferredTime, email],
    );
    res.json({ success: true });
  } catch (error) {
    console.error("Add demo error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/demo-booking/availability", async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT 
         TO_CHAR("preferredDate", 'YYYY-MM-DD') AS date, 
         TO_CHAR("preferredTime", 'FMHH12:MI AM') AS time 
       FROM demo_pharmacies`,
    );
    res.json({ booked: rows });
  } catch (err) {
    console.error("Get availability error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/demo-booking/:id", adminCheck, async (req, res) => {
  const contactId = req.params.id;
  const { status } = req.body;
  try {
    await query(`UPDATE demo_pharmacies SET status = $1 WHERE id = $2`, [
      status,
      contactId,
    ]);
  } catch (err) {
    console.error("Update demo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== contact ================
app.get("/api/contact", async (req, res) => {
  try {
    const { rows } = await query(`SELECT * FROM contact_form`);
    res.json(rows);
  } catch (err) {
    console.error("Get demo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/post-contact", async (req, res) => {
  const { name, email, phone, subject, message } = req.body;

  const contactId = crypto.randomUUID();

  try {
    await query(
      `INSERT INTO contact_form (id, name, phone, subject, email, message) VALUES ($1, $2, $3, $4, $5, $6)`,
      [contactId, name, phone, subject, email, message],
    );
    res.json({ success: true });
  } catch (error) {
    console.error("Add demo error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// update contact
app.put("/api/update-contact/:id", adminCheck, async (req, res) => {
  const contactId = req.params.id;
  const { status } = req.body;

  try {
    await query(`UPDATE contact_form SET status = $1 WHERE id = $2`, [
      status,
      contactId,
    ]);
    res.json({ success: true });
  } catch (error) {
    console.error("Update contact error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== trial ================
app.get("/api/trial", async (req, res) => {
  try {
    const { rows } = await query(`SELECT * FROM trial`);
    res.json(rows);
  } catch (err) {
    console.error("Get demo error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/post-trial", async (req, res) => {
  const { pharmacyName, ownerName, email, phone, location, message } = req.body;

  const trialId = crypto.randomUUID();

  try {
    await query(
      `INSERT INTO trial (id, "ownerName", phone, "pharmacyName", email, message, location) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [trialId, ownerName, phone, pharmacyName, email, message, location],
    );
    res.json({ success: true });
  } catch (error) {
    console.error("Add demo error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// update trial status
app.put("/api/trial/:id", adminCheck, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    await query(`UPDATE trial SET "status" = $1 WHERE id = $2`, [status, id]);
    res.json({ success: true });
  } catch (error) {
    console.error("Update trial error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===================== 404 =====================
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

const PORT = process.env.PORT || 5000;

// connect to database and start server
pool.connect().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Server running on:`);
    console.log(`   Local:   http://localhost:${PORT}`);
  });
});
