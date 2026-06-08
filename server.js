const pg = require("pg");
pg.types.setTypeParser(1114, (str) => str ? str.replace(" ", "T") + "Z" : null);
pg.types.setTypeParser(1184, (str) => str ? str.replace(" ", "T") + "Z" : null);

require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require("joi")
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
  getMedicines,
  getMedicineById,
  addMedicine,
  updateMedicine,
  deleteMedicine,
  addTransaction,
  getTransactionsByCashierId,
  saveLicense,
  getLicense,
  saveSetting,
  getSetting,
  addInventoryMovement,
  deleteInventoryMovement,
  getInventoryMovementsByMedicineId,
  getInventoryMovements,
  getUserByUsername,
  getTransactions,
  deleteTransaction,
} = require("./lib/dbFunc");
const uuid = require("uuid");

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

// --------------------------
// Helper functions
// --------------------------

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
  return {
    key: `${productCode}-${timestamp}-${random}`,
    productCode: productCode,
  };
}

function canonicalStringify(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function signLicense(payload, productCode = "DWF") {
  const data = canonicalStringify(payload);
  const privateKey = getPrivateKey(productCode);
  if (!privateKey) {
    throw new Error("Private key not available for signing");
  }
  const privateKeyObject = crypto.createPrivateKey(privateKey);
  const signature = crypto.sign(null, Buffer.from(data), privateKeyObject);
  return signature.toString("base64");
}

function generateMarzPar() {
  return uuid.v4();
}

// User authentication
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  return hash;
}

const activateSchema = Joi.object({
  licenseKey: Joi.string().required(),
  machineId: Joi.string().required(),
});

// --------------------------
// Express API
// --------------------------
const app = express();

app.set("trust proxy", 1);
app.use(cors());

app.use(morgan("tiny"));
app.use(express.json());

// Users
app.post("/api/login", limiter, async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password, "login attempt");
  const user = await getUserByUsername(username);
  console.log(user, "users");

  if (!user) return res.status(401).json({ error: "Invalid credential" });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(user, process.env.JWT_SECRET || "secret", {
    expiresIn: "8h",
  });
  res.json({ token, user });
});

app.post("/api/login-staff", limiter, async (req, res) => {
  try {
    const { username, pin: password, pharmacyCode } = req.body;

    // 1. Get staff joined with pharmacy (verify pharmacyCode)
    const staffResult = await query(
      `
      SELECT s.*
      FROM staff s
      JOIN "pharmacyInfo" p ON s."pharmacyId" = p.id
      WHERE s."userName" = $1
        AND p."pharmacyCode" = $2
      `,
      [username, pharmacyCode],
    );

    const staff = staffResult.rows[0];


    if (!staff) {
      return res.status(401).json({ error: "Invalid credentials  xxxx" });
    }

    // 2. Validate PIN exists
    if (!password || !staff.pin) {
      return res.status(400).json({
        error: "Missing password or stored PIN",
      });
    }

    // 3. Verify PIN (bcrypt)
    const validPassword = bcrypt.compareSync(password, staff.pin);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // 4. Fetch pharmacy
    const pharmacyResult = await query(
      `
      SELECT *
      FROM "pharmacyInfo"
      WHERE id = $1
      `,
      [staff.pharmacyId],
    );

    const pharmacy = pharmacyResult.rows[0];

    // 5. Build JWT payload
    const staffPayload = {
      ...staff,
      username: staff.userName,
    };

    delete staffPayload.userName;

    const token = jwt.sign(staffPayload, process.env.JWT_SECRET || "secret", {
      expiresIn: "8h",
    });

    // 6. Response
    res.json({
      token,
      staff,
      pharmacy,
    });
  } catch (error) {
    console.error("Login staff error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/register", limiter, async (req, res) => {
  const { username, password, phone, email } = req.body;
  if (await getUserByUsername(username))
    return res.status(400).json({ error: "Username already exists" });
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    'INSERT INTO users (id, username, password, phone, email, "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [id, username, hashPassword(password), phone, email, now, now],
  );

  res.json({ id, username, phone, email, createdAt: now, updatedAt: now });
});

// 2️⃣ VERIFY EMAIL
app.get("/api/auth/verify", async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ error: "Verification token required" });
    }

    // Find user with valid verification token
    const result = await pool.query(
      `SELECT * FROM users WHERE "verificationToken" = $1`,
      [token],
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: "Invalid verification token" });
    }

    if (user.isverified) {
      return res.status(400).json({ error: "Account already verified" });
    }

    if (
      user.verificationexpires &&
      new Date(user.verificationexpires) < new Date()
    ) {
      return res.status(400).json({ error: "Verification token expired" });
    }

    // Verify user
    if (user.verificationtoken !== token) {
      return res.status(400).json({ error: "Invalid verification token" });
    }

    await pool.query(
      `UPDATE users SET "isVerified" = true, "verifiedAt" = now(), "verificationToken" = NULL, "verificationExpires" = NULL
       WHERE id = $1`,
      [user.id],
    );

    res.json({ message: "Email verified successfully. You can now login." });
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 3️⃣ RESEND VERIFICATION
app.post("/api/auth/resend-verification", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const result = await pool.query(
      `SELECT id, email, "isVerified" FROM users WHERE email = $1`,
      [email.toLowerCase()],
    );

    const user = result.rows[0];

    if (!user) {
      // Don't reveal if user exists
      return res.json({
        message: "If that email exists, a verification link has been sent",
      });
    }

    if (user.isverified) {
      return res.status(400).json({ error: "Account already verified" });
    }

    // Generate new verification token
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await pool.query(
      `UPDATE users SET "verificationToken" = $1, "verificationExpires" = $2 WHERE id = $3`,
      [verificationToken, verificationExpires, user.id],
    );

    // Send verification email
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

// 6️⃣ FORGOT PASSWORD
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Find user by email
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase(),
    ]);

    const user = result.rows[0];

    // Always return success to prevent email enumeration
    if (!user) {
      return res.json({
        message: "If that email exists, a password reset link has been sent",
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save reset token to database
    await pool.query(
      `UPDATE users SET "resetToken" = $1, "resetTokenExpires" = $2 WHERE id = $3`,
      [resetToken, resetTokenExpires, user.id],
    );

    // Send reset email
    const emailSent = await sendResetPasswordEmail(user.email, resetToken);

    if (!emailSent) {
      return res.status(500).json({ error: "Failed to send reset email" });
    }

    res.json({
      message: "If that email exists, a password reset link has been sent",
    });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 7️⃣ RESET PASSWORD
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res
        .status(400)
        .json({ error: "Email, token, and new password are required" });
    }

    // Validate password length
    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: "Password must be at least 6 characters" });
    }

    // Find user with valid reset token
    const result = await pool.query(
      `SELECT * FROM users WHERE email = $1 AND "resetToken" = $2 AND "resetTokenExpires" > NOW()`,
      [email.toLowerCase(), token],
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({
        error: "Invalid or expired reset token",
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update password and clear reset token
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

// Pharmacy registration
app.post("/api/pharmacy", authMiddleware, async (req, res) => {
  const { name, address, contactNumber } = req.body;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    'INSERT INTO "pharmacyInfo" (id, name, address, "contactNumber", "createdAt", "userId") VALUES ($1, $2, $3, $4, $5, $6)',
    [id, name, address, contactNumber, now, req.user.id],
  );
  res.json({ id, name, address, contactNumber, createdAt: now });
});

// Medicines
app.get("/api/medicines", authMiddleware, async (req, res) =>
  res.json(await getMedicines(req.query.pharmacyId || null)),
);
app.get("/api/medicines/:id", authMiddleware, async (req, res) => {
  const medicine = await getMedicineById(req.params.id);
  if (!medicine) return res.status(404).json({ error: "Not found" });
  res.json(medicine);
});
app.post("/api/medicines", authMiddleware, async (req, res) =>
  res.json(await addMedicine(req.body)),
);
app.put("/api/medicines/:id", authMiddleware, async (req, res) => {
  try {
    res.json(await updateMedicine(req.params.id, req.body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
app.delete("/api/medicines/:id", authMiddleware, async (req, res) => {
  await deleteMedicine(req.params.id);
  res.json({ success: true });
});

// Transactions
app.get("/api/transactions", authMiddleware, async (req, res) =>
  res.json(await getTransactions(req.query.pharmacyId || null)),
);
app.post("/api/transactions", authMiddleware, async (req, res) =>
  res.json(await addTransaction(req.body)),
);
app.delete("/api/transactions/:id", authMiddleware, async (req, res) => {
  await deleteTransaction(req.params.id);
  res.json({ success: true });
});

// cashier transactions
app.get("/api/transactions/cashier/:cashierId",  authMiddleware, async (req, res) =>
  res.json(await getTransactionsByCashierId(req.params.cashierId)),
);

// Licenses
app.get("/api/license", async (req, res) =>
  res.json((await getLicense()) || null),
);
app.post("/api/license", async (req, res) =>
  res.json(await saveLicense(req.body)),
);

// Settings
app.get("/api/settings/:key", async (req, res) =>
  res.json({ value: await getSetting(req.params.key) }),
);
app.post("/api/settings", async (req, res) => {
  await saveSetting(req.body.key, req.body.value);
  res.json({ success: true });
});

// Inventory Movements
app.get("/api/inventoryMovements", authMiddleware,  async (req, res) =>
  res.json(await getInventoryMovements()),
);
app.post("/api/inventoryMovements", authMiddleware, async (req, res) =>
  res.json(await addInventoryMovement(req.body)),
);
app.delete("/api/inventoryMovements/:id", authMiddleware, async (req, res) => {
  await deleteInventoryMovement(req.params.id);
  res.json({ success: true });
});
app.get("/api/inventoryMovements/:medicineId", async (req, res) =>
  res.json(await getInventoryMovementsByMedicineId(req.params.medicineId)),
);

// User pharmacy registration (kept for backward compatibility)
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

    const hashedPin = hashPassword("1234");

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
    // Add new pharmacy to existing admin staff
    const staff = await query(
      'SELECT "pharmacyIds" FROM staff WHERE id = $1',
      [req.user.id],
    );

    if (staff.rows.length > 0) {
      const pharmacyIds = staff.rows[0].pharmacyIds || "[]";
      
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

// Get pharmacy by user ID
app.get("/api/pharmacy", authMiddleware, async (req, res) => {
  const result = await query(
    'SELECT * FROM "pharmacyInfo" WHERE "userId" = $1 ORDER BY "createdAt" DESC',
    [req.user.id],
  );
  const pharmacy = result.rows[0];
  if (!pharmacy) return res.status(404).json({ error: "Not found" });

  res.json(pharmacy);
});

// Get all pharmacies
app.get("/api/pharmacies", authMiddleware, async (req, res) => {
  const result = await query('SELECT * FROM "pharmacyInfo"');

  res.json(result.rows);
});

// Get pharmacy by ID
app.get("/api/pharmacy/:id", authMiddleware, async (req, res) => {
  const result = await query('SELECT * FROM "pharmacyInfo" WHERE id = $1', [
    req.params.id,
  ]);
  const pharmacy = result.rows[0];
  if (!pharmacy) return res.status(404).json({ error: "Not found" });

  res.json(pharmacy);
});

// Update pharmacy by ID
app.put("/api/pharmacy", authMiddleware, async (req, res) => {
  const { name, address, contactNumber, phone, email, pharmacyCode, pharmacyId } = req.body;
  const now = new Date().toISOString();
  const fields = [];
  if (name) fields.push(`name = '${name}'`);
  if (address) fields.push(`address = '${address}'`);
  if (contactNumber) fields.push(`contactNumber = '${contactNumber}'`);
  if (phone) fields.push(`phone = '${phone}'`);
  if (email) fields.push(`email = '${email}'`);
  if (pharmacyCode) fields.push(`pharmacyCode = '${pharmacyCode}'`);
  fields.push(`"updatedAt" = '${now}'`);
  await query(
    `UPDATE "pharmacyInfo" SET ${fields.join(", ")} WHERE id = $1`,
    [pharmacyId],
  );
  res.json({ success: true });
});

// Staff registration
app.post("/api/staff", authMiddleware, async (req, res) => {
  const {
    userName,
    role,
    contactNumber,
    pin,
    pharmacyId,
  } = req.body;

  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const hashedPin = hashPassword(pin);

  const pharmacyIds = pharmacyId ? [pharmacyId] : [];

  await query(
    `INSERT INTO staff (
      id,
      "userName",
      role,
      "contactNumber",
      pin,
      "pharmacyIds",
      "createdAt",
      "updatedAt"
    )
    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
    [
      id,
      userName,
      role,
      contactNumber,
      hashedPin,
      JSON.stringify(pharmacyIds),
      now,
      now,
    ],
  );

  res.json({
    id,
    userName,
    role,
    contactNumber,
    pharmacyIds,
    createdAt: now,
    updatedAt: now,
  });
});

// Get staff by pharmacy ID
app.get("/api/staff/:pharmacyId", authMiddleware, async (req, res) => {
  const { rows } = await query(
    `
    SELECT *
    FROM staff
    WHERE "pharmacyIds" ? $1
    ORDER BY "createdAt" DESC
    `,
    [req.params.pharmacyId],
  );
  if (!rows || rows.length === 0)
    return res.status(404).json({ error: "Not found" });
  res.json(rows);
});

// Verify staff PIN
app.post("/api/staff/verify-pin", authMiddleware, async (req, res) => {
  const { staffId, pin, role } = req.body;
  if (role === "admin") {
    const user = await getUserByUsername(req.user.username);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!bcrypt.compareSync(pin, user.password))
      return res.status(401).json({ error: "Invalid PIN" });
    return res.json({ success: true });
  }

  const result = await query("SELECT * FROM staff WHERE id = $1", [staffId]);
  const staff = result.rows[0];
  if (!staff) return res.status(404).json({ error: "Staff not found" });

  if (staff.role !== role) {
    return res.status(404).json({ error: "Staff not found" });
  }

  if (!bcrypt.compareSync(pin, staff.pin))
    return res.status(401).json({ error: "Invalid PIN" });
  res.json({ success: true });
});

// Update staff
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

  const sql = `
    UPDATE staff
    SET ${fields.join(", ")}
    WHERE id = $${index}
  `;

  const result = await query(sql, values);

  res.json({ success: true });
});

// Delete staff
app.delete("/api/staff/:id", authMiddleware, async (req, res) => {
  const result = await query("DELETE FROM staff WHERE id = $1 RETURNING *", [
    req.params.id,
  ]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "Staff not found" });
  }
  res.json({ success: true });
});

// 3️⃣ GET EMAIL LIST (Protected route - admin only)
app.get("/api/users/emails", authMiddleware, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }

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

// 1️⃣ CREATE LICENSE
app.post("/api/licenses", limiter, authMiddleware, async (req, res) => {
  try {
    const { plan, maxMachines, expiresAt, phone, amount, productCode } =
      req.body;

    const reference = generateMarzPar();
    const { key: licenseKey, productCode: storedProductCode } =
      generateLicenseKey(productCode);

    await pool.query(
      `INSERT INTO licenses 
       (licenseKey, plan, maxMachines, expiresAt, machineIds, status, "paymentReference", amount, phone, "productCode", "userId")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        licenseKey,
        plan,
        maxMachines,
        expiresAt ? new Date(expiresAt) : null,
        JSON.stringify([]),
        "inactive",
        reference,
        amount,
        phone,
        storedProductCode,
        req.user.id, // Assuming the authenticated user's ID is available in req.user.id
      ],
    );

    await axios.post(
      `${process.env.MARZ_API_URL}/collect-money`,
      {
        amount: amount,
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

// MARZ PAYMENT CALLBACK
app.post("/marz/callback", async (req, res) => {
  res.status(200).json({ received: true });

  try {
    const { event_type, transaction } = req.body;

    if (event_type !== "collection.completed") return;
    if (transaction?.status !== "completed") return;

    const transactionReference = transaction.uuid;
    const paymentReference = transaction.reference;
    if (!transactionReference) return;

    // 1. Verify with Marz
    const verifyRes = await axios.get(
      `${process.env.MARZ_API_URL}/transactions/${transactionReference}`,
      {
        headers: {
          Authorization: `Basic ${process.env.MARZ_API_CREDENTIALS}`,
        },
      },
    );

    if (verifyRes.data?.transaction?.status !== "completed") return;

    // 2. Idempotency check
    const existing = await pool.query(
      `SELECT status FROM licenses WHERE "paymentReference" = $1`,
      [paymentReference],
    );

    if (existing.rows[0]?.status === "paid") return; // already processed

    // 3. Safe to update now ✅ (quoted column names)
    await pool.query(
      `UPDATE licenses
       SET status = 'paid', "paymentStatus" = 'completed'
       WHERE "paymentReference" = $1`,
      [paymentReference],
    );

    console.log("Payment verified and confirmed:", paymentReference);
  } catch (err) {
    console.error("Callback error:", err);
  }
});

// 2️⃣ ACTIVATE LICENSE
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

    // ✅ null check FIRST, before accessing any properties
    if (!license) return res.status(404).json({ error: "Invalid license key" });
    if (license.status === "revoked")
      return res.status(403).json({ error: "License revoked" });
    if (license.paymentStatus !== "completed")
      return res.status(402).json({ error: "Payment not completed" });

    let machineIds = license.machineids || [];

    if (!machineIds.includes(machineId)) {
      if (machineIds.length >= license.maxmachines) {
        return res.status(403).json({ error: "Max machines reached" });
      }
      machineIds = [...machineIds, machineId];
    }

    await pool.query(
      "UPDATE licenses SET machineIds = $1, status = $2 WHERE licenseKey = $3",
      [JSON.stringify(machineIds), "active", licenseKey],
    );

    const licensePayload = {
      licenseKey: license.licensekey,
      plan: license.plan,
      machineIds: machineId,
      maxMachines: license.maxmachines,
      expiresAt: license.expiresat,
    };

    // Extract productCode from licenseKey prefix (e.g., DENT-XXXXXX, PHARMA-XXXXXX)
    const licenseKeyPrefix = (license.licensekey || "DWF").split("-")[0];
    const productCode =
      licenseKeyPrefix === "DENT" || licenseKeyPrefix === "PHARMA"
        ? licenseKeyPrefix
        : license.productcode || "DWF";

    const signature = signLicense(licensePayload, productCode);

    res.json({ license: licensePayload, signature });
  } catch (err) {
    console.error("Activate error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 3️⃣ REVOKE LICENSE
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

// 4️⃣ GET USER LICENSES
app.get("/api/user/licenses", authMiddleware, async (req, res) => {
  try {
    const { id } = req.user;
    const result = await pool.query(`SELECT * FROM licenses WHERE "userId" = $1`, [
      id,
    ]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No licenses found" });
    }
    res.json(result.rows);
  } catch (err) {
    console.error("Get licenses error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===================== 404 =====================
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`✅ Server running on:`);
  console.log(`   Local:   http://localhost:${PORT}`);
});
