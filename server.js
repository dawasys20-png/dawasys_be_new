require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { runMigrations } = require("./migrations");

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

// Test connection and run migrations
pool.connect((err, client, release) => {
  if (err) {
    console.error("Failed to connect to PostgreSQL", err.stack);
    process.exit(1);
  }
  console.log("Connected to PostgreSQL");
  runMigrations(client);
  release();
});

// --------------------------
// Helper functions
// --------------------------

async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

// Medicines
async function getMedicines(pharmacyId) {
  if (pharmacyId) {
    const result = await query(
      "SELECT * FROM medicines WHERE isDeleted = 0 AND pharmacyId = $1 ORDER BY name",
      [pharmacyId],
    );
    return result.rows;
  }
  const result = await query("SELECT * FROM medicines WHERE isDeleted = 0 ORDER BY name");
  return result.rows;
}

async function getMedicineById(id) {
  const result = await query("SELECT * FROM medicines WHERE id = $1 AND isDeleted = 0", [id]);
  return result.rows[0] || null;
}

async function addMedicine(m) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await query(
    `
    INSERT INTO medicines (
      id, name, unitType, quantity, boxes, stripsPerBox, unitsPerStrip,
      bottles, mlPerBottle, price, lowStockThreshold, restockThreshold,
      expiryDate, supplier, batchNumber, unitBuyingPrice, isDeleted,
      wholesaleStripPrice, wholesaleBoxPrice, createdAt, updatedAt,
      buyingPrice, sellingPrice, pharmacyId
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
  `,
    [
      id, m.name, m.unitType, m.quantity, m.boxes || null, m.stripsPerBox || null,
      m.unitsPerStrip || null, m.bottles || null, m.mlPerBottle || null, m.price,
      m.lowStockThreshold, m.restockThreshold, m.expiryDate, m.supplier || null,
      m.batchNumber || null, m.unitBuyingPrice || 0, 0, m.wholesaleStripPrice || 0,
      m.wholesaleBoxPrice || 0, now, now, m.buyingPrice || 0, m.sellingPrice || 0,
      m.pharmacyId || null,
    ],
  );

  return { ...m, id, createdAt: now, updatedAt: now };
}

async function updateMedicine(id, updates) {
  const now = new Date().toISOString();
  const medicine = await getMedicineById(id);
  if (!medicine) throw new Error("Medicine not found");

  const updated = { ...medicine, ...updates, updatedAt: now };

  await query(
    `
    UPDATE medicines SET
      name=$1, unitType=$2, quantity=$3, boxes=$4, stripsPerBox=$5,
      unitsPerStrip=$6, bottles=$7, mlPerBottle=$8, price=$9,
      lowStockThreshold=$10, restockThreshold=$11, expiryDate=$12,
      supplier=$13, batchNumber=$14, unitBuyingPrice=$15,
      wholesaleStripPrice=$16, wholesaleBoxPrice=$17, updatedAt=$18,
      buyingPrice=$19, sellingPrice=$20, pharmacyId=$21
    WHERE id=$22
  `,
    [
      updated.name, updated.unitType, updated.quantity, updated.boxes || null,
      updated.stripsPerBox || null, updated.unitsPerStrip || null, updated.bottles || null,
      updated.mlPerBottle || null, updated.price, updated.lowStockThreshold,
      updated.restockThreshold, updated.expiryDate, updated.supplier || null,
      updated.batchNumber || null, updated.unitBuyingPrice || 0,
      updated.wholesaleStripPrice || 0, updated.wholesaleBoxPrice || 0, now,
      updated.buyingPrice || 0, updated.sellingPrice || 0, updated.pharmacyId || null, id,
    ],
  );

  return updated;
}

async function deleteMedicine(id) {
  await query("UPDATE medicines SET isDeleted=1 WHERE id=$1", [id]);
}

// Transactions
async function addTransaction(tx) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  // Check if all medicines have sufficient quantity before processing
  for (const item of tx.items) {
    const medicine = await getMedicineById(item.medicineId);
    if (!medicine) {
      throw new Error(`Medicine not found: ${item.medicineName}`);
    }
    if (medicine.quantity < item.stockQuantity) {
      throw new Error(
        `Insufficient quantity for ${item.medicineName}. Available: ${medicine.quantity}, Requested: ${item.stockQuantity}`,
      );
    }
  }

  // Insert transaction
  await query(
    `
    INSERT INTO transactions (
      id, totalAmount, paymentMethod, date, notes, createdAt,
      profit, transactionType, packType, pharmacyId, cashierId
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `,
    [
      id, tx.totalAmount, tx.paymentMethod, tx.date, tx.notes || null,
      now, tx.profit, tx.transactionType, tx.packType || null,
      tx.pharmacyId || null, tx.cashierId || null,
    ],
  );

  const itemStmt = `
    INSERT INTO transactionItems (
      id, transactionId, medicineId, medicineName, unitType, quantity,
      dosageInstructions, unitPrice, subtotal, stockQuantity, pharmacyId
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `;

  // Insert items and update stock in a transaction
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of tx.items) {
      const itemId = crypto.randomUUID();
      await client.query(itemStmt, [
        itemId, id, item.medicineId, item.medicineName, item.unitType,
        item.quantity, item.dosageInstructions || null, item.unitPrice,
        item.subtotal, item.stockQuantity, tx.pharmacyId || null,
      ]);

      // Reduce medicine stock
      const medicine = await getMedicineById(item.medicineId);
      if (medicine) {
        await query(
          "UPDATE medicines SET quantity = quantity - $1, updatedAt = $2 WHERE id = $3",
          [item.stockQuantity, now, item.medicineId],
        );
      }

      // Add inventory movement
      await addInventoryMovementRaw(client, {
        medicineId: item.medicineId,
        quantity: -item.stockQuantity,
        transactionId: id,
        transactionType: "create",
        unitType: item.unitType,
        movementType: "sale",
      });
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }

  return { ...tx, id, createdAt: now };
}

async function getTransactions(pharmacyId) {
  let transactions;
  if (pharmacyId) {
    const result = await query(
      "SELECT * FROM transactions WHERE pharmacyId = $1 ORDER BY date ASC",
      [pharmacyId],
    );
    transactions = result.rows;
  } else {
    const result = await query("SELECT * FROM transactions ORDER BY date ASC");
    transactions = result.rows;
  }

  // Fetch items for each transaction
  for (const tx of transactions) {
    const itemsResult = await query("SELECT * FROM transactionItems WHERE transactionId = $1", [tx.id]);
    tx.items = itemsResult.rows;
  }
  return transactions;
}

async function deleteTransaction(id) {
  const itemsResult = await query("SELECT * FROM transactionItems WHERE transactionId = $1", [id]);
  const items = itemsResult.rows;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of items) {
      // Restock the medicine
      await query(
        "UPDATE medicines SET quantity = quantity + $1, updatedAt = $2 WHERE id = $3",
        [item.stockQuantity, new Date().toISOString(), item.medicineId],
      );

      // Add inventory movement
      await addInventoryMovementRaw(client, {
        medicineId: item.medicineId,
        quantity: item.stockQuantity,
        transactionId: id,
        transactionType: "delete",
        unitType: item.unitType,
        movementType: "restock",
      });
    }
    await client.query("DELETE FROM transactions WHERE id = $1", [id]);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// Licenses
async function saveLicense(license) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await query(
    `
    INSERT INTO licenses (
      id, key, type, licenseType, status, activationDate,
      expiryDate, maxMachines, machineIds, signature, createdAt
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `,
    [
      id, license.key, license.type, license.licenseType, license.status,
      license.activationDate, license.expiryDate || null, license.maxMachines,
      license.machineIds, license.signature || null, now,
    ],
  );

  return { ...license, id, createdAt: now };
}

async function getLicense() {
  const result = await query("SELECT * FROM licenses ORDER BY createdAt DESC LIMIT 1");
  return result.rows[0] || null;
}

// Settings
async function saveSetting(key, value) {
  const now = new Date().toISOString();
  await query(
    "INSERT INTO settings (key, value, updatedAt) VALUES ($1, $2, $3) " +
    "ON CONFLICT (key) DO UPDATE SET value = $2, updatedAt = $3",
    [key, value, now],
  );
}

async function getSetting(key) {
  const result = await query("SELECT value FROM settings WHERE key = $1", [key]);
  return result.rows[0]?.value || null;
}

async function getInventoryMovements() {
  const result = await query("SELECT * FROM inventory_movements ORDER BY date DESC");
  return result.rows;
}

async function addInventoryMovementRaw(client, movement) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await client.query(
    "INSERT INTO inventory_movements (id, medicineId, quantity, unitType, movementType, createdAt) " +
    "VALUES ($1, $2, $3, $4, $5, $6)",
    [id, movement.medicineId, movement.quantity, movement.unitType, movement.movementType, now],
  );
  return { ...movement, id, createdAt: now };
}

async function addInventoryMovement(movement) {
  return await addInventoryMovementRaw(pool, movement);
}

async function deleteInventoryMovement(id) {
  await query("DELETE FROM inventory_movements WHERE id = $1", [id]);
}

async function getInventoryMovementsByMedicineId(medicineId) {
  const result = await query(
    "SELECT * FROM inventory_movements WHERE medicineId = $1 ORDER BY date DESC",
    [medicineId],
  );
  return result.rows;
}

// User authentication
function hashPassword(password) {
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  return hash;
}

async function getUserByUsername(username) {
  const result = await query("SELECT * FROM users WHERE username = $1", [username]);
  return result.rows[0] || null;
}

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET || "secret", (err, user) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    req.user = user;
    next();
  });
}

// --------------------------
// Express API
// --------------------------
const app = express();
app.use(express.json());
app.use(cors());

// Users
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(username, password, "login attempt");
  const user = await getUserByUsername(username);
  console.log(user, "users");

  if (!user) return res.status(401).json({ error: "Invalid credential" });
  if (!bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(user, process.env.JWT_SECRET || "secret", { expiresIn: "1h" });
  res.json({ token, user });
});

app.post("/api/register", async (req, res) => {
  const { username, password, phone } = req.body;
  if (await getUserByUsername(username))
    return res.status(400).json({ error: "Username already exists" });
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    "INSERT INTO users (id, username, password, phone, createdAt, updatedAt) VALUES ($1, $2, $3, $4, $5, $6)",
    [id, username, hashPassword(password), phone, now, now],
  );
  res.json({ id, username, phone, createdAt: now, updatedAt: now });
});

// Pharmacy registration
app.post("/api/pharmacy", authMiddleware, async (req, res) => {
  const { name, address, contactNumber } = req.body;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    "INSERT INTO pharmacyInfo (id, name, address, contactNumber, createdAt, userId) VALUES ($1, $2, $3, $4, $5, $6)",
    [id, name, address, contactNumber, now, req.user.id],
  );
  res.json({ id, name, address, contactNumber, createdAt: now });
});

// Medicines
app.get("/api/medicines", (req, res) =>
  res.json(await getMedicines(req.query.pharmacyId || null)),
);
app.get("/api/medicines/:id", async (req, res) => {
  const medicine = await getMedicineById(req.params.id);
  if (!medicine) return res.status(404).json({ error: "Not found" });
  res.json(medicine);
});
app.post("/api/medicines", async (req, res) => res.json(await addMedicine(req.body)));
app.put("/api/medicines/:id", async (req, res) => {
  try {
    res.json(await updateMedicine(req.params.id, req.body));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
app.delete("/api/medicines/:id", async (req, res) => {
  await deleteMedicine(req.params.id);
  res.json({ success: true });
});

// Transactions
app.get("/api/transactions", (req, res) =>
  res.json(await getTransactions(req.query.pharmacyId || null)),
);
app.post("/api/transactions", async (req, res) => res.json(await addTransaction(req.body)));
app.delete("/api/transactions/:id", async (req, res) => {
  await deleteTransaction(req.params.id);
  res.json({ success: true });
});

// Licenses
app.get("/api/license", async (req, res) => res.json(await getLicense() || null));
app.post("/api/license", async (req, res) => res.json(await saveLicense(req.body)));

// Settings
app.get("/api/settings/:key", async (req, res) =>
  res.json({ value: await getSetting(req.params.key) }),
);
app.post("/api/settings", async (req, res) => {
  await saveSetting(req.body.key, req.body.value);
  res.json({ success: true });
});

// Inventory Movements
app.get("/api/inventoryMovements", async (req, res) =>
  res.json(await getInventoryMovements()),
);
app.post("/api/inventoryMovements", async (req, res) =>
  res.json(await addInventoryMovement(req.body)),
);
app.delete("/api/inventoryMovements/:id", async (req, res) => {
  await deleteInventoryMovement(req.params.id);
  res.json({ success: true });
});
app.get("/api/inventoryMovements/:medicineId", async (req, res) =>
  res.json(await getInventoryMovementsByMedicineId(req.params.medicineId)),
);

// User pharmacy registration (kept for backward compatibility)
app.post("/api/register-pharmacy", authMiddleware, async (req, res) => {
  const { name, address, contactNumber, phone, email } = req.body;
  const userId = req.user.id;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await query(
    "INSERT INTO pharmacyInfo (id, name, address, contactNumber, phone, email, userId, createdAt, updatedAt) " +
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    [id, name, address, contactNumber, phone, email, userId, now, now],
  );
  res.json({
    id, name, address, contactNumber, phone, email, createdAt: now, updatedAt: now,
  });
});

// Get pharmacy by user ID
app.get("/api/pharmacy", authMiddleware, async (req, res) => {
  const result = await query(
    "SELECT * FROM pharmacyInfo WHERE userId = $1 ORDER BY createdAt DESC",
    [req.user.id],
  );
  const pharmacy = result.rows[0];
  if (!pharmacy) return res.status(404).json({ error: "Not found" });
  res.json(pharmacy);
});

// Get all pharmacies
app.get("/api/pharmacies", async (req, res) => {
  const result = await query("SELECT * FROM pharmacyInfo");
  res.json(result.rows);
});

// Staff registration
app.post("/api/staff", authMiddleware, async (req, res) => {
  const { userName, role, contactNumber, pin, pharmacyId } = req.body;
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  const hashedPin = hashPassword(pin);
  await query(
    "INSERT INTO staff (id, userName, role, contactNumber, pin, pharmacyId, createdAt, updatedAt) " +
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    [id, userName, role, contactNumber, hashedPin, pharmacyId, now, now],
  );
  res.json({
    id, userName, role, contactNumber, pin: hashedPin, pharmacyId, createdAt: now, updatedAt: now,
  });
});

// Get staff by pharmacy ID
app.get("/api/staff/:pharmacyId", authMiddleware, async (req, res) => {
  const result = await query(
    "SELECT * FROM staff WHERE pharmacyId = $1 ORDER BY createdAt DESC",
    [req.params.pharmacyId],
  );
  const staff = result.rows;
  if (!staff || staff.length === 0) return res.status(404).json({ error: "Not found" });
  res.json(staff);
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

// Delete staff
app.delete("/api/staff/:id", authMiddleware, async (req, res) => {
  const result = await query("DELETE FROM staff WHERE id = $1 RETURNING *", [req.params.id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: "Staff not found" });
  }
  res.json({ success: true });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on:`);
  console.log(`   Local:   http://localhost:${PORT}`);
});
