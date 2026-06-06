const pg = require("pg");
pg.types.setTypeParser(1114, (str) => str ? str.replace(" ", "T") + "Z" : null); // TIMESTAMP
pg.types.setTypeParser(1184, (str) => str ? str.replace(" ", "T") + "Z" : null); // TIMESTAMPTZ

require("dotenv").config();
const { Pool } = require("pg");
const crypto = require("crypto");
const { get } = require("http");

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});


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
      'SELECT * FROM medicines WHERE "isDeleted" = 0 AND "pharmacyId" = $1 ORDER BY name',
      [pharmacyId],
    );
    return result.rows;
  }
  const result = await query(
    'SELECT * FROM medicines WHERE "isDeleted" = 0 ORDER BY name',
  );
  return result.rows;
}

async function getMedicineById(id) {
  const result = await query(
    'SELECT * FROM medicines WHERE id = $1 AND "isDeleted" = 0',
    [id],
  );
  return result.rows[0] || null;
}

async function addMedicine(m) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  // Validate required expiryDate
  if (!m.expiryDate || m.expiryDate.trim() === "") {
    throw new Error("expiryDate is required");
  }

  await query(
    `
    INSERT INTO medicines (
      id, name, "unitType", quantity, boxes, "stripsPerBox", "unitsPerStrip",
      bottles, "mlPerBottle", price, "lowStockThreshold", "restockThreshold",
      "expiryDate", supplier, "batchNumber", "unitBuyingPrice", "isDeleted",
      "wholesaleStripPrice", "wholesaleBoxPrice", "createdAt", "updatedAt",
      "buyingPrice", "sellingPrice", "pharmacyId"
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
  `,
    [
      id,
      m.name,
      m.unitType,
      m.quantity,
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
      now,
      now,
      m.buyingPrice || 0,
      m.sellingPrice || 0,
      m.pharmacyId || null,
    ],
  );

  return { ...m, id, createdAt: now, updatedAt: now };
}

async function updateMedicine(id, updates) {
  const now = new Date().toISOString();
  const medicine = await getMedicineById(id);
  if (!medicine) throw new Error("Medicine not found");

  // Prevent updating expiryDate to empty string
  if (
    updates.expiryDate !== undefined &&
    (!updates.expiryDate || updates.expiryDate.trim() === "")
  ) {
    throw new Error("expiryDate cannot be empty");
  }

  const updated = { ...medicine, ...updates, updatedAt: now };

  await query(
    `
    UPDATE medicines SET
      name=$1, "unitType"=$2, quantity=$3, boxes=$4, "stripsPerBox"=$5,
      "unitsPerStrip"=$6, bottles=$7, "mlPerBottle"=$8, price=$9,
      "lowStockThreshold"=$10, "restockThreshold"=$11, "expiryDate"=$12,
      supplier=$13, "batchNumber"=$14, "unitBuyingPrice"=$15,
      "wholesaleStripPrice"=$16, "wholesaleBoxPrice"=$17, "updatedAt"=$18,
      "buyingPrice"=$19, "sellingPrice"=$20, "pharmacyId"=$21
    WHERE id=$22
  `,
    [
      updated.name,
      updated.unitType,
      updated.quantity,
      updated.boxes || null,
      updated.stripsPerBox || null,
      updated.unitsPerStrip || null,
      updated.bottles || null,
      updated.mlPerBottle || null,
      updated.price,
      updated.lowStockThreshold,
      updated.restockThreshold,
      updated.expiryDate,
      updated.supplier || null,
      updated.batchNumber || null,
      updated.unitBuyingPrice || 0,
      updated.wholesaleStripPrice || 0,
      updated.wholesaleBoxPrice || 0,
      now,
      updated.buyingPrice || 0,
      updated.sellingPrice || 0,
      updated.pharmacyId || null,
      id,
    ],
  );

  return updated;
}

async function deleteMedicine(id) {
  await query('UPDATE medicines SET "isDeleted"=1 WHERE id=$1', [id]);
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
      id, "totalAmount", "paymentMethod", date, notes, "createdAt",
      profit, "transactionType", "packType", "pharmacyId", "cashierId", "billTotal"
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
  `,
    [
      id,
      tx.totalAmount,
      tx.paymentMethod,
      tx.date,
      tx.notes || null,
      now,
      tx.profit,
      tx.transactionType,
      tx.packType || null,
      tx.pharmacyId || null,
      tx.cashierId || null,
      tx.billTotal || null,
    ],
  );

  const itemStmt = `
    INSERT INTO "transactionItems" (
      id, "transactionId", "medicineId", "medicineName", "unitType", quantity,
      "dosageInstructions", "unitPrice", "subtotal", "stockQuantity", "pharmacyId"
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `;

  // Insert items and update stock in a transaction
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of tx.items) {
        if (!item.medicineId) {
        throw new Error(`Missing medicineId for item: ${item.medicineName}`);
      }
      const itemId = crypto.randomUUID();
      await client.query(itemStmt, [
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
      ]);

      // Reduce medicine stock
      const medicine = await getMedicineById(item.medicineId);
      if (medicine) {
        await query(
          'UPDATE medicines SET quantity = quantity - $1, "updatedAt" = $2 WHERE id = $3',
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
      'SELECT * FROM transactions WHERE "pharmacyId" = $1 ORDER BY date ASC',
      [pharmacyId],
    );
    transactions = result.rows;
  } else {
    const result = await query("SELECT * FROM transactions ORDER BY date ASC");
    transactions = result.rows;
  }

  // Fetch items for each transaction
  for (const tx of transactions) {
    const itemsResult = await query(
      'SELECT * FROM "transactionItems" WHERE "transactionId" = $1',
      [tx.id],
    );
    tx.items = itemsResult.rows;
  }
  return transactions;
}

async function deleteTransaction(id) {
  const itemsResult = await query(
    'SELECT * FROM "transactionItems" WHERE "transactionId" = $1',
    [id],
  );
  const items = itemsResult.rows;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of items) {
      // Restock the medicine
      await query(
        'UPDATE medicines SET quantity = quantity + $1, "updatedAt" = $2 WHERE id = $3',
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

async function getTransactionsByCashierId(cashierId) {
  const result = await query(
    'SELECT * FROM transactions WHERE "cashierId" = $1 ORDER BY date ASC',
    [cashierId],
  );
  const transactions = result.rows;

  // Fetch items for each transaction
  for (const tx of transactions) {
    const itemsResult = await query(
      'SELECT * FROM "transactionItems" WHERE "transactionId" = $1',
      [tx.id],
    );
    tx.items = itemsResult.rows;
  }
  return transactions;
}

async function getTransactionById(id) {
  const result = await query(
    'SELECT * FROM transactions WHERE id = $1 ORDER BY date ASC',
    [id],
  );
  const transaction = result.rows[0];
  if (!transaction) return null;

  const itemsResult = await query(
    'SELECT * FROM "transactionItems" WHERE "transactionId" = $1',
    [id],
  );
  transaction.items = itemsResult.rows;
  return transaction;
}

// Licenses
async function saveLicense(license) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  await query(
    `
    INSERT INTO licenses (
      id, key, type, "licenseType", status, "activationDate",
      "expiryDate", "maxMachines", "machineIds", signature, "createdAt"
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
  `,
    [
      id,
      license.key,
      license.type,
      license.licenseType,
      license.status,
      license.activationDate,
      license.expiryDate || null,
      license.maxMachines,
      license.machineIds,
      license.signature || null,
      now,
    ],
  );

  return { ...license, id, createdAt: now };
}

async function getLicense() {
  const result = await query(
    'SELECT * FROM licenses ORDER BY "createdAt" DESC LIMIT 1',
  );
  return result.rows[0] || null;
}

// Settings
async function saveSetting(key, value) {
  const now = new Date().toISOString();
  await query(
    'INSERT INTO settings (key, value, "updatedAt") VALUES ($1, $2, $3) ' +
      'ON CONFLICT (key) DO UPDATE SET value = $2, "updatedAt" = $3',
    [key, value, now],
  );
}

async function getSetting(key) {
  const result = await query("SELECT value FROM settings WHERE key = $1", [
    key,
  ]);
  return result.rows[0]?.value || null;
}

async function getInventoryMovements() {
  const result = await query(
    'SELECT * FROM "inventory_movements" ORDER BY date DESC',
  );
  return result.rows;
}

async function addInventoryMovementRaw(client, movement) {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  await client.query(
    'INSERT INTO "inventory_movements" (id, "medicineId", quantity, "unitType", "movementType", "createdAt") ' +
      "VALUES ($1, $2, $3, $4, $5, $6)",
    [
      id,
      movement.medicineId,
      movement.quantity,
      movement.unitType,
      movement.movementType,
      now,
    ],
  );
  return { ...movement, id, createdAt: now };
}

async function addInventoryMovement(movement) {
  return await addInventoryMovementRaw(pool, movement);
}

async function deleteInventoryMovement(id) {
  await query('DELETE FROM "inventory_movements" WHERE id = $1', [id]);
}

async function getInventoryMovementsByMedicineId(medicineId) {
  const result = await query(
    'SELECT * FROM "inventory_movements" WHERE "medicineId" = $1 ORDER BY date DESC',
    [medicineId],
  );
  return result.rows;
}

async function getUserByUsername(username) {
  const result = await query("SELECT * FROM users WHERE username = $1", [
    username,
  ]);
  return result.rows[0] || null;
}


module.exports = {
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
  getTransactionById,
};