const { Client } = require("pg");

async function runMigrations(client) {
  // Create migrations tracking table
  await client.query(`
    CREATE TABLE IF NOT EXISTS migrations (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      runAt TIMESTAMP NOT NULL
    );
  `);

  // Get already applied migrations
  const result = await client.query("SELECT name FROM migrations");
  const appliedMigrations = new Set(result.rows.map((m) => m.name));

  const migrations = [
    {
      name: "001_initial_schema",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS medicines (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            "unitType" TEXT NOT NULL CHECK ("unitType" IN ('tablet', 'capsule', 'ml', 'vial')),
            quantity INTEGER NOT NULL,
            boxes INTEGER,
            "stripsPerBox" INTEGER,
            "unitsPerStrip" INTEGER,
            bottles INTEGER,
            "mlPerBottle" INTEGER,
            price DECIMAL(10,2) NOT NULL,
            "lowStockThreshold" INTEGER NOT NULL,
            "restockThreshold" INTEGER NOT NULL,
            "expiryDate" TIMESTAMP NOT NULL,
            supplier TEXT,
            "batchNumber" TEXT,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS transactions (
            id UUID PRIMARY KEY,
            "totalAmount" DECIMAL(10,2) NOT NULL,
            "paymentMethod" TEXT NOT NULL,
            date TIMESTAMP NOT NULL,
            notes TEXT,
            "createdAt" TIMESTAMP NOT NULL
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS "transactionItems" (
            id UUID PRIMARY KEY,
            "transactionId" UUID NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
            "medicineId" UUID NOT NULL REFERENCES medicines(id),
            "medicineName" TEXT NOT NULL,
            "unitType" TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            "dosageInstructions" TEXT,
            "unitPrice" DECIMAL(10,2) NOT NULL,
            subtotal DECIMAL(10,2) NOT NULL
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS licenses (
            id UUID PRIMARY KEY,
            key TEXT NOT NULL UNIQUE,
            type TEXT NOT NULL CHECK (type IN ('trial', 'purchased')),
            "licenseType" TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'expired')),
            "activationDate" TIMESTAMP NOT NULL,
            "expiryDate" TIMESTAMP,
            "maxMachines" INTEGER NOT NULL,
            "machineIds" TEXT NOT NULL,
            "createdAt" TIMESTAMP NOT NULL
          );
        `);

        await client.query(`
          CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updatedAt TIMESTAMP NOT NULL
          );
        `);

        await client.query(`
          CREATE INDEX IF NOT EXISTS "idx_medicines_expiryDate" ON medicines("expiryDate");
        `);
        await client.query(`
          CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date);
        `);
        await client.query(`
          CREATE INDEX IF NOT EXISTS "idx_transactionItems_transactionId" ON "transactionItems"("transactionId");
        `);
      },
    },

    {
      name: "002_add_inactive_license_status",
      up: async (client) => {
        await client.query(`
          ALTER TABLE licenses
          ADD COLUMN IF NOT EXISTS status TEXT CHECK (status IN ('active', 'expired', 'inactive'));
        `);
        // Update existing rows to have 'active' status if needed
        await client.query(
          `UPDATE licenses SET status = 'active' WHERE status IS NULL`,
        );
        await client.query(
          `ALTER TABLE licenses ALTER COLUMN status SET NOT NULL`,
        );
      },
    },

    {
      name: "003_add_signature_to_licenses",
      up: async (client) => {
        await client.query(
          `ALTER TABLE licenses ADD COLUMN IF NOT EXISTS signature TEXT;`,
        );
      },
    },

    {
      name: "004_add_unit_buying_price_to_medicines",
      up: async (client) => {
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "unitBuyingPrice" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "005_add_isDeleted_to_medicines",
      up: async (client) => {
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "isDeleted" INTEGER NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "006_add_wholesaleStripPrice_and_wholesaleBoxPrice_to_medicines",
      up: async (client) => {
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "wholesaleStripPrice" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "wholesaleBoxPrice" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "007_add_profit_to_transactions",
      up: async (client) => {
        await client.query(`
          ALTER TABLE transactions
          ADD COLUMN IF NOT EXISTS profit DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "008_add_transactionType_to_transactions",
      up: async (client) => {
        await client.query(`
          ALTER TABLE transactions
          ADD COLUMN IF NOT EXISTS "transactionType" TEXT;
        `);
      },
    },

    {
      name: "009_add_stockQuantity_to_transactionItems",
      up: async (client) => {
        await client.query(`
          ALTER TABLE "transactionItems"
          ADD COLUMN IF NOT EXISTS "stockQuantity" INTEGER NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "add_buying_and_selling_price_to_medicines",
      up: async (client) => {
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "buyingPrice" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
        await client.query(`
          ALTER TABLE medicines
          ADD COLUMN IF NOT EXISTS "sellingPrice" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
      },
    },

    {
      name: "010_add_inventory_movements_table",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS "inventory_movements" (
            id UUID PRIMARY KEY,
            "medicineId" UUID NOT NULL,
            quantity INTEGER NOT NULL,
            "unitType" TEXT NOT NULL,
            "movementType" TEXT NOT NULL,
            "createdAt" TIMESTAMP NOT NULL
          );
        `);
        await client.query(`
          CREATE INDEX IF NOT EXISTS "idx_inventory_movements_medicineId"
          ON "inventory_movements"("medicineId");
        `);
      },
    },

    {
      name: "011_add_packType_to_transactions",
      up: async (client) => {
        await client.query(`
          ALTER TABLE transactions
          ADD COLUMN IF NOT EXISTS "packType" TEXT NOT NULL DEFAULT 'unit';
        `);
      },
    },

    {
      name: "012_expand_unitType_constraint",
      up: async (client) => {
        // PostgreSQL doesn't support directly modifying CHECK constraints
        // We need to drop and recreate the constraint
        await client.query(`
          ALTER TABLE medicines DROP CONSTRAINT IF EXISTS "medicines_unitType_check";
        `);
        await client.query(`
          ALTER TABLE medicines
          ADD CONSTRAINT "medicines_unitType_check"
          CHECK ("unitType" IN (
            'tablet', 'capsule', 'syrup', 'suspension', 'solution',
            'injection', 'drops', 'cream', 'ointment', 'lotion', 'gel',
            'suppository', 'powder', 'inhaler', 'spray', 'sachet', 'ml', 'vial', 'custom'
          ));
        `);
      },
    },

    {
      name: "013_add_custom_unitType_and_update_constraints",
      up: async (client) => {
        // Already handled in 012, kept for compatibility
      },
    },

    {
      name: "014_users_table",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            username TEXT NOT NULL,
            phone TEXT NOT NULL,
            password TEXT NOT NULL,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL
          );
        `);
        await client.query(
          `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);`,
        );
      },
    },

    {
      name: "015_add_pharmacy_info_table",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS "pharmacyInfo" (
            id UUID PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            "userId" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL
          );
        `);
      },
    },

    {
      name: "016_add_staff_table",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS staff (
            id UUID PRIMARY KEY,
            "userName" TEXT NOT NULL,
            pin TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'pharmacist', 'cashier', 'technician')),
            "pharmacyId" UUID NOT NULL REFERENCES "pharmacyInfo"(id) ON DELETE CASCADE,
            "contactNumber" TEXT,
            "createdAt" TIMESTAMP NOT NULL,
            "updatedAt" TIMESTAMP NOT NULL
          );
        `);
      },
    },

    {
      name: "017_add_contactNumber_to_staff",
      up: async (client) => {
        await client.query(
          `ALTER TABLE staff ADD COLUMN IF NOT EXISTS "contactNumber" TEXT;`,
        );
      },
    },

    {
      name: "018_add_pharmacyId_to_medicines_and_transactions",
      up: async (client) => {
        await client.query(
          `ALTER TABLE medicines ADD COLUMN IF NOT EXISTS "pharmacyId" UUID;`,
        );
        await client.query(
          `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS "pharmacyId" UUID;`,
        );
        await client.query(
          `ALTER TABLE "transactionItems" ADD COLUMN IF NOT EXISTS "pharmacyId" UUID;`,
        );
      },
    },

    {
      name: "019_add_cashierId_to_transactions",
      up: async (client) => {
        await client.query(
          `ALTER TABLE transactions ADD COLUMN IF NOT EXISTS "cashierId" UUID;`,
        );
      },
    },

    {
      name: "020_add_foreign_keys_for_pharmacyId",
      up: async (client) => {
        await client.query(`
          DO $$
          BEGIN
            IF NOT EXISTS (
              SELECT 1 FROM pg_constraint
              WHERE conname = 'fk_medicines_pharmacy'
            ) THEN
              ALTER TABLE medicines
              ADD CONSTRAINT fk_medicines_pharmacy
              FOREIGN KEY ("pharmacyId") REFERENCES "pharmacyInfo"(id);
            END IF;
            IF NOT EXISTS (
              SELECT 1 FROM pg_constraint
              WHERE conname = 'fk_transactions_pharmacy'
            ) THEN
              ALTER TABLE transactions
              ADD CONSTRAINT fk_transactions_pharmacy
              FOREIGN KEY ("pharmacyId") REFERENCES "pharmacyInfo"(id);
            END IF;
            IF NOT EXISTS (
              SELECT 1 FROM pg_constraint
              WHERE conname = 'fk_transactionItems_pharmacy'
            ) THEN
              ALTER TABLE "transactionItems"
              ADD CONSTRAINT fk_transactionItems_pharmacy
              FOREIGN KEY ("pharmacyId") REFERENCES "pharmacyInfo"(id);
            END IF;
            IF NOT EXISTS (
              SELECT 1 FROM pg_constraint
              WHERE conname = 'fk_transactions_cashier'
            ) THEN
              ALTER TABLE transactions
              ADD CONSTRAINT fk_transactions_cashier 
              FOREIGN KEY ("cashierId") REFERENCES staff(id);
            END IF;
          END $$;
        `);
      },
    },

    {
      name: "021_add_contactNumber_to_pharmacyInfo",
      up: async (client) => {
        // Add contactNumber column if it doesn't exist
        await client.query(`
          ALTER TABLE "pharmacyInfo"
          ADD COLUMN IF NOT EXISTS "contactNumber" TEXT;
        `);

        // Copy existing phone values to contactNumber for backward compatibility
        await client.query(`
          UPDATE "pharmacyInfo" 
          SET "contactNumber" = phone 
          WHERE "contactNumber" IS NULL AND phone IS NOT NULL;
        `);
      },
    },
    {
      name: "022_add_billTotal_to_transactions",
      up: async (client) => {
        await client.query(`
          ALTER TABLE transactions
          ADD COLUMN IF NOT EXISTS "billTotal" DECIMAL(10,2) NOT NULL DEFAULT 0;
        `);
      },
    },
    {
      name: "023_add_pharmacyCode_to_pharmacyInfo",
      up: async (client) => {
        await client.query(`
          ALTER TABLE "pharmacyInfo"
          ADD COLUMN IF NOT EXISTS "pharmacyCode" TEXT;
        `);
        await client.query(`
          CREATE UNIQUE INDEX IF NOT EXISTS idx_pharmacyInfo_pharmacyCode ON "pharmacyInfo"("pharmacyCode");
        `);
      },
    },
    {
      name: "024_add_licenses_table",
      up: async (client) => {
        await client.query(`
          CREATE TABLE IF NOT EXISTS licenses (
            id UUID PRIMARY KEY,
            licenseKey TEXT NOT NULL UNIQUE,
            plan TEXT NOT NULL,
            maxMachines INTEGER NOT NULL,
            expiresAt TIMESTAMP NOT NULL,
            machineIds TEXT[] NOT NULL,
            status TEXT NOT NULL,
            "paymentReference" TEXT,
            "paymentStatus" TEXT DEFAULT 'pending',
            amount DECIMAL(10,2) NOT NULL,
            phone TEXT NOT NULL,
            "productCode" TEXT NOT NULL,
            "user" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            "isEarlyAdopter" BOOLEAN NOT NULL DEFAULT FALSE
          );
        `);
      },
    },
    // add email, "isVerified", "verificationToken", "verificationExpires", "verifiedAt", "resetToken", "resetTokenExpires", "passwordChangedAt", role, "createdAt", "updatedAt" to users table
    {
      name: "025_add_email_and_verification_fields_to_users",
      up: async (client) => {
        await client.query(`
          ALTER TABLE users
          ADD COLUMN IF NOT EXISTS email TEXT UNIQUE,
          ADD COLUMN IF NOT EXISTS "isVerified" BOOLEAN NOT NULL DEFAULT FALSE,
          ADD COLUMN IF NOT EXISTS "verificationToken" TEXT,
          ADD COLUMN IF NOT EXISTS "verificationExpires" TIMESTAMP,
          ADD COLUMN IF NOT EXISTS "verifiedAt" TIMESTAMP,
          ADD COLUMN IF NOT EXISTS "resetToken" TEXT,
          ADD COLUMN IF NOT EXISTS "resetTokenExpires" TIMESTAMP,
          ADD COLUMN IF NOT EXISTS "passwordChangedAt" TIMESTAMP,
          ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user',
          ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMP NOT NULL DEFAULT NOW(),
          ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP NOT NULL DEFAULT NOW();
        `);
      },
    },
    {
      name: "026_make_pharmacyId_array_of_ids",
      up: async (client) => {
        // Add new jsonb column
        await client.query(`
      ALTER TABLE staff
      ADD COLUMN IF NOT EXISTS "pharmacyIds" JSONB;
    `);

        // Migrate existing pharmacyId values
        await client.query(`
      UPDATE staff
      SET "pharmacyIds" = jsonb_build_array("pharmacyId")
      WHERE "pharmacyId" IS NOT NULL
        AND "pharmacyIds" IS NULL;
    `);

        // Default empty array for any remaining rows
        await client.query(`
      UPDATE staff
      SET "pharmacyIds" = '[]'::jsonb
      WHERE "pharmacyIds" IS NULL;
    `);

        // Make column required
        await client.query(`
      ALTER TABLE staff
      ALTER COLUMN "pharmacyIds" SET NOT NULL;
    `);

        // Remove old foreign key constraint if it exists
        await client.query(`
      ALTER TABLE staff
      DROP CONSTRAINT IF EXISTS staff_pharmacyId_fkey;
    `);

        // Remove old column
        await client.query(`
      ALTER TABLE staff
      DROP COLUMN IF EXISTS "pharmacyId";
    `);

        // Index for fast lookups
        await client.query(`
      CREATE INDEX IF NOT EXISTS idx_staff_pharmacyIds
      ON staff
      USING GIN ("pharmacyIds");
    `);
      },
    },
    {
      name: "027_rename_key_to_licenseKey",
      up: async (client) => {
        await client.query(`
      ALTER TABLE licenses
      RENAME COLUMN key TO "licenseKey";
    `);
      },
    },
  ];

  for (const migration of migrations) {
    if (appliedMigrations.has(migration.name)) continue;

    console.log(`Running migration: ${migration.name}`);
    await client.query("BEGIN");
    try {
      await migration.up(client);
      await client.query(
        "INSERT INTO migrations (name, runAt) VALUES ($1, NOW())",
        [migration.name],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      console.error(`Migration ${migration.name} failed:`, err);
      throw err;
    }
  }
}

module.exports = { runMigrations };
