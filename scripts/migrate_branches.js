const { Pool } = require('pg');
require('dotenv').config();

// --- CONFIGURATION ---
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false } // Required for Render
});

const runMigration = async () => {
  const client = await pool.connect();
  console.log('🚀 Starting Branch Migration...');

  try {
    await client.query('BEGIN');

    // 1. Create 'branches' table
    console.log('Creating branches table...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS branches (
        id SERIAL PRIMARY KEY,
        branch_name VARCHAR(255) NOT NULL UNIQUE,
        branch_code VARCHAR(50) NOT NULL UNIQUE,
        address TEXT,
        phone_number VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // 2. Insert Default 'Main Branch' (if not exists)
    // We use ON CONFLICT to prevent errors if you run this script twice
    console.log('Creating Main Branch...');
    const mainBranchRes = await client.query(`
      INSERT INTO branches (branch_name, branch_code, address, phone_number)
      VALUES ('Main Branch', 'MAIN', 'Head Office', '0000000000')
      ON CONFLICT (branch_code) DO UPDATE SET branch_name = EXCLUDED.branch_name
      RETURNING id;
    `);
    
    // If it was an update, we fetch the ID separately
    let mainBranchId = mainBranchRes.rows[0]?.id;
    if (!mainBranchId) {
        const fetchRes = await client.query("SELECT id FROM branches WHERE branch_code = 'MAIN'");
        mainBranchId = fetchRes.rows[0].id;
    }
    console.log(`✅ Main Branch ID: ${mainBranchId}`);

    // 3. Add 'branch_id' to USERS table
    console.log('Updating Users table...');
    await client.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS branch_id INT REFERENCES branches(id);
    `);
    await client.query(`UPDATE users SET branch_id = $1 WHERE branch_id IS NULL`, [mainBranchId]);

    // 4. Add 'branch_id' to CUSTOMERS table
    console.log('Updating Customers table...');
    await client.query(`
      ALTER TABLE customers 
      ADD COLUMN IF NOT EXISTS branch_id INT REFERENCES branches(id);
    `);
    await client.query(`UPDATE customers SET branch_id = $1 WHERE branch_id IS NULL`, [mainBranchId]);

    // 5. Add 'branch_id' to LOANS table
    console.log('Updating Loans table...');
    await client.query(`
      ALTER TABLE loans 
      ADD COLUMN IF NOT EXISTS branch_id INT REFERENCES branches(id);
    `);
    await client.query(`UPDATE loans SET branch_id = $1 WHERE branch_id IS NULL`, [mainBranchId]);

    // 6. (Optional) Add 'branch_id' to TRANSACTIONS
    // For now, we rely on the Loan's branch_id, but adding it here helps with specific accounting later.
    console.log('Updating Transactions table...');
    await client.query(`
      ALTER TABLE transactions 
      ADD COLUMN IF NOT EXISTS branch_id INT REFERENCES branches(id);
    `);
    await client.query(`UPDATE transactions SET branch_id = $1 WHERE branch_id IS NULL`, [mainBranchId]);

    await client.query('COMMIT');
    console.log('✅ Migration Successful! All data is now linked to "Main Branch".');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Migration Failed:', err);
  } finally {
    client.release();
    pool.end();
  }
};

runMigration();