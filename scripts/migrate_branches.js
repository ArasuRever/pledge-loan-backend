const { Pool } = require('pg');
require('dotenv').config();

// Check if we are connecting to a local database
const isLocal = process.env.DB_HOST === 'localhost' || process.env.DB_HOST === '127.0.0.1';

// --- CONFIGURATION ---
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  // Smart SSL: False for Localhost, True for Render
  ssl: isLocal ? false : { rejectUnauthorized: false }
});

const runMigration = async () => {
  const client = await pool.connect();
  console.log(`🚀 Starting Branch Migration on: ${process.env.DB_HOST}...`);

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

    // 2. Insert Default 'Main Branch'
    console.log('Creating Main Branch...');
    const mainBranchRes = await client.query(`
      INSERT INTO branches (branch_name, branch_code, address, phone_number)
      VALUES ('Main Branch', 'MAIN', 'Head Office', '0000000000')
      ON CONFLICT (branch_code) DO UPDATE SET branch_name = EXCLUDED.branch_name
      RETURNING id;
    `);
    
    let mainBranchId = mainBranchRes.rows[0]?.id;
    if (!mainBranchId) {
        const fetchRes = await client.query("SELECT id FROM branches WHERE branch_code = 'MAIN'");
        mainBranchId = fetchRes.rows[0].id;
    }
    console.log(`✅ Main Branch ID: ${mainBranchId}`);

    // 3. Add 'branch_id' columns (Safe Updates)
    const addColumn = async (table) => {
        console.log(`Updating ${table} table...`);
        await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS branch_id INT REFERENCES branches(id);`);
        await client.query(`UPDATE ${table} SET branch_id = $1 WHERE branch_id IS NULL`, [mainBranchId]);
    };

    await addColumn('users');
    await addColumn('customers');
    await addColumn('loans');
    await addColumn('transactions');

    await client.query('COMMIT');
    console.log('✅ Migration Successful! Local DB is now Multi-Branch ready.');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Migration Failed:', err);
  } finally {
    client.release();
    pool.end();
  }
};

runMigration();