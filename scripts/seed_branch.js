const { Pool } = require('pg');
require('dotenv').config();

// Check if we are connecting to a local database
const isLocal = process.env.DB_HOST === 'localhost' || process.env.DB_HOST === '127.0.0.1';

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  // Only use SSL if we are NOT on localhost
  ssl: isLocal ? false : { rejectUnauthorized: false }
});

const seed = async () => {
  console.log(`🔌 Connecting to: ${process.env.DB_HOST} (SSL: ${!isLocal})`);
  const client = await pool.connect();
  try {
    // Insert "City Branch"
    const res = await client.query(`
      INSERT INTO branches (branch_name, branch_code, address, phone_number)
      VALUES ('City Branch', 'CITY01', '123 Market St', '9876543210')
      ON CONFLICT (branch_code) DO NOTHING
      RETURNING *;
    `);
    
    if (res.rows.length > 0) {
        console.log('✅ Created Branch:', res.rows[0]);
    } else {
        console.log('⚠️ Branch already exists.');
    }
  } catch (err) {
    console.error('❌ Error:', err.message);
  } finally {
    client.release();
    pool.end();
  }
};

seed();