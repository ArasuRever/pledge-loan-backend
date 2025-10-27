// db.js
const { Pool } = require('pg');
require('dotenv').config(); // Keep dotenv for local development

// Check if we are in the production (Render) environment
const isProduction = process.env.NODE_ENV === 'production';

// This is the URL Render provides in its environment variables
const connectionString = process.env.DATABASE_URL;

// Use Render's connection string in production, otherwise use local .env variables
const pool = new Pool({
    connectionString: isProduction ? connectionString : `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_DATABASE}`,
    // Enable SSL for production (Render requires this)
    // rejectUnauthorized: false is often needed for Render's setup
    ssl: isProduction ? { rejectUnauthorized: false } : false,
});

// Optional: Add a connection check
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Database connected, server time:', res.rows[0].now);
  }
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool: pool,
};