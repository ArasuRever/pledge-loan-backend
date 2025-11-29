// Force Re-deploy v1
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// --- CONFIGURATION ---
const DB_CONFIG = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
};

const R2_CONFIG = {
  accountId: process.env.R2_ACCOUNT_ID,
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  bucketName: process.env.R2_BUCKET_NAME,
};

// --- S3 CLIENT SETUP (Cloudflare R2) ---
const s3Client = new S3Client({
  region: 'auto',
  endpoint: `https://${R2_CONFIG.accountId}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_CONFIG.accessKeyId,
    secretAccessKey: R2_CONFIG.secretAccessKey,
  },
});

const backupFileName = `backup-${new Date().toISOString().replace(/:/g, '-')}.sql`;
const backupPath = path.join(__dirname, backupFileName);

// --- MAIN FUNCTION ---
const runBackup = async () => {
  console.log('⏳ Starting Database Backup...');

  // 1. Construct pg_dump command
  // PGPASSWORD environment variable is used to pass the password securely to pg_dump
  const dumpCommand = `PGPASSWORD='${DB_CONFIG.password}' pg_dump -h ${DB_CONFIG.host} -p ${DB_CONFIG.port} -U ${DB_CONFIG.user} -d ${DB_CONFIG.database} -F p -f "${backupPath}"`;

  exec(dumpCommand, async (error, stdout, stderr) => {
    if (error) {
      console.error(`❌ Error creating dump: ${error.message}`);
      return;
    }
    if (stderr) {
      // pg_dump writes verbose info to stderr, so we just log it
      console.log(`ℹ️ pg_dump output: ${stderr}`);
    }

    console.log('✅ Backup file created locally.');

    // 2. Upload to Cloudflare R2
    try {
      const fileStream = fs.createReadStream(backupPath);
      
      const uploadParams = {
        Bucket: R2_CONFIG.bucketName,
        Key: `db-backups/${backupFileName}`, // Organized in a folder
        Body: fileStream,
      };

      console.log('⏳ Uploading to Cloudflare R2...');
      await s3Client.send(new PutObjectCommand(uploadParams));
      console.log('✅ Upload Successful!');

      // 3. Cleanup local file
      fs.unlinkSync(backupPath);
      console.log('🧹 Local backup file cleaned up.');
      
      process.exit(0); // Success exit code

    } catch (err) {
      console.error('❌ Upload Failed:', err);
      process.exit(1); // Error exit code
    }
  });
};

runBackup();