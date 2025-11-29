const express = require('express');
const db = require('./db');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- 1. CONFIGURE CORS FOR PRODUCTION ---
const allowedOrigins = [
  'http://localhost:3000', 
  'https://pledge-loan-frontend.onrender.com',
  'exp://192.168.29.6:8081' 
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));

app.use(express.json());

const PORT = process.env.PORT || 3001; 
const JWT_SECRET = process.env.JWT_SECRET || 'a-very-strong-secret-key-that-you-should-change';
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verification Error:", err.message);
      return res.sendStatus(403);
    }
    req.user = user; 
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
};

// --- 3. GLOBAL INTEREST CALCULATION FUNCTION ---
const calculateTotalMonthsFactor = (startDate, endDate) => {
  const start = new Date(startDate);
  const end = new Date(endDate);
  start.setHours(0,0,0,0);
  end.setHours(0,0,0,0);

  if (end < start) return 0; 

  let fullMonthsPassed = 0;
  let tempDate = new Date(start);

  while (true) {
      const nextMonth = tempDate.getMonth() + 1;
      tempDate.setMonth(nextMonth);
      if (tempDate.getMonth() !== (nextMonth % 12)) tempDate.setDate(0); 
      
      if (tempDate <= end) { 
        fullMonthsPassed++; 
      } else { 
        tempDate.setMonth(tempDate.getMonth() - 1); 
        break; 
      }
  }

  const oneDay = 1000 * 60 * 60 * 24;
  const remainingDays = Math.floor((end.getTime() - tempDate.getTime()) / oneDay);
  
  let partialFraction = 0; 
  let totalMonthsFactor;

  if (fullMonthsPassed === 0) { 
    totalMonthsFactor = 1.0; 
  } else { 
    if (remainingDays > 0) { 
      partialFraction = (remainingDays <= 15) ? 0.5 : 1.0; 
    } 
    totalMonthsFactor = fullMonthsPassed + partialFraction; 
  }

  if (totalMonthsFactor === 0 && end >= start) {
     totalMonthsFactor = 1.0; 
  }

  return totalMonthsFactor;
};

app.get('/', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT NOW()');
    res.status(200).json({ message: "Welcome!", db_status: "Connected", db_time: rows[0].now });
  } catch (err) {
    res.status(500).json({ message: "DB connection failed.", db_status: "Error" });
  }
});

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/register', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password are required.');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await db.query("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username", [username, hashedPassword]);
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('Username already exists.');
    res.status(500).send('Server error during registration.');
  }
});

// --- UPDATED LOGIN ROUTE (Phase 2) ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password are required.');
    
    // FETCH branch_id along with user details
    const userResult = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    
    if (userResult.rows.length === 0) return res.status(401).send('Invalid credentials.');
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) return res.status(401).send('Invalid credentials.');
    
    // INCLUDE branch_id in the token payload
    const tokenPayload = { 
      userId: user.id, 
      username: user.username, 
      role: user.role,
      branchId: user.branch_id // <--- NEW FIELD
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({ 
      token: token, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        branchId: user.branch_id 
      } 
    });
  } catch (err) { 
    console.error("Login Error:", err);
    res.status(500).send('Server error during login.'); 
  }
});

// --- USER MANAGEMENT ---
// - UPDATED USER MANAGEMENT (Admins & Staff)
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await db.query("SELECT id, username, role FROM users ORDER BY id ASC");
    res.json(users.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

// UPDATED: Accepts 'role' in body
// --- UPDATED CREATE USER ROUTE (Phase 2) ---
app.post('/api/users/create', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    // added branchId to request body
    const { username, password, role, branchId } = req.body; 
    
    if (!username || !password) return res.status(400).send('Username and password are required.');
    
    // Default to admin's branch if not provided, or 1 (Main)
    const assignedBranch = branchId || req.user.branchId || 1; 
    const validRole = (role === 'admin') ? 'admin' : 'staff';

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const newUser = await db.query(
        "INSERT INTO users (username, password, role, branch_id) VALUES ($1, $2, $3, $4) RETURNING id, username, role, branch_id", 
        [username, hashedPassword, validRole, assignedBranch]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('Username already exists.');
    console.error("Create User Error:", err);
    res.status(500).send('Server error during user creation.');
  }
});

app.put('/api/users/change-password', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return res.status(400).send('User ID and new password are required.');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const result = await db.query("UPDATE users SET password = $1 WHERE id = $2 RETURNING id, username", [hashedPassword, userId]);
    if (result.rows.length === 0) return res.status(404).send('User not found.');
    res.status(200).json({ message: `Password for ${result.rows[0].username} updated successfully.` });
  } catch (err) { res.status(500).send('Server error changing password.'); }
});

// UPDATED: Can delete anyone except SELF
app.delete('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = parseInt(id);
    if (isNaN(userId)) return res.status(400).send('Invalid user ID.');
    
    // Safety Check: Prevent deleting self
    if (userId === req.user.userId) return res.status(400).send('You cannot delete your own account.');
    
    const result = await db.query("DELETE FROM users WHERE id = $1 RETURNING id, username, role", [userId]);
    if (result.rows.length === 0) return res.status(404).send('User not found.');
    
    res.status(200).json({ message: `User ${result.rows[0].username} (${result.rows[0].role}) deleted successfully.` });
  } catch (err) { res.status(500).send('Server error deleting user.'); }
});


// --- CUSTOMERS ---
//
// --- CUSTOMERS LIST (With Loan Stats) ---
// --- UPDATED GET CUSTOMERS (Phase 2 - Branch Filtered) ---
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    // 1. Update Overdue Status (Standard maintenance)
    // Same logic as loans: Admins update all, Staff update theirs (to be safe)
    if (req.user.role === 'admin') {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    } else {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [req.user.branchId]);
    }

    let query;
    let params = [];

    // 2. Build Query based on Role
    // Note: We join with Branches table to get the branch name (optional but useful)
    if (req.user.role === 'admin') {
      // ADMIN: Sees ALL customers
      query = `
        SELECT 
          c.id, c.name, c.phone_number, c.address, c.customer_image_url, c.branch_id, b.branch_name,
          COUNT(CASE WHEN l.status = 'active' THEN 1 END)::int AS active_loan_count,
          COUNT(CASE WHEN l.status = 'overdue' THEN 1 END)::int AS overdue_loan_count,
          COUNT(CASE WHEN l.status = 'paid' THEN 1 END)::int AS paid_loan_count
        FROM Customers c
        LEFT JOIN Loans l ON c.id = l.customer_id AND l.status != 'deleted'
        LEFT JOIN Branches b ON c.branch_id = b.id
        WHERE c.is_deleted = false
        GROUP BY c.id, b.branch_name
        ORDER BY c.name ASC
      `;
    } else {
      // STAFF: Sees ONLY their branch's customers
      query = `
        SELECT 
          c.id, c.name, c.phone_number, c.address, c.customer_image_url, c.branch_id, b.branch_name,
          COUNT(CASE WHEN l.status = 'active' THEN 1 END)::int AS active_loan_count,
          COUNT(CASE WHEN l.status = 'overdue' THEN 1 END)::int AS overdue_loan_count,
          COUNT(CASE WHEN l.status = 'paid' THEN 1 END)::int AS paid_loan_count
        FROM Customers c
        LEFT JOIN Loans l ON c.id = l.customer_id AND l.status != 'deleted'
        LEFT JOIN Branches b ON c.branch_id = b.id
        WHERE c.is_deleted = false 
        AND c.branch_id = $1
        GROUP BY c.id, b.branch_name
        ORDER BY c.name ASC
      `;
      params.push(req.user.branchId);
    }
    
    const result = await db.query(query, params);
    
    // Process images
    const customers = result.rows.map(c => {
        if (c.customer_image_url) {
            const b64 = c.customer_image_url.toString('base64');
            const mime = b64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
            c.customer_image_url = `data:${mime};base64,${b64}`;
        }
        return c;
    });

    res.json(customers);
  } catch (err) { 
    console.error("Get Customers Error:", err);
    res.status(500).send("Server Error"); 
  }
});

app.get('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });
    const customerResult = await db.query("SELECT * FROM Customers WHERE id = $1 AND is_deleted = false", [id]);
    if (customerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
    const customer = customerResult.rows[0];
    if (customer.customer_image_url) {
      const imageBase64 = customer.customer_image_url.toString('base64');
      let mimeType = imageBase64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
      customer.customer_image_url = `data:${mimeType};base64,${imageBase64}`;
    }
    res.json(customer);
  } catch (err) { res.status(500).send("Server Error"); }
});

// --- MODIFIED: Create Customer (Includes KYC & Nominee) ---
// --- UPDATED CREATE CUSTOMER (Phase 2 - Auto Branch Tag) ---
app.post('/api/customers', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation } = req.body;
    const imageBuffer = req.file ? req.file.buffer : null;
    
    if (!name || !phone_number) return res.status(400).json({ error: 'Name and phone are required.' });
    
    // 1. Determine Branch
    // If admin provides a 'branchId' in body, use it. Otherwise default to user's branch.
    // (Parsing int to ensure safety)
    const assignedBranch = req.body.branchId ? parseInt(req.body.branchId) : (req.user.branchId || 1);

    const newCustomerResult = await db.query(
      `INSERT INTO Customers 
       (name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, customer_image_url, is_deleted, branch_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, $9) 
       RETURNING *`,
      [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, imageBuffer, assignedBranch]
    );
    res.status(201).json(newCustomerResult.rows[0]);
  } catch (err) { 
    console.error("Create Customer Error:", err);
    res.status(500).send("Server Error"); 
  }
});

// --- MODIFIED: Update Customer (Includes KYC & Nominee) ---
app.put('/api/customers/:id', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });

        // --- 🛡️ PASTE THE SECURITY SNIPPET HERE ---
        // Check if the user is authorized to edit this specific customer
        if (req.user.role !== 'admin') {
            const checkBranch = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
            // If customer exists AND belongs to a different branch -> Block access
            if (checkBranch.rows.length > 0 && checkBranch.rows[0].branch_id !== req.user.branchId) {
                return res.status(403).json({ error: "Access Denied. You can only edit customers in your branch." });
            }
        }
        // ---------------------------------------------
        
        const { name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation } = req.body;
        let imageBuffer = null;
        let updateImage = false;
        
        if (req.file) { imageBuffer = req.file.buffer; updateImage = true; }
        else if (req.body.removeCurrentImage === 'true') { imageBuffer = null; updateImage = true; }
        
        let query; let values;
        if (updateImage) {
          query = `UPDATE Customers SET 
                   name = $1, phone_number = $2, address = $3, 
                   id_proof_type = $4, id_proof_number = $5, 
                   nominee_name = $6, nominee_relation = $7,
                   customer_image_url = $8 
                   WHERE id = $9 AND is_deleted = false RETURNING *`;
          values = [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, imageBuffer, id];
        } else {
          query = `UPDATE Customers SET 
                   name = $1, phone_number = $2, address = $3, 
                   id_proof_type = $4, id_proof_number = $5, 
                   nominee_name = $6, nominee_relation = $7
                   WHERE id = $8 AND is_deleted = false RETURNING *`;
          values = [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, id];
        }
        const updateCustomerResult = await db.query(query, values);
        if (updateCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
        res.json(updateCustomerResult.rows[0]);
    } catch (err) { 
        console.error("Update Customer Error:", err);
        res.status(500).send("Server Error"); 
    }
});

app.delete('/api/customers/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    const activeLoanCheck = await db.query("SELECT COUNT(*) FROM Loans WHERE customer_id = $1 AND status IN ('active', 'overdue')", [id]);
    if (parseInt(activeLoanCheck.rows[0].count) > 0) return res.status(400).json({ error: "Cannot delete customer. They have active or overdue loans." });
    const deleteCustomerResult = await db.query("UPDATE Customers SET is_deleted = true WHERE id = $1 RETURNING id, name", [id]);
    if (deleteCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
    await db.query("UPDATE Loans SET status = 'deleted' WHERE customer_id = $1 AND status IN ('paid', 'forfeited')", [id]);
    res.json({ message: `Customer '${deleteCustomerResult.rows[0].name}' and their closed loans have been moved to the recycle bin.` });
  } catch (err) { res.status(500).send("Server Error"); }
});

// --- LOANS ---
// --- UPDATED GET LOANS (Phase 2 - Branch Filtered) ---
app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    // 1. Update Overdue Status (Standard maintenance)
    // We restrict this update to the user's branch permissions to be safe, 
    // but updating all is fine for Admins.
    if (req.user.role === 'admin') {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    } else {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [req.user.branchId]);
    }

    let query;
    let params = [];

    // 2. Build Query based on Role
    if (req.user.role === 'admin') {
      // ADMIN: Sees ALL loans (Active, Overdue, Paid, Forfeited)
      query = `
        SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status,
               c.name AS customer_name, c.phone_number, b.branch_name
        FROM Loans l 
        JOIN Customers c ON l.customer_id = c.id
        LEFT JOIN Branches b ON l.branch_id = b.id
        WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited') AND c.is_deleted = false
        ORDER BY l.pledge_date DESC`;
    } else {
      // STAFF: Sees ONLY their branch's loans
      query = `
        SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status,
               c.name AS customer_name, c.phone_number, b.branch_name
        FROM Loans l 
        JOIN Customers c ON l.customer_id = c.id
        LEFT JOIN Branches b ON l.branch_id = b.id
        WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited') 
          AND c.is_deleted = false 
          AND l.branch_id = $1
        ORDER BY l.pledge_date DESC`;
      params.push(req.user.branchId);
    }

    const allLoans = await db.query(query, params);
    res.json(allLoans.rows);
  } catch (err) { 
    console.error("Get Loans Error:", err);
    res.status(500).send("Server Error"); 
  }
});

app.get('/api/loans/recent/created', authenticateToken, async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status != 'deleted' AND c.is_deleted = false ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/recent/closed', authenticateToken, async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'paid' AND c.is_deleted = false ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/overdue', authenticateToken, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    
    // FIX: Added 'c.address' to the SELECT list
    const query = `
      SELECT l.id, l.due_date, l.principal_amount, l.book_loan_number, l.pledge_date, 
             c.name AS customer_name, c.phone_number, c.address 
      FROM Loans l 
      JOIN Customers c ON l.customer_id = c.id 
      WHERE l.status = 'overdue' AND c.is_deleted = false 
      ORDER BY l.due_date ASC`;
      
    const overdueLoans = await db.query(query);
    res.json(overdueLoans.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/find-by-book-number/:bookNumber', authenticateToken, async (req, res) => {
  try {
    const { bookNumber } = req.params;
    const result = await db.query("SELECT id FROM Loans WHERE book_loan_number = $1 AND status != 'deleted'", [bookNumber]);
    if (result.rows.length === 0) return res.status(404).json({ error: "No loan found." });
    res.json({ loanId: result.rows[0].id });
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/loans/:id/add-principal', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { additionalAmount } = req.body;
  const loanId = parseInt(id);
  const amountToAdd = parseFloat(additionalAmount);
  const username = req.user.username; 
  if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid loan ID." });
  if (isNaN(amountToAdd) || amountToAdd <= 0) return res.status(400).json({ error: "Invalid additional amount." });
  
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const loanResult = await client.query("SELECT principal_amount, status FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
    const currentLoan = loanResult.rows[0];
    if (currentLoan.status !== 'active' && currentLoan.status !== 'overdue') { await client.query('ROLLBACK'); return res.status(400).json({ error: `Cannot add principal to a loan with status '${currentLoan.status}'.` }); }
    
    const currentPrincipal = parseFloat(currentLoan.principal_amount);
    const newPrincipal = currentPrincipal + amountToAdd;
    const updateResult = await client.query("UPDATE Loans SET principal_amount = $1 WHERE id = $2 RETURNING *", [newPrincipal, loanId]);
    await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4)", [loanId, amountToAdd, 'disbursement', username]);
    await client.query('COMMIT');
    res.json({ message: `Successfully added ₹${amountToAdd.toFixed(2)}.`, loan: updateResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK'); console.error("Add Principal Error:", err.message); res.status(500).send("Server Error.");
  } finally { client.release(); }
});

// --- MODIFIED: GET Loan Details (Includes Appraised Value & Net Weight) ---
app.get('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    
    await db.query("UPDATE Loans SET status = 'overdue' WHERE id = $1 AND due_date < NOW() AND status = 'active'", [id]);

    const loanQuery = `
      SELECT l.*, 
             pi.item_type, pi.description, pi.quality, 
             pi.weight, pi.gross_weight, pi.net_weight, pi.purity, 
             pi.item_image_data, 
             c.name AS customer_name, c.phone_number, c.address, c.customer_image_url 
      FROM Loans l 
      LEFT JOIN PledgedItems pi ON l.id = pi.loan_id 
      JOIN Customers c ON l.customer_id = c.id 
      WHERE l.id = $1 AND l.status != 'deleted' AND c.is_deleted = false
    `;
    const loanResult = await db.query(loanQuery, [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    let loanDetails = loanResult.rows[0];

    const transactionsResult = await db.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [id]);
    const transactions = transactionsResult.rows;

    const currentPrincipalTotal = parseFloat(loanDetails.principal_amount);
    const rate = parseFloat(loanDetails.interest_rate);
    const pledgeDate = new Date(loanDetails.pledge_date);
    const today = new Date();
    
    let totalInterestOwed = 0;
    let principalPaid = 0;
    let interestPaid = 0;
    let totalPaid = 0;
    const disbursementTxs = [];
    
    transactions.forEach(tx => {
      const amount = parseFloat(tx.amount_paid);
      if (tx.payment_type === 'disbursement') {
        disbursementTxs.push({ amount: amount, date: new Date(tx.payment_date) });
      } else {
        // [FIX] Exclude 'discount' from Total Cash Paid
        if (tx.payment_type !== 'discount') {
           totalPaid += amount;
        }

        if (tx.payment_type === 'principal') principalPaid += amount;
        else if (tx.payment_type === 'interest') interestPaid += amount;
      }
    });

    const subsequentDisbursementsSum = disbursementTxs.reduce((sum, tx) => sum + tx.amount, 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum; 
    const disbursements = [];
    
    // --- BUILD BREAKDOWN ---
    if (initialPrincipal > 0) {
        disbursements.push({ amount: initialPrincipal, date: pledgeDate, isInitial: true });
    }
    disbursements.push(...disbursementTxs.map(tx => ({ ...tx, isInitial: false })));
    
    const breakdown = [];
    
    disbursements.forEach((event, index) => {
        const monthsFactor = calculateTotalMonthsFactor(event.date, today);
        const interest = event.amount * (rate / 100) * monthsFactor;
        totalInterestOwed += interest;
        
        breakdown.push({
            label: event.isInitial ? 'Initial Principal' : `Top-up #${index}`,
            amount: event.amount,
            date: event.date,
            months: monthsFactor,
            interest: interest
        });
    });
    
    const outstandingPrincipal = currentPrincipalTotal - principalPaid;
    const outstandingInterest = totalInterestOwed - interestPaid;
    const amountDue = outstandingPrincipal + outstandingInterest;

    if (loanDetails.item_image_data) { const ib64 = loanDetails.item_image_data.toString('base64'); let mt = ib64.startsWith('/9j/') ? 'image/jpeg' : 'image/png'; loanDetails.item_image_data_url = `data:${mt};base64,${ib64}`; } delete loanDetails.item_image_data;
    if (loanDetails.customer_image_url) { const cb64 = loanDetails.customer_image_url.toString('base64'); let mt = cb64.startsWith('/9j/') ? 'image/jpeg' : 'image/png'; loanDetails.customer_image_url = `data:${mt};base64,${cb64}`; }

    res.json({ 
        loanDetails: loanDetails, 
        transactions: transactions.sort((a, b) => new Date(b.payment_date) - new Date(a.payment_date)),
        interestBreakdown: breakdown, 
        calculated: {
          totalInterestOwed: totalInterestOwed.toFixed(2),
          principalPaid: principalPaid.toFixed(2),
          interestPaid: interestPaid.toFixed(2),
          totalPaid: totalPaid.toFixed(2),
          outstandingPrincipal: outstandingPrincipal.toFixed(2),
          outstandingInterest: outstandingInterest.toFixed(2),
          amountDue: amountDue.toFixed(2)
        }
    });
  } catch (err) { console.error("GET Loan Details Error:", err.message); res.status(500).send("Server Error"); }
});

// --- MODIFIED: Create Loan (Includes Weight Details & Appraised Value) ---
app.post('/api/loans', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username; 
  try {
    const { 
      customer_id, principal_amount, interest_rate, book_loan_number, 
      item_type, description, quality, 
      gross_weight, net_weight, purity, appraised_value,
      deductFirstMonthInterest 
    } = req.body;

    const itemImageBuffer = req.file ? req.file.buffer : null;
    const principal = parseFloat(principal_amount);
    const rate = parseFloat(interest_rate); 

    if (!customer_id || isNaN(principal) || principal <= 0 || isNaN(rate) || rate <= 0 || !book_loan_number || !item_type || !description) return res.status(400).send("Missing fields.");
    
    const customerCheck = await client.query("SELECT is_deleted FROM Customers WHERE id = $1", [customer_id]);
    if (customerCheck.rows.length === 0 || customerCheck.rows[0].is_deleted) return res.status(404).send("Customer not found.");

    await client.query('BEGIN');
    // 1. Insert Loan (added appraised_value)
    // NEW (Includes branch_id)
    // Use the user's branch from the token
    const branchId = req.user.branchId || 1; 
    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number, appraised_value, branch_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal, rate, book_loan_number, appraised_value || 0, branchId]);
    const newLoanId = loanResult.rows[0].id;

    // 2. Insert Pledged Item (added gross_weight, net_weight, purity)
    const finalGrossWeight = gross_weight || req.body.weight; // Fallback for backward compatibility
    const itemQuery = `INSERT INTO PledgedItems 
      (loan_id, item_type, description, quality, weight, gross_weight, net_weight, purity, item_image_data) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;
      
    await client.query(itemQuery, [
      newLoanId, item_type, description, quality, 
      finalGrossWeight, // Legacy weight
      finalGrossWeight, // New gross_weight
      net_weight, purity, itemImageBuffer
    ]);
    
    if (deductFirstMonthInterest === 'true') {
      const firstMonthInterest = principal * (rate / 100);
      if (firstMonthInterest > 0) {
        await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)", [newLoanId, firstMonthInterest, username]);
      }
    }

    await client.query('COMMIT');
    res.status(201).json({ message: "Loan created successfully", loanId: newLoanId });
  } catch (err) {
    await client.query('ROLLBACK'); console.error("POST Loan Error:", err.message);
    if (err.code === '23505') return res.status(400).json({ error: "Book Loan Number already exists." });
    res.status(500).send("Server Error while creating loan");
  } finally { client.release(); }
});

app.get('/api/customers/:id/loans', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    await db.query("UPDATE Loans SET status = 'overdue' WHERE customer_id = $1 AND due_date < NOW() AND status = 'active'", [id]);
    const query = `SELECT l.id AS loan_id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status, pi.description FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id WHERE l.customer_id = $1 AND l.status != 'deleted' ORDER BY l.pledge_date DESC`;
    const customerLoans = await db.query(query, [id]);
    res.json(customerLoans.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  try {
    const { loan_id, amount_paid, payment_type } = req.body; 
    const loanId = parseInt(loan_id);
    const paymentAmount = parseFloat(amount_paid);
    if (!loanId || !paymentAmount || paymentAmount <= 0) return res.status(400).json({ error: 'Valid Loan ID and positive amount required.' }); 

    await client.query('BEGIN');

    if (payment_type === 'principal') {
      const newTransaction = await client.query(
        "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4) RETURNING *", 
        [loanId, paymentAmount, 'principal', username]
      );
      await client.query('COMMIT');
      return res.status(201).json([newTransaction.rows[0]]);
    }

    if (payment_type === 'interest') {
      const loanResult = await client.query("SELECT * FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
      if (loanResult.rows.length === 0) throw new Error('Loan not found.');
      const loan = loanResult.rows[0];
      if (loan.status === 'deleted') throw new Error('Cannot add transaction to a deleted loan.');
      
      const transactionsResult = await client.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [loanId]);
      const transactions = transactionsResult.rows;
      const principal = parseFloat(loan.principal_amount);
      const rate = parseFloat(loan.interest_rate);
      const pledgeDate = new Date(loan.pledge_date);
      const today = new Date();
      let totalInterestOwed = 0;
      let interestPaid = 0;
      let principalPaid = 0;
      const disbursementTxs = [];
      transactions.forEach(tx => {
        const amount = parseFloat(tx.amount_paid);
        if (tx.payment_type === 'disbursement') disbursementTxs.push({ amount: amount, date: new Date(tx.payment_date) });
        else if (tx.payment_type === 'principal') principalPaid += amount;
        else if (tx.payment_type === 'interest') interestPaid += amount;
      });
      const subsequentDisbursementsSum = disbursementTxs.reduce((sum, tx) => sum + tx.amount, 0);
      const initialPrincipal = principal - subsequentDisbursementsSum;
      const disbursements = [];
      if (initialPrincipal > 0) disbursements.push({ amount: initialPrincipal, date: pledgeDate, isInitial: true });
      disbursements.push(...disbursementTxs.map(tx => ({ ...tx, isInitial: false })));
      
      disbursements.forEach(event => {
          const monthsFactor = calculateTotalMonthsFactor(event.date, today);
          totalInterestOwed += event.amount * (rate / 100) * monthsFactor;
      });
      
      const outstandingInterest = totalInterestOwed - interestPaid;

      if (paymentAmount > outstandingInterest) {
        const interestPayment = outstandingInterest > 0 ? outstandingInterest : 0; 
        const principalPayment = paymentAmount - interestPayment; 
        let createdTransactions = [];
        if (interestPayment > 0) {
          const interestTx = await client.query(
            "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3) RETURNING *",
            [loanId, interestPayment, username]
          );
          createdTransactions.push(interestTx.rows[0]);
        }
        const principalTx = await client.query(
          "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'principal', NOW(), $3) RETURNING *",
          [loanId, principalPayment, username]
        );
        createdTransactions.push(principalTx.rows[0]);
        await client.query('COMMIT');
        return res.status(201).json(createdTransactions);
      } else {
        const newTransaction = await client.query(
          "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3) RETURNING *",
          [loanId, paymentAmount, username]
        );
        await client.query('COMMIT');
        return res.status(201).json([newTransaction.rows[0]]);
      }
    }

    const newTransaction = await client.query(
      "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4) RETURNING *", 
      [loanId, paymentAmount, payment_type, username]
    );
    await client.query('COMMIT');
    return res.status(201).json([newTransaction.rows[0]]);
  } catch (err) {
    await client.query('ROLLBACK'); console.error("POST Transaction Error:", err.message);
    if (err.code === '23503') return res.status(404).json({ error: 'Loan not found.' });
    res.status(500).send("Server Error");
  } finally { client.release(); }
});

app.post('/api/loans/:id/settle', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  try {
    const { id } = req.params;
    const { discountAmount, settlementAmount } = req.body; 
    const loanId = parseInt(id);
    if (isNaN(loanId)) return res.status(400).json({ error: "Invalid loan ID." });

    const discount = parseFloat(discountAmount) || 0;
    const finalPayment = parseFloat(settlementAmount) || 0;

    await client.query('BEGIN');

    const loanQuery = `SELECT principal_amount, pledge_date, status, interest_rate FROM Loans WHERE id = $1 FOR UPDATE`;
    const loanResult = await client.query(loanQuery, [loanId]);
    if (loanResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
    const loan = loanResult.rows[0];

    if (loan.status !== 'active' && loan.status !== 'overdue') {
      await client.query('ROLLBACK'); return res.status(400).json({ error: `Cannot settle a loan with status '${loan.status}'.` });
    }

    // --- 1. Calculate Total Owed & Outstanding Interest ---
    const currentPrincipalTotal = parseFloat(loan.principal_amount);
    const monthlyInterestRatePercent = parseFloat(loan.interest_rate);
    const pledgeDate = new Date(loan.pledge_date);
    const today = new Date();

    const txResult = await client.query("SELECT amount_paid, payment_type, payment_date FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [loanId]);
    const transactions = txResult.rows;

    // Calculate Disbursements & Interest
    const disbursements = [];
    let principalPaidBefore = 0;
    let interestPaidBefore = 0;

    transactions.forEach(tx => {
        const amt = parseFloat(tx.amount_paid);
        if (tx.payment_type === 'disbursement') disbursements.push({ amount: amt, date: new Date(tx.payment_date), isInitial: false });
        else if (tx.payment_type === 'principal') principalPaidBefore += amt;
        else if (tx.payment_type === 'interest') interestPaidBefore += amt;
        // We ignore previous 'settlement' types as this logic replaces them, but if they exist, treat as principal for safety? 
        // Ideally, legacy 'settlement' should be treated carefully, but for now, we stick to P/I types.
    });

    // Add initial principal
    const subsequentDisbursementsSum = disbursements.reduce((sum, d) => sum + d.amount, 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum;
    if (initialPrincipal > 0) disbursements.unshift({ amount: initialPrincipal, date: pledgeDate, isInitial: true });

    let totalInterestAccrued = 0;
    disbursements.forEach(d => {
        const factor = calculateTotalMonthsFactor(d.date, today);
        totalInterestAccrued += d.amount * (monthlyInterestRatePercent / 100) * factor;
    });

    const totalOwed = currentPrincipalTotal + totalInterestAccrued;
    const totalPaidBefore = principalPaidBefore + interestPaidBefore; // Excluding previous discounts
    const outstandingBalance = totalOwed - totalPaidBefore;
    const outstandingInterest = totalInterestAccrued - interestPaidBefore;

    // --- 2. Validation ---
    const remainingAfterPayment = outstandingBalance - finalPayment - discount;
    // Allow tiny floating point diff (e.g., 0.5 rupees)
    if (remainingAfterPayment > 1.0) { 
      await client.query('ROLLBACK');
      return res.status(400).json({
          error: `Insufficient funds. Outstanding: ${outstandingBalance.toFixed(2)}, Payment+Discount: ${(finalPayment + discount).toFixed(2)}. Short by: ${remainingAfterPayment.toFixed(2)}`
      });
    }

    // --- 3. Record Split Transactions ---
    if (finalPayment > 0) {
        // Split logic: Pay off interest first
        let interestComponent = 0;
        let principalComponent = 0;

        if (outstandingInterest > 0) {
            // If payment covers all interest
            if (finalPayment >= outstandingInterest) {
                interestComponent = outstandingInterest;
                principalComponent = finalPayment - outstandingInterest;
            } else {
                // Payment only covers part of interest
                interestComponent = finalPayment;
                principalComponent = 0;
            }
        } else {
            // No interest left, all principal
            principalComponent = finalPayment;
        }

        if (interestComponent > 0) {
            await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)", [loanId, interestComponent, username]);
        }
        if (principalComponent > 0) {
            await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'principal', NOW(), $3)", [loanId, principalComponent, username]);
        }
    }

    if (discount > 0) {
       await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'discount', NOW(), $3)", [loanId, discount, username]);
    }

    // --- 4. Close Loan ---
    const closeLoan = await client.query("UPDATE Loans SET status = 'paid', closed_date = NOW() WHERE id = $1 RETURNING *", [loanId]);
    await client.query('COMMIT');
    res.json({ message: `Loan successfully closed.`, loan: closeLoan.rows[0] });

  } catch (err) {
    await client.query('ROLLBACK'); console.error("Settle Loan Error:", err.message); res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

app.delete('/api/loans/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    const loanResult = await db.query("SELECT status, book_loan_number FROM Loans WHERE id = $1", [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    if (loanResult.rows[0].status === 'active' || loanResult.rows[0].status === 'overdue') return res.status(400).json({ error: "Cannot delete an active or overdue loan. Please settle it first." });
    const deleteLoanResult = await db.query("UPDATE Loans SET status = 'deleted' WHERE id = $1 RETURNING id, book_loan_number", [id]);
    res.json({ message: `Loan #${deleteLoanResult.rows[0].book_loan_number} moved to recycle bin.` });
  } catch (err) { console.error("DELETE Loan Error:", err.message); res.status(500).send("Server Error"); }
});

// --- MODIFIED: Update Loan (Includes all new fields in Audit Log) ---
//
// --- MODIFIED: Update Loan (Robust Empty String Handling) ---
app.put('/api/loans/:id', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    const username = req.user.username; 
    const { 
        book_loan_number, interest_rate, pledge_date, due_date, appraised_value,
        item_type, description, quality, 
        gross_weight, net_weight, purity 
    } = req.body;

    const newItemImageBuffer = req.file ? req.file.buffer : undefined;
    const removeItemImage = req.body.removeItemImage === 'true';

    if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid loan ID." });
    
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        
        // Fetch old values
        const currentDataQuery = `
            SELECT l.book_loan_number, l.interest_rate, l.pledge_date, l.due_date, l.status, l.appraised_value,
                   pi.id AS item_id, pi.item_type, pi.description, pi.quality, 
                   pi.weight, pi.gross_weight, pi.net_weight, pi.purity, pi.item_image_data 
            FROM "loans" l 
            LEFT JOIN "pledgeditems" pi ON l.id = pi.loan_id 
            WHERE l.id = $1 FOR UPDATE OF l`;
            
        const currentResult = await client.query(currentDataQuery, [loanId]);
        if (currentResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
        
        const oldData = currentResult.rows[0];
        const itemId = oldData.item_id;
        
        if (oldData.status === 'deleted') { await client.query('ROLLBACK'); return res.status(400).json({ error: "Cannot edit a deleted loan." }); }

        const historyLogs = [];
        const loanUpdateFields = []; const loanUpdateValues = [];
        const itemUpdateFields = []; const itemUpdateValues = [];

        // --- HELPER TO COMPARE & PREPARE UPDATES ---
        const addUpdate = (table, field, newValue, oldValue, fieldsArray, valuesArray, logLabel = field) => {
            if (newValue === undefined) return; // Field not sent in request

            let dbValue = newValue;
            
            // --- FIX: Convert empty strings to NULL for all fields ---
            if (dbValue === "") dbValue = null;

            let oldValCompare = oldValue;
            let newValCompare = dbValue;

            // Date comparison logic
            const dateFields = ['pledge_date', 'due_date'];
            if (dateFields.includes(field)) {
                if (oldValue) {
                    const d = new Date(oldValue);
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    oldValCompare = `${year}-${month}-${day}`;
                } else {
                    oldValCompare = null;
                }
                // Ensure dbValue is strictly null or string for comparison
                newValCompare = dbValue; 
            } 
            // Numeric comparison logic
            else if (typeof oldValue === 'number' || !isNaN(parseFloat(oldValue))) {
                // If it's a number column, parse both to compare values, not types
                if (oldValue !== null) oldValCompare = parseFloat(oldValue);
                if (dbValue !== null) newValCompare = parseFloat(dbValue);
            }

            // If different, add to update list
            if (newValCompare !== oldValCompare) {
                fieldsArray.push(`"${field}"`);
                valuesArray.push(dbValue);
                
                historyLogs.push({ 
                    loan_id: loanId, 
                    field_changed: logLabel, 
                    old_value: String(oldValue ?? 'null'), 
                    new_value: String(dbValue ?? 'null'), 
                    changed_by_username: username 
                });
            }
        };

        // Check Loan Table Updates
        addUpdate('loans', 'book_loan_number', book_loan_number, oldData.book_loan_number, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'interest_rate', interest_rate, oldData.interest_rate, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'pledge_date', pledge_date, oldData.pledge_date, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'due_date', due_date, oldData.due_date, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'appraised_value', appraised_value, oldData.appraised_value, loanUpdateFields, loanUpdateValues);

        // Check Item Table Updates
        if (itemId) {
            addUpdate('pledgeditems', 'item_type', item_type, oldData.item_type, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'description', description, oldData.description, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'quality', quality, oldData.quality, itemUpdateFields, itemUpdateValues);
            
            // Sync legacy 'weight' with 'gross_weight'
            addUpdate('pledgeditems', 'weight', gross_weight, oldData.weight, itemUpdateFields, itemUpdateValues, 'gross_weight (legacy)');
            addUpdate('pledgeditems', 'gross_weight', gross_weight, oldData.gross_weight, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'net_weight', net_weight, oldData.net_weight, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'purity', purity, oldData.purity, itemUpdateFields, itemUpdateValues);

            // Handle Image Update
            if (newItemImageBuffer !== undefined || removeItemImage) {
                const finalImageValue = removeItemImage ? null : newItemImageBuffer;
                itemUpdateFields.push(`"item_image_data"`); itemUpdateValues.push(finalImageValue);
                
                historyLogs.push({ 
                    loan_id: loanId, 
                    field_changed: 'item_image', 
                    old_value: oldData.item_image_data ? '[Image Data]' : '[No Image]', 
                    new_value: finalImageValue ? '[New Image Data]' : '[Image Removed]', 
                    changed_by_username: username 
                });
            }
        }

        // Execute Updates
        if (loanUpdateFields.length > 0) {
            const loanSetClause = loanUpdateFields.map((field, i) => `${field} = $${i + 1}`).join(', ');
            loanUpdateValues.push(loanId); 
            await client.query(`UPDATE "loans" SET ${loanSetClause} WHERE id = $${loanUpdateValues.length}`, loanUpdateValues);
        }

        if (itemUpdateFields.length > 0 && itemId) {
            const itemSetClause = itemUpdateFields.map((field, i) => `${field} = $${i + 1}`).join(', ');
            itemUpdateValues.push(itemId); 
            await client.query(`UPDATE "pledgeditems" SET ${itemSetClause} WHERE id = $${itemUpdateValues.length}`, itemUpdateValues);
        }

        // Log Changes
        if (historyLogs.length > 0) {
            const historyInsertQuery = `INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username) VALUES ($1, $2, $3, $4, $5)`;
            for (const log of historyLogs) {
                await client.query(historyInsertQuery, [log.loan_id, log.field_changed, log.old_value, log.new_value, log.changed_by_username]);
            }
        }

        await client.query('COMMIT');
        res.json({ message: `Loan ${loanId} updated successfully. ${historyLogs.length} changes logged.` });

    } catch (err) {
        await client.query('ROLLBACK'); 
        console.error(`Error updating loan ${loanId}:`, err.message);
        if (err.code === '23505') return res.status(400).json({ error: "Book Loan Number already exists." });
        res.status(500).send("Server Error while updating loan.");
    } finally { 
        client.release(); 
    }
});

app.get('/api/loans/:id/history', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    if (isNaN(loanId)) return res.status(400).json({ error: "Invalid loan ID." });
    try {
        const historyQuery = `
          (SELECT id, changed_at, changed_by_username, 'edit' AS event_type, field_changed, old_value, new_value, NULL AS amount_paid, NULL AS payment_type FROM loan_history WHERE loan_id = $1)
          UNION ALL
          (SELECT id, payment_date AS changed_at, changed_by_username, 'transaction' AS event_type, NULL AS field_changed, NULL AS old_value, NULL AS new_value, amount_paid, payment_type FROM Transactions WHERE loan_id = $1)
          ORDER BY changed_at DESC;
        `;
        const historyResult = await db.query(historyQuery, [loanId]);
        res.json(historyResult.rows);
    } catch (err) { console.error(`Error fetching history for loan ${loanId}:`, err.message); res.status(500).send("Server Error fetching loan history."); }
});


// --- BRANCH MANAGEMENT ROUTE ---
app.get('/api/branches', authenticateToken, async (req, res) => {
  try {
    const result = await db.query("SELECT id, branch_name, branch_code FROM branches WHERE is_active = true ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    console.error("Get Branches Error:", err);
    res.status(500).send("Server Error");
  }
});

// --- DASHBOARD STATS ---
// --- UPDATED DASHBOARD STATS (Supports Branch Filtering) ---
app.get('/api/dashboard/stats', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { branchId } = req.query; // Check if frontend sent a specific branch
    const bId = branchId ? parseInt(branchId) : null;

    // Helper to build queries: If bId exists, filter by it. If null, show all.
    // Logic: "WHERE ($1::int IS NULL OR branch_id = $1)"
    const whereBranch = " AND ($1::int IS NULL OR branch_id = $1)";
    const params = [bId];

    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");

    const [
      principalResult, 
      activeLoansResult, 
      overdueLoansResult, 
      interestThisMonthResult, 
      totalCustomersResult, 
      totalLoansResult, 
      totalPaidResult, 
      totalForfeitedResult,
      totalDisbursedPrincipalResult 
    ] = await Promise.all([
      db.query(`SELECT SUM(principal_amount) FROM Loans WHERE (status = 'active' OR status = 'overdue') ${whereBranch}`, params), 
      db.query(`SELECT COUNT(*) FROM Loans WHERE (status = 'active' OR status = 'overdue') ${whereBranch}`, params),
      db.query(`SELECT COUNT(*) FROM Loans WHERE status = 'overdue' ${whereBranch}`, params),
      // For Transactions, we join Loans to check the branch
      db.query(`SELECT SUM(t.amount_paid) FROM Transactions t JOIN Loans l ON t.loan_id = l.id WHERE t.payment_type = 'interest' AND t.payment_date >= date_trunc('month', CURRENT_DATE) ${whereBranch}`, params),
      db.query(`SELECT COUNT(*) FROM Customers WHERE is_deleted = false ${whereBranch}`, params),
      db.query(`SELECT COUNT(*) FROM Loans WHERE status != 'deleted' ${whereBranch}`, params), 
      db.query(`SELECT COUNT(*) FROM Loans WHERE status = 'paid' ${whereBranch}`, params),
      db.query(`SELECT COUNT(*) FROM Loans WHERE status = 'forfeited' ${whereBranch}`, params),
      db.query(`SELECT SUM(principal_amount) FROM Loans WHERE status != 'deleted' ${whereBranch}`, params),
      db.query(`SELECT COUNT(*) FROM Loans WHERE status IN ('paid', 'renewed') ${whereBranch}`, params),
    ]);
    
    const totalDisbursedPrincipal = parseFloat(totalDisbursedPrincipalResult.rows[0].sum || 0);

    res.json({
      totalPrincipalOut: parseFloat(principalResult.rows[0].sum || 0),
      totalActiveLoans: parseInt(activeLoansResult.rows[0].count || 0),
      totalOverdueLoans: parseInt(overdueLoansResult.rows[0].count || 0),
      interestCollectedThisMonth: parseFloat(interestThisMonthResult.rows[0].sum || 0),
      totalCustomers: parseInt(totalCustomersResult.rows[0].count || 0),
      totalLoans: parseInt(totalLoansResult.rows[0].count || 0),
      totalValue: totalDisbursedPrincipal, 
      loansActive: parseInt(activeLoansResult.rows[0].count || 0),
      loansOverdue: parseInt(overdueLoansResult.rows[0].count || 0),
      loansPaid: parseInt(totalPaidResult.rows[0].count || 0),
      loansForfeited: parseInt(totalForfeitedResult.rows[0].count || 0)
    });
  } catch (err) { 
    console.error("Dashboard Stats Error:", err); 
    res.status(500).send("Server Error."); 
  }
});

// --- FINANCIAL REPORT ---
// - UPDATED FINANCIAL REPORT (Includes Loan Count)
app.get('/api/reports/financial-summary', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) return res.status(400).json({ error: "Start date and end date are required." });

    // 1. Disbursed (Money OUT) - Includes Principal + Additional Principal
    const disbursedQuery = `
      SELECT SUM(amount_paid) as total 
      FROM Transactions 
      WHERE payment_type = 'disbursement' 
      AND payment_date >= $1 AND payment_date <= $2
    `;

    // 2. Interest (Money IN)
    const interestQuery = `
      SELECT SUM(amount_paid) as total 
      FROM Transactions 
      WHERE payment_type = 'interest' 
      AND payment_date >= $1 AND payment_date <= $2
    `;

    // 3. Principal Repaid (Money IN)
    const principalRepaidQuery = `
      SELECT SUM(amount_paid) as total 
      FROM Transactions 
      WHERE (payment_type = 'principal' OR payment_type = 'settlement')
      AND payment_date >= $1 AND payment_date <= $2
    `;

    // 4. Discount (Virtual Cost)
    const discountQuery = `
      SELECT SUM(amount_paid) as total 
      FROM Transactions 
      WHERE payment_type = 'discount' 
      AND payment_date >= $1 AND payment_date <= $2
    `;
    
    // 5. NEW: Count of New Loans Created
    const loansCountQuery = `
      SELECT COUNT(*) as count 
      FROM Loans 
      WHERE pledge_date >= $1 AND pledge_date <= $2
    `;

    const [disbursedRes, interestRes, principalRepaidRes, discountRes, loansCountRes] = await Promise.all([
      db.query(disbursedQuery, [startDate, endDate]),
      db.query(interestQuery, [startDate, endDate]),
      db.query(principalRepaidQuery, [startDate, endDate]),
      db.query(discountQuery, [startDate, endDate]),
      db.query(loansCountQuery, [startDate, endDate]) // --- NEW ---
    ]);

    const totalDisbursed = parseFloat(disbursedRes.rows[0].total || 0);
    const totalInterest = parseFloat(interestRes.rows[0].total || 0);
    const totalPrincipalRepaid = parseFloat(principalRepaidRes.rows[0].total || 0);
    const totalDiscount = parseFloat(discountRes.rows[0].total || 0);
    const loansCreatedCount = parseInt(loansCountRes.rows[0].count || 0); // --- NEW ---
    
    const netProfit = totalInterest - totalDiscount;

    res.json({
      startDate,
      endDate,
      totalDisbursed,
      totalInterest,
      totalPrincipalRepaid,
      totalDiscount,
      netProfit,
      loansCreatedCount // --- NEW ---
    });

  } catch (err) {
    console.error("Financial Report Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/recycle-bin/deleted', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const [deletedCustomers, deletedLoans] = await Promise.all([
      db.query("SELECT id, name, phone_number, 'Customer' as type FROM Customers WHERE is_deleted = true"),
      db.query(`SELECT l.id, l.book_loan_number, c.name as customer_name, 'Loan' as type FROM Loans l JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'deleted' AND c.is_deleted = false`)
    ]);
    res.json({ customers: deletedCustomers.rows, loans: deletedLoans.rows });
  } catch (err) { console.error("GET Recycle Bin Error:", err.message); res.status(500).send("Server Error"); }
});

app.post('/api/customers/:id/restore', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    const restoreCustomerResult = await db.query("UPDATE Customers SET is_deleted = false WHERE id = $1 RETURNING id, name", [id]);
    if (restoreCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found in recycle bin." });
    await db.query("UPDATE Loans SET status = 'paid' WHERE customer_id = $1 AND status = 'deleted'", [id]);
    res.json({ message: `Customer '${restoreCustomerResult.rows[0].name}' and their loans have been restored.` });
  } catch (err) { console.error("RESTORE Customer Error:", err.message); res.status(500).send("Server Error"); }
});

app.delete('/api/customers/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const customerId = parseInt(id);
    if (isNaN(customerId)) return res.status(400).json({ error: "Invalid customer ID." });
    
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        const loanIdsResult = await client.query("SELECT id FROM Loans WHERE customer_id = $1", [customerId]);
        const loanIds = loanIdsResult.rows.map(row => row.id);

        if (loanIds.length > 0) {
            const loanIdString = loanIds.join(',');
            await client.query(`DELETE FROM PledgedItems WHERE loan_id IN (${loanIdString})`);
            await client.query(`DELETE FROM Transactions WHERE loan_id IN (${loanIdString})`);
            await client.query(`DELETE FROM loan_history WHERE loan_id IN (${loanIdString})`);
            await client.query(`DELETE FROM Loans WHERE customer_id = $1`, [customerId]);
        }

        const deleteCustomerResult = await client.query("DELETE FROM Customers WHERE id = $1 AND is_deleted = true RETURNING name", [customerId]);
        if (deleteCustomerResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Deleted customer not found." });
        }

        await client.query('COMMIT');
        res.json({ message: `Customer '${deleteCustomerResult.rows[0].name}' and all associated data permanently deleted.` });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("PERMANENT DELETE Customer Error:", err.message);
        res.status(500).send("Server Error during permanent deletion.");
    } finally {
        client.release();
    }
});

app.post('/api/loans/:id/restore', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    const customerCheck = await db.query("SELECT c.is_deleted FROM Customers c JOIN Loans l ON l.customer_id = c.id WHERE l.id = $1", [id]);
    if (customerCheck.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    if (customerCheck.rows[0].is_deleted) return res.status(400).json({ error: "Cannot restore loan. Customer is deleted." });
    const restoreLoanResult = await db.query("UPDATE Loans SET status = 'paid' WHERE id = $1 AND status = 'deleted' RETURNING id, book_loan_number", [id]);
    if (restoreLoanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found in recycle bin." });
    res.json({ message: `Loan #${restoreLoanResult.rows[0].book_loan_number} has been restored.` });
  } catch (err) { console.error("RESTORE Loan Error:", err.message); res.status(500).send("Server Error"); }
});

app.delete('/api/loans/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    if (isNaN(loanId)) return res.status(400).json({ error: "Invalid loan ID." });

    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        await client.query("DELETE FROM PledgedItems WHERE loan_id = $1", [loanId]);
        await client.query("DELETE FROM Transactions WHERE loan_id = $1", [loanId]);
        await client.query("DELETE FROM loan_history WHERE loan_id = $1", [loanId]);
        
        const deleteLoanResult = await client.query("DELETE FROM Loans WHERE id = $1 AND status = 'deleted' RETURNING book_loan_number", [loanId]);
        if (deleteLoanResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Deleted loan not found." });
        }

        await client.query('COMMIT');
        res.json({ message: `Loan #${deleteLoanResult.rows[0].book_loan_number} permanently deleted.` });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("PERMANENT DELETE Loan Error:", err.message);
        res.status(500).send("Server Error during permanent deletion.");
    } finally {
        client.release();
    }
});

// - NEW DAY BOOK ENDPOINT
// - OPTIMIZED DAY BOOK (Timezone Fixed)
app.get('/api/reports/day-book', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const dateParam = req.query.date; // Client sends 'YYYY-MM-DD'
    if (!dateParam) return res.status(400).json({ error: "Date is required." });

    // 1. Calculate Opening Balance
    // Logic: Sum of all transactions strictly BEFORE the start of this day in local time
    const openingBalanceQuery = `
      SELECT 
        SUM(CASE WHEN payment_type IN ('interest', 'principal', 'settlement') THEN amount_paid ELSE 0 END) -
        SUM(CASE WHEN payment_type = 'disbursement' THEN amount_paid ELSE 0 END) as balance
      FROM Transactions 
      WHERE (payment_date AT TIME ZONE 'Asia/Kolkata')::date < $1::date
    `;
    
    // 2. Fetch Transactions FOR this date
    // Logic: Transactions that fall ON this specific date in local time
    const dayTransactionsQuery = `
      SELECT t.*, l.book_loan_number, c.name as customer_name 
      FROM Transactions t
      JOIN Loans l ON t.loan_id = l.id
      JOIN Customers c ON l.customer_id = c.id
      WHERE (t.payment_date AT TIME ZONE 'Asia/Kolkata')::date = $1::date 
      AND t.payment_type != 'discount'
      ORDER BY t.payment_date ASC
    `;

    const [openingRes, dayRes] = await Promise.all([
      db.query(openingBalanceQuery, [dateParam]),
      db.query(dayTransactionsQuery, [dateParam])
    ]);

    const openingBalance = parseFloat(openingRes.rows[0].balance || 0);
    
    res.json({
      date: dateParam,
      openingBalance: openingBalance,
      transactions: dayRes.rows
    });

  } catch (err) {
    console.error("Day Book Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// - RENEW / ROLLOVER LOAN
// - SMART RENEWAL (Adds Unpaid Interest to Principal)
// - CORRECTED RENEWAL ROUTE (Fixes "5 parameters" error)
app.post('/api/loans/:id/renew', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  const oldLoanId = parseInt(req.params.id);
  
  const { interestPaid, newBookLoanNumber, newInterestRate } = req.body;

  if (isNaN(oldLoanId)) return res.status(400).json({ error: "Invalid Loan ID." });
  if (!newBookLoanNumber) return res.status(400).json({ error: "New Book Loan Number is required." });

  try {
    await client.query('BEGIN');

    // 1. Fetch Old Loan & Transactions
    const oldLoanRes = await client.query(`
      SELECT l.*, pi.item_type, pi.description, pi.quality, 
             pi.weight, pi.gross_weight, pi.net_weight, pi.purity, l.appraised_value, pi.item_image_data
      FROM Loans l 
      JOIN PledgedItems pi ON l.id = pi.loan_id 
      WHERE l.id = $1 FOR UPDATE`, [oldLoanId]);

    if (oldLoanRes.rows.length === 0) throw new Error("Loan not found.");
    const oldLoan = oldLoanRes.rows[0];

    if (oldLoan.status !== 'active' && oldLoan.status !== 'overdue') {
        throw new Error("Can only renew Active or Overdue loans.");
    }

    const txRes = await client.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [oldLoanId]);
    const transactions = txRes.rows;

    // 2. Calculate OUTSTANDING INTEREST
    const currentPrincipalTotal = parseFloat(oldLoan.principal_amount);
    const rate = parseFloat(oldLoan.interest_rate);
    const pledgeDate = new Date(oldLoan.pledge_date);
    const today = new Date();

    let interestPaidTotal = 0;
    const disbursementTxs = [];

    transactions.forEach(tx => {
      const amt = parseFloat(tx.amount_paid);
      if (tx.payment_type === 'disbursement') disbursementTxs.push({ amount: amt, date: new Date(tx.payment_date) });
      else if (tx.payment_type === 'interest') interestPaidTotal += amt;
    });

    const subsequentDisbursementsSum = disbursementTxs.reduce((sum, tx) => sum + tx.amount, 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum;
    
    const events = [];
    if (initialPrincipal > 0) events.push({ amount: initialPrincipal, date: pledgeDate });
    disbursementTxs.forEach(tx => events.push({ amount: tx.amount, date: tx.date }));

    let totalInterestAccrued = 0;
    events.forEach(e => {
        const factor = calculateTotalMonthsFactor(e.date, today);
        totalInterestAccrued += e.amount * (rate / 100) * factor;
    });

    const outstandingInterest = totalInterestAccrued - interestPaidTotal;
    
    // 3. Determine New Principal
    const payingNow = parseFloat(interestPaid) || 0;
    const unpaidInterest = outstandingInterest - payingNow;
    
    const interestToCapitalize = unpaidInterest > 0 ? unpaidInterest : 0;
    const newPrincipalAmount = currentPrincipalTotal + interestToCapitalize;

    // 4. Record the Interest Payment (if any)
    if (payingNow > 0) {
        await client.query(
            "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)",
            [oldLoanId, payingNow, username]
        );
    }
    
    // 5. Close Old Loan (Mark as 'renewed' instead of 'paid')
    await client.query("UPDATE Loans SET status = 'renewed', closed_date = NOW() WHERE id = $1", [oldLoanId]);

    // 6. Create NEW Loan
    const newRate = newInterestRate || oldLoan.interest_rate;
    const newLoanQuery = `
      INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number, appraised_value, pledge_date, due_date) 
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '1 year') 
      RETURNING id`;
      
    const newLoanRes = await client.query(newLoanQuery, [
        oldLoan.customer_id, 
        newPrincipalAmount, 
        newRate, 
        newBookLoanNumber, 
        oldLoan.appraised_value || 0
    ]);
    const newLoanId = newLoanRes.rows[0].id;

    // 7. Copy Item Details
    const itemQuery = `
      INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, gross_weight, net_weight, purity, item_image_data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `;
    await client.query(itemQuery, [
        newLoanId, oldLoan.item_type, oldLoan.description, oldLoan.quality, 
        oldLoan.weight, oldLoan.gross_weight, oldLoan.net_weight, oldLoan.purity, oldLoan.item_image_data
    ]);

    // 8. Audit Log (FIXED: Removed extra parameter)
    let logMsg = `Renewed from #${oldLoan.book_loan_number}.`;
    if (interestToCapitalize > 0) logMsg += ` Principal increased by ₹${interestToCapitalize.toFixed(2)} (Unpaid Interest).`;
    
    await client.query(
        "INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username) VALUES ($1, 'renewal', $2, $3, $4)",
        [newLoanId, logMsg, 'Active', username] // <--- Fixed array (4 items for 4 placeholders)
    );

    await client.query('COMMIT');
    
    res.json({ 
        message: `Renewed! New Principal: ₹${newPrincipalAmount.toFixed(2)}`, 
        newLoanId: newLoanId 
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Renewal Error:", err.message);
    if (err.code === '23505') return res.status(400).json({ error: "New Book Loan Number already exists." });
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// [cite: index.js] - BUSINESS SETTINGS ROUTES

// GET Settings
app.get('/api/settings', async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM business_settings WHERE id = 1");
    if (result.rows.length > 0) {
      const settings = result.rows[0];
      // If logo is stored as bytea, convert to base64 (if you chose that path),
      // but for now let's assume it's a text URL or base64 string stored in text column.
      res.json(settings);
    } else {
      res.json({ business_name: 'Sri KuberaLakshmi Bankers' }); // Default fallback
    }
  } catch (err) {
    console.error("Get Settings Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// UPDATE Settings
app.put('/api/settings', authenticateToken, authorizeAdmin, upload.single('logo'), async (req, res) => {
  try {
    // 1. Extract the new field 'navbar_display_mode'
    const { business_name, address, phone_number, license_number, navbar_display_mode } = req.body;
    let logoUrl = req.body.existingLogoUrl;

    if (req.file) {
      const b64 = req.file.buffer.toString('base64');
      const mime = req.file.mimetype;
      logoUrl = `data:${mime};base64,${b64}`;
    }

    // 2. Default to 'both' if not provided
    const displayMode = navbar_display_mode || 'both';

    // 3. Update the Query to include navbar_display_mode
    const query = `
      INSERT INTO business_settings (id, business_name, address, phone_number, license_number, logo_url, navbar_display_mode, updated_at)
      VALUES (1, $1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (id) DO UPDATE 
      SET business_name = $1, address = $2, phone_number = $3, license_number = $4, logo_url = $5, navbar_display_mode = $6, updated_at = NOW()
      RETURNING *
    `;
    
    // 4. Pass the new variable ($6)
    const result = await db.query(query, [business_name, address, phone_number, license_number, logoUrl, displayMode]);
    res.json(result.rows[0]);

  } catch (err) {
    console.error("Update Settings Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});