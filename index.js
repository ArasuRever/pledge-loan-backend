
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
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      // In development, you might want to allow all, but for security in prod:
      // return callback(new Error('The CORS policy for this site does not allow access from the specified Origin.'), false);
      return callback(null, true); // Permissive for now to ensure your mobile app connects easily
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

// Allows Admin OR Manager
const authorizeManagement = (req, res, next) => {
  if (['admin', 'manager'].includes(req.user.role)) {
    next();
  } else {
    return res.sendStatus(403);
  }
};

// --- HELPER: GET TARGET BRANCH ID ---
// Returns null if "All Branches" (Admin only), or specific ID for filtering
const getTargetBranchId = (req) => {
  const { role, branchId: userBranchId } = req.user;
  const { branchId: queryBranchId } = req.query;

  if (role === 'admin') {
    // Admin can see ALL (null) or specific branch if requested
    if (queryBranchId && queryBranchId !== 'all') {
      return parseInt(queryBranchId);
    }
    return null; // Return null to signify "No Filter / All Branches"
  } else {
    // Managers and Staff are ALWAYS locked to their assigned branch
    return userBranchId;
  }
};

// --- GLOBAL INTEREST CALCULATION FUNCTION ---
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
    res.status(200).json({ message: "Welcome to Pledge Loan API", db_status: "Connected", db_time: rows[0].now });
  } catch (err) {
    res.status(500).json({ message: "DB connection failed.", db_status: "Error" });
  }
});

// --- AUTHENTICATION ROUTES ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password are required.');
    
    // Fetch user details + Branch Name
    const query = `
      SELECT u.*, b.branch_name 
      FROM users u 
      LEFT JOIN branches b ON u.branch_id = b.id 
      WHERE u.username = $1
    `;
    const userResult = await db.query(query, [username]);
    
    if (userResult.rows.length === 0) return res.status(401).send('Invalid credentials.');
    const user = userResult.rows[0];
    
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) return res.status(401).send('Invalid credentials.');
    
    // INCLUDE branch_id in the token payload
    const tokenPayload = { 
      userId: user.id, 
      username: user.username, 
      role: user.role,
      branchId: user.branch_id 
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '30d' });
    
    res.json({ 
      token: token, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        branchId: user.branch_id,
        branchName: user.branch_name || 'Main Branch'
      } 
    });
  } catch (err) { 
    console.error("Login Error:", err);
    res.status(500).send('Server error during login.'); 
  }
});

// --- USER MANAGEMENT (ADMIN ONLY) ---
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await db.query(`
      SELECT u.id, u.username, u.role, u.branch_id, b.branch_name 
      FROM users u 
      LEFT JOIN branches b ON u.branch_id = b.id 
      ORDER BY u.id ASC
    `);
    res.json(users.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/users/create', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, password, role, branchId } = req.body; 
    
    if (!username || !password) return res.status(400).send('Username and password are required.');
    
    const validRoles = ['admin', 'manager', 'staff'];
    const assignedRole = validRoles.includes(role) ? role : 'staff';
    const assignedBranch = branchId || 1; 

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const newUser = await db.query(
        "INSERT INTO users (username, password, role, branch_id) VALUES ($1, $2, $3, $4) RETURNING id, username, role, branch_id", 
        [username, hashedPassword, assignedRole, assignedBranch]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('Username already exists.');
    console.error("Create User Error:", err);
    res.status(500).send('Server error during user creation.');
  }
});

// Update User Details (Role, Branch, Username)
app.put('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, role, branchId } = req.body;
    
    // 1. Check if user exists
    const check = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: "User not found" });

    // 2. Prepare Update
    // Use existing values if not provided
    const oldUser = check.rows[0];
    const newUsername = username || oldUser.username;
    const newRole = role || oldUser.role;
    const newBranchId = (branchId !== undefined) ? branchId : oldUser.branch_id;

    // 3. Update Query
    const result = await db.query(
      "UPDATE users SET username = $1, role = $2, branch_id = $3 WHERE id = $4 RETURNING id, username, role, branch_id",
      [newUsername, newRole, newBranchId, id]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update User Error:", err);
    res.status(500).send("Server Error");
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

app.delete('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = parseInt(id);
    if (isNaN(userId)) return res.status(400).send('Invalid user ID.');
    if (userId === req.user.userId) return res.status(400).send('You cannot delete your own account.');
    
    const result = await db.query("DELETE FROM users WHERE id = $1 RETURNING id, username, role", [userId]);
    if (result.rows.length === 0) return res.status(404).send('User not found.');
    
    res.status(200).json({ message: `User ${result.rows[0].username} (${result.rows[0].role}) deleted successfully.` });
  } catch (err) { res.status(500).send('Server error deleting user.'); }
});


// --- CUSTOMERS ---
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req); // null (All) or ID

    // Update overdue status efficiently (scoped)
    if (targetBranch) {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [targetBranch]);
    } else {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    }

    let query = `
        SELECT 
          c.id, c.name, c.phone_number, c.address, c.customer_image_url, c.branch_id, b.branch_name,
          COUNT(CASE WHEN l.status = 'active' THEN 1 END)::int AS active_loan_count,
          COUNT(CASE WHEN l.status = 'overdue' THEN 1 END)::int AS overdue_loan_count,
          COUNT(CASE WHEN l.status = 'paid' THEN 1 END)::int AS paid_loan_count
        FROM Customers c
        LEFT JOIN Loans l ON c.id = l.customer_id AND l.status != 'deleted'
        LEFT JOIN Branches b ON c.branch_id = b.id
        WHERE c.is_deleted = false
    `;

    const params = [];
    if (targetBranch) {
        query += ` AND c.branch_id = $1`;
        params.push(targetBranch);
    }

    query += ` GROUP BY c.id, b.branch_name ORDER BY c.name ASC`;
    
    const result = await db.query(query, params);
    
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

    // Check Access (Manager/Staff can only view own branch)
    if (req.user.role !== 'admin' && customer.branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied. Customer belongs to another branch." });
    }

    if (customer.customer_image_url) {
      const imageBase64 = customer.customer_image_url.toString('base64');
      let mimeType = imageBase64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
      customer.customer_image_url = `data:${mimeType};base64,${imageBase64}`;
    }
    res.json(customer);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/customers', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation } = req.body;
    const imageBuffer = req.file ? req.file.buffer : null;
    
    if (!name || !phone_number) return res.status(400).json({ error: 'Name and phone are required.' });
    
    // Assign Branch: Admin can choose, others use their own
    let assignedBranch = req.user.branchId;
    if (req.user.role === 'admin' && req.body.branchId) {
        assignedBranch = parseInt(req.body.branchId);
    }

    const newCustomerResult = await db.query(
      `INSERT INTO Customers 
       (name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, customer_image_url, is_deleted, branch_id) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, $9) 
       RETURNING *`,
      [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, imageBuffer, assignedBranch || 1]
    );
    res.status(201).json(newCustomerResult.rows[0]);
  } catch (err) { 
    console.error("Create Customer Error:", err);
    res.status(500).send("Server Error"); 
  }
});

app.put('/api/customers/:id', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });

        // Branch check
        const checkBranch = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
        if (checkBranch.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
        
        if (req.user.role !== 'admin' && checkBranch.rows[0].branch_id !== req.user.branchId) {
            return res.status(403).json({ error: "Access Denied. You can only edit customers in your branch." });
        }
        
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
        res.json(updateCustomerResult.rows[0]);
    } catch (err) { 
        console.error("Update Customer Error:", err);
        res.status(500).send("Server Error"); 
    }
});

// Admin AND Manager can delete (within branch)
app.delete('/api/customers/:id', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    
    // Check branch ownership
    const cust = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
    if (cust.rows.length === 0) return res.status(404).json({ error: "Not found." });

    if (req.user.role !== 'admin' && cust.rows[0].branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied." });
    }

    const activeLoanCheck = await db.query("SELECT COUNT(*) FROM Loans WHERE customer_id = $1 AND status IN ('active', 'overdue')", [id]);
    if (parseInt(activeLoanCheck.rows[0].count) > 0) return res.status(400).json({ error: "Cannot delete customer. They have active or overdue loans." });
    
    const deleteCustomerResult = await db.query("UPDATE Customers SET is_deleted = true WHERE id = $1 RETURNING id, name", [id]);
    await db.query("UPDATE Loans SET status = 'deleted' WHERE customer_id = $1 AND status IN ('paid', 'forfeited')", [id]);
    
    res.json({ message: `Customer '${deleteCustomerResult.rows[0].name}' and their closed loans have been moved to the recycle bin.` });
  } catch (err) { res.status(500).send("Server Error"); }
});

// --- LOANS ---
app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);

    // Scoped update for overdue
    if (targetBranch) {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [targetBranch]);
    } else {
       await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    }

    let query = `
        SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status,
               c.name AS customer_name, c.phone_number, b.branch_name
        FROM Loans l 
        JOIN Customers c ON l.customer_id = c.id
        LEFT JOIN Branches b ON l.branch_id = b.id
        WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited') AND c.is_deleted = false
    `;
    
    const params = [];
    if (targetBranch) {
        query += ` AND l.branch_id = $1`;
        params.push(targetBranch);
    }
    
    query += ` ORDER BY l.pledge_date DESC`;

    const allLoans = await db.query(query, params);
    res.json(allLoans.rows);
  } catch (err) { 
    console.error("Get Loans Error:", err);
    res.status(500).send("Server Error"); 
  }
});

// Recent/Overdue filters also need to respect branch
const getScopedLoanQuery = (baseQuery, req) => {
    const targetBranch = getTargetBranchId(req);
    let q = baseQuery;
    const params = [];
    // Ensure baseQuery has WHERE clause or add it
    const hasWhere = q.toUpperCase().includes("WHERE");
    
    if (targetBranch) {
        q += hasWhere ? ` AND l.branch_id = $1` : ` WHERE l.branch_id = $1`;
        params.push(targetBranch);
    }
    return { q, params };
};

app.get('/api/loans/recent/created', authenticateToken, async (req, res) => {
  try {
    let base = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status != 'deleted' AND c.is_deleted = false`;
    const { q, params } = getScopedLoanQuery(base, req);
    const finalQ = q + ` ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(finalQ, params)).rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/recent/closed', authenticateToken, async (req, res) => {
  try {
    let base = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'paid' AND c.is_deleted = false`;
    const { q, params } = getScopedLoanQuery(base, req);
    const finalQ = q + ` ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(finalQ, params)).rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/overdue', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);
    if(targetBranch) await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [targetBranch]);
    else await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    
    let base = `
      SELECT l.id, l.due_date, l.principal_amount, l.book_loan_number, l.pledge_date, 
             c.name AS customer_name, c.phone_number, c.address 
      FROM Loans l 
      JOIN Customers c ON l.customer_id = c.id 
      WHERE l.status = 'overdue' AND c.is_deleted = false`;
    
    const { q, params } = getScopedLoanQuery(base, req);
    const finalQ = q + ` ORDER BY l.due_date ASC`;
      
    const overdueLoans = await db.query(finalQ, params);
    res.json(overdueLoans.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/find-by-book-number/:bookNumber', authenticateToken, async (req, res) => {
  try {
    const { bookNumber } = req.params;
    // Check branch scope
    const targetBranch = getTargetBranchId(req);
    let query = "SELECT id FROM Loans WHERE book_loan_number = $1 AND status != 'deleted'";
    let params = [bookNumber];
    
    if (targetBranch) {
        query += " AND branch_id = $2";
        params.push(targetBranch);
    }
    
    const result = await db.query(query, params);
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
    const loanResult = await client.query("SELECT principal_amount, status, branch_id FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
    
    const currentLoan = loanResult.rows[0];
    // Branch Access Check
    if (req.user.role !== 'admin' && currentLoan.branch_id !== req.user.branchId) {
        await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." });
    }

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

app.get('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    
    const check = await db.query("SELECT branch_id FROM Loans WHERE id = $1", [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: "Loan not found" });
    
    // Access Check
    if (req.user.role !== 'admin' && check.rows[0].branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied." });
    }

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

    // Calculation Logic
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
    
    // Check Customer Branch
    const customerCheck = await client.query("SELECT branch_id, is_deleted FROM Customers WHERE id = $1", [customer_id]);
    if (customerCheck.rows.length === 0 || customerCheck.rows[0].is_deleted) return res.status(404).send("Customer not found.");
    
    const custBranch = customerCheck.rows[0].branch_id;
    if (req.user.role !== 'admin' && custBranch !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied. Cannot create loan for other branch customer." });
    }

    await client.query('BEGIN');
    
    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number, appraised_value, branch_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal, rate, book_loan_number, appraised_value || 0, custBranch]);
    const newLoanId = loanResult.rows[0].id;

    const finalGrossWeight = gross_weight || req.body.weight; 
    const itemQuery = `INSERT INTO PledgedItems 
      (loan_id, item_type, description, quality, weight, gross_weight, net_weight, purity, item_image_data) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;
      
    await client.query(itemQuery, [
      newLoanId, item_type, description, quality, 
      finalGrossWeight, 
      finalGrossWeight, 
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
    // This endpoint typically called inside Customer Detail, where access is already checked.
    // But good to double check.
    const cust = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
    if (cust.rows.length > 0 && req.user.role !== 'admin' && cust.rows[0].branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied." });
    }

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

    // Access Check
    const loanCheck = await client.query("SELECT branch_id, status, principal_amount, interest_rate, pledge_date FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanCheck.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
    const loan = loanCheck.rows[0];

    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) {
        await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." });
    }

    // Principal Payment logic
    if (payment_type === 'principal') {
      const newTransaction = await client.query(
        "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4) RETURNING *", 
        [loanId, paymentAmount, 'principal', username]
      );
      await client.query('COMMIT');
      return res.status(201).json([newTransaction.rows[0]]);
    }

    // Interest Payment logic
    if (payment_type === 'interest') {
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

      // Smart Split: If paying more than owed interest, split rest to principal
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

    // Other types
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

    const loanQuery = `SELECT branch_id, principal_amount, pledge_date, status, interest_rate FROM Loans WHERE id = $1 FOR UPDATE`;
    const loanResult = await client.query(loanQuery, [loanId]);
    if (loanResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
    const loan = loanResult.rows[0];

    // Access Check
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) {
        await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." });
    }

    if (loan.status !== 'active' && loan.status !== 'overdue') {
      await client.query('ROLLBACK'); return res.status(400).json({ error: `Cannot settle a loan with status '${loan.status}'.` });
    }

    const currentPrincipalTotal = parseFloat(loan.principal_amount);
    const monthlyInterestRatePercent = parseFloat(loan.interest_rate);
    const pledgeDate = new Date(loan.pledge_date);
    const today = new Date();

    const txResult = await client.query("SELECT amount_paid, payment_type, payment_date FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [loanId]);
    const transactions = txResult.rows;

    const disbursements = [];
    let principalPaidBefore = 0;
    let interestPaidBefore = 0;

    transactions.forEach(tx => {
        const amt = parseFloat(tx.amount_paid);
        if (tx.payment_type === 'disbursement') disbursements.push({ amount: amt, date: new Date(tx.payment_date), isInitial: false });
        else if (tx.payment_type === 'principal') principalPaidBefore += amt;
        else if (tx.payment_type === 'interest') interestPaidBefore += amt;
    });

    const subsequentDisbursementsSum = disbursements.reduce((sum, d) => sum + d.amount, 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum;
    if (initialPrincipal > 0) disbursements.unshift({ amount: initialPrincipal, date: pledgeDate, isInitial: true });

    let totalInterestAccrued = 0;
    disbursements.forEach(d => {
        const factor = calculateTotalMonthsFactor(d.date, today);
        totalInterestAccrued += d.amount * (monthlyInterestRatePercent / 100) * factor;
    });

    const totalOwed = currentPrincipalTotal + totalInterestAccrued;
    const totalPaidBefore = principalPaidBefore + interestPaidBefore; 
    const outstandingBalance = totalOwed - totalPaidBefore;
    const outstandingInterest = totalInterestAccrued - interestPaidBefore;

    const remainingAfterPayment = outstandingBalance - finalPayment - discount;
    if (remainingAfterPayment > 1.0) { 
      await client.query('ROLLBACK');
      return res.status(400).json({
          error: `Insufficient funds. Outstanding: ${outstandingBalance.toFixed(2)}, Payment+Discount: ${(finalPayment + discount).toFixed(2)}. Short by: ${remainingAfterPayment.toFixed(2)}`
      });
    }

    if (finalPayment > 0) {
        let interestComponent = 0;
        let principalComponent = 0;

        if (outstandingInterest > 0) {
            if (finalPayment >= outstandingInterest) {
                interestComponent = outstandingInterest;
                principalComponent = finalPayment - outstandingInterest;
            } else {
                interestComponent = finalPayment;
                principalComponent = 0;
            }
        } else {
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

    const closeLoan = await client.query("UPDATE Loans SET status = 'paid', closed_date = NOW() WHERE id = $1 RETURNING *", [loanId]);
    await client.query('COMMIT');
    res.json({ message: `Loan successfully closed.`, loan: closeLoan.rows[0] });

  } catch (err) {
    await client.query('ROLLBACK'); console.error("Settle Loan Error:", err.message); res.status(500).send("Server Error");
  } finally {
    client.release();
  }
});

// Admin OR Manager can delete
app.delete('/api/loans/:id', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    
    const loanResult = await db.query("SELECT status, book_loan_number, branch_id FROM Loans WHERE id = $1", [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    
    const loan = loanResult.rows[0];
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied." });
    }

    if (loan.status === 'active' || loan.status === 'overdue') return res.status(400).json({ error: "Cannot delete an active or overdue loan. Please settle it first." });
    
    const deleteLoanResult = await db.query("UPDATE Loans SET status = 'deleted' WHERE id = $1 RETURNING id, book_loan_number", [id]);
    res.json({ message: `Loan #${deleteLoanResult.rows[0].book_loan_number} moved to recycle bin.` });
  } catch (err) { console.error("DELETE Loan Error:", err.message); res.status(500).send("Server Error"); }
});

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
        
        const currentDataQuery = `
            SELECT l.book_loan_number, l.interest_rate, l.pledge_date, l.due_date, l.status, l.appraised_value, l.branch_id,
                   pi.id AS item_id, pi.item_type, pi.description, pi.quality, 
                   pi.weight, pi.gross_weight, pi.net_weight, pi.purity, pi.item_image_data 
            FROM "loans" l 
            LEFT JOIN "pledgeditems" pi ON l.id = pi.loan_id 
            WHERE l.id = $1 FOR UPDATE OF l`;
            
        const currentResult = await client.query(currentDataQuery, [loanId]);
        if (currentResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
        
        const oldData = currentResult.rows[0];

        // Access Check
        if (req.user.role !== 'admin' && oldData.branch_id !== req.user.branchId) {
             await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." });
        }

        const itemId = oldData.item_id;
        if (oldData.status === 'deleted') { await client.query('ROLLBACK'); return res.status(400).json({ error: "Cannot edit a deleted loan." }); }

        const historyLogs = [];
        const loanUpdateFields = []; const loanUpdateValues = [];
        const itemUpdateFields = []; const itemUpdateValues = [];

        const addUpdate = (table, field, newValue, oldValue, fieldsArray, valuesArray, logLabel = field) => {
            if (newValue === undefined) return; 
            let dbValue = newValue;
            if (dbValue === "") dbValue = null;
            let oldValCompare = oldValue;
            let newValCompare = dbValue;

            const dateFields = ['pledge_date', 'due_date'];
            if (dateFields.includes(field)) {
                if (oldValue) {
                    const d = new Date(oldValue);
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    oldValCompare = `${year}-${month}-${day}`;
                } else { oldValCompare = null; }
                newValCompare = dbValue; 
            } 
            else if (typeof oldValue === 'number' || !isNaN(parseFloat(oldValue))) {
                if (oldValue !== null) oldValCompare = parseFloat(oldValue);
                if (dbValue !== null) newValCompare = parseFloat(dbValue);
            }

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

        addUpdate('loans', 'book_loan_number', book_loan_number, oldData.book_loan_number, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'interest_rate', interest_rate, oldData.interest_rate, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'pledge_date', pledge_date, oldData.pledge_date, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'due_date', due_date, oldData.due_date, loanUpdateFields, loanUpdateValues);
        addUpdate('loans', 'appraised_value', appraised_value, oldData.appraised_value, loanUpdateFields, loanUpdateValues);

        if (itemId) {
            addUpdate('pledgeditems', 'item_type', item_type, oldData.item_type, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'description', description, oldData.description, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'quality', quality, oldData.quality, itemUpdateFields, itemUpdateValues);
            
            addUpdate('pledgeditems', 'weight', gross_weight, oldData.weight, itemUpdateFields, itemUpdateValues, 'gross_weight (legacy)');
            addUpdate('pledgeditems', 'gross_weight', gross_weight, oldData.gross_weight, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'net_weight', net_weight, oldData.net_weight, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'purity', purity, oldData.purity, itemUpdateFields, itemUpdateValues);

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
    
    // Access Check (View Only)
    const check = await db.query("SELECT branch_id FROM Loans WHERE id=$1", [loanId]);
    if(check.rows.length > 0 && req.user.role!=='admin' && check.rows[0].branch_id !== req.user.branchId) {
        return res.status(403).json({ error: "Access Denied."});
    }

    try {
        const historyQuery = `
          (SELECT id, changed_at, changed_by_username, 'edit' AS event_type, field_changed, old_value, new_value, NULL AS amount_paid, NULL AS payment_type FROM loan_history WHERE loan_id = $1)
          UNION ALL
          (SELECT id, payment_date AS changed_at, changed_by_username, 'transaction' AS event_type, NULL AS field_changed, NULL AS old_value, NULL AS new_value, amount_paid, payment_type FROM Transactions WHERE loan_id = $1)
          ORDER BY changed_at DESC;
        `;
        const historyResult = await db.query(historyQuery, [loanId]);
        res.json(historyResult.rows);
    } catch (err) { res.status(500).send("Server Error fetching loan history."); }
});


// --- BRANCH MANAGEMENT ROUTES (Admin/Manager) ---
// 1. GET ALL Branches
// 1. GET ALL Branches
app.get('/api/branches', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
        // FIX: Changed to SELECT * to get 'is_active', 'address', etc.
        // FIX: Removed 'WHERE is_active = true' so Admins can see Inactive branches too.
        const result = await db.query("SELECT * FROM branches ORDER BY id ASC");
        res.json(result.rows);
    } else {
        // Manager sees only their own branch (also getting all details now)
        const result = await db.query("SELECT * FROM branches WHERE id = $1", [req.user.branchId]);
        res.json(result.rows);
    }
  } catch (err) {
    console.error("Get Branches Error:", err);
    res.status(500).send("Server Error");
  }
});

// 2. GET Single Branch
app.get('/api/branches/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await db.query("SELECT * FROM branches WHERE id = $1", [id]);
    if (result.rows.length === 0) return res.status(404).send("Branch not found.");
    res.json(result.rows[0]);
  } catch (err) { 
    res.status(500).send("Server Error"); 
  }
});

// 3. CREATE New Branch (Admin Only)
app.post('/api/branches', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { branch_name, branch_code, address, phone_number } = req.body;
    if (!branch_name || !branch_code) return res.status(400).json({ error: "Branch Name and Code are required." });

    const result = await db.query(
      "INSERT INTO branches (branch_name, branch_code, address, phone_number) VALUES ($1, $2, $3, $4) RETURNING *",
      [branch_name, branch_code, address, phone_number]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: "Branch Name or Code already exists." });
    console.error("Create Branch Error:", err);
    res.status(500).send("Server Error");
  }
});

// 4. UPDATE Branch
app.put('/api/branches/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    // ADD license_number to extraction
    const { branch_name, branch_code, address, phone_number, license_number, is_active } = req.body;

    // We must fetch existing data first if some fields are missing (Partial Update logic)
    // allowing the frontend to send only address/phone if it wants.
    const existing = await db.query("SELECT * FROM branches WHERE id = $1", [id]);
    if (existing.rows.length === 0) return res.status(404).send("Branch not found.");
    
    const old = existing.rows[0];
    
    // Fallback to existing values if new ones are undefined
    const newName = branch_name || old.branch_name;
    const newCode = branch_code || old.branch_code;
    const newAddr = address || old.address;
    const newPhone = phone_number || old.phone_number;
    const newLicense = license_number || old.license_number;
    const newActive = (is_active !== undefined) ? is_active : old.is_active;

    const result = await db.query(
      `UPDATE branches 
       SET branch_name = $1, branch_code = $2, address = $3, phone_number = $4, license_number = $5, is_active = $6 
       WHERE id = $7 RETURNING *`,
      [newName, newCode, newAddr, newPhone, newLicense, newActive, id]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update Branch Error:", err); // Added logging
    res.status(500).send("Server Error");
  }
});

// --- DASHBOARD STATS (Fixed for Multi-Branch) ---
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req); // Null (Admin All) or ID

    // 1. Update Overdue Status
    let updateQuery = "UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'";
    // Use specific branch filter if applicable to optimize
    if (targetBranch) updateQuery += ` AND branch_id = ${targetBranch}`; 
    await db.query(updateQuery);

    // 2. Build Base Filter for Counts
    let whereClause = " WHERE 1=1 "; 
    const params = [];

    if (targetBranch) {
        whereClause += ` AND branch_id = $1`;
        params.push(targetBranch);
    }

    // 3. Fetch Basic Aggregates (Parallel)
    const [
      principalRes, activeRes, overdueRes, customersRes, loansRes, paidRes, forfeitedRes, disbursedRes
    ] = await Promise.all([
      db.query(`SELECT SUM(principal_amount) FROM Loans ${whereClause} AND (status = 'active' OR status = 'overdue')`, params),
      db.query(`SELECT COUNT(*) FROM Loans ${whereClause} AND (status = 'active' OR status = 'overdue')`, params),
      db.query(`SELECT COUNT(*) FROM Loans ${whereClause} AND status = 'overdue'`, params),
      db.query(`SELECT COUNT(*) FROM Customers ${whereClause} AND is_deleted = false`, params),
      db.query(`SELECT COUNT(*) FROM Loans ${whereClause} AND status != 'deleted'`, params),
      db.query(`SELECT COUNT(*) FROM Loans ${whereClause} AND status = 'paid'`, params),
      db.query(`SELECT COUNT(*) FROM Loans ${whereClause} AND status = 'forfeited'`, params),
      db.query(`SELECT SUM(principal_amount) FROM Loans ${whereClause} AND status != 'deleted'`, params)
    ]);
    
    // 4. Calculate Total Interest Accrued (Complex Logic)
    let totalInterestAccrued = 0;
    
    // Fetch active loans to calculate their specific interest
    const loansQuery = `SELECT id, principal_amount, interest_rate, pledge_date FROM Loans ${whereClause} AND (status = 'active' OR status = 'overdue')`;
    const loansResult = await db.query(loansQuery, params);
    const activeLoans = loansResult.rows;

    if (activeLoans.length > 0) {
        const loanIds = activeLoans.map(l => l.id);
        
        // FIX: Simplified Query. We don't rely on 'params' here.
        // We just pass loanIds as the first and only argument ($1)
        const txQuery = `SELECT loan_id, amount_paid, payment_type, payment_date FROM Transactions WHERE loan_id = ANY($1::int[])`;
        const txResult = await db.query(txQuery, [loanIds]);
        const allTxs = txResult.rows; 

        const today = new Date();

        // Iterate and Calculate
        for (const loan of activeLoans) {
            const loanTxs = allTxs.filter(t => t.loan_id === loan.id);
            
            const currentPrincipal = parseFloat(loan.principal_amount);
            const rate = parseFloat(loan.interest_rate);
            const pledgeDate = new Date(loan.pledge_date);

            const disbursementTxs = loanTxs.filter(t => t.payment_type === 'disbursement');
            const interestPaid = loanTxs.filter(t => t.payment_type === 'interest').reduce((sum, t) => sum + parseFloat(t.amount_paid), 0);

            // Reconstruct timeline
            const disbursementsSum = disbursementTxs.reduce((sum, t) => sum + parseFloat(t.amount_paid), 0);
            const initialPrincipal = currentPrincipal - disbursementsSum;
            
            const events = [];
            if (initialPrincipal > 0) events.push({ amount: initialPrincipal, date: pledgeDate });
            disbursementTxs.forEach(t => events.push({ amount: parseFloat(t.amount_paid), date: new Date(t.payment_date) }));

            let totalInterestGenerated = 0;
            for (const event of events) {
                const factor = calculateTotalMonthsFactor(event.date, today);
                totalInterestGenerated += event.amount * (rate / 100) * factor;
            }

            const accrued = totalInterestGenerated - interestPaid;
            // Only add positive accrued amount (if they overpaid interest, we don't subtract it from total)
            if (accrued > 0) totalInterestAccrued += accrued;
        }
    }

    res.json({
      totalPrincipalOut: parseFloat(principalRes.rows[0].sum || 0),
      totalInterestAccrued: totalInterestAccrued,
      totalActiveLoans: parseInt(activeRes.rows[0].count || 0),
      totalOverdueLoans: parseInt(overdueRes.rows[0].count || 0),
      totalCustomers: parseInt(customersRes.rows[0].count || 0),
      totalLoans: parseInt(loansRes.rows[0].count || 0),
      totalValue: parseFloat(disbursedRes.rows[0].sum || 0),
      loansActive: parseInt(activeRes.rows[0].count || 0),
      loansOverdue: parseInt(overdueRes.rows[0].count || 0),
      loansPaid: parseInt(paidRes.rows[0].count || 0),
      loansForfeited: parseInt(forfeitedRes.rows[0].count || 0)
    });
  } catch (err) { 
    console.error("Dashboard Stats Error:", err); 
    res.status(500).send("Server Error."); 
  }
});

// --- REPORTS (Scoped) ---
app.get('/api/reports/financial-summary', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) return res.status(400).json({ error: "Start/End date required." });
    
    const targetBranch = getTargetBranchId(req);
    const params = [startDate, endDate];
    let branchClause = "";
    if (targetBranch) {
        branchClause = " AND l.branch_id = $3";
        params.push(targetBranch);
    }

    // Join with Loans table to verify branch
    const baseTxQuery = (type) => `
        SELECT SUM(t.amount_paid) as total 
        FROM Transactions t
        JOIN Loans l ON t.loan_id = l.id
        WHERE t.payment_type = ${type} 
        AND t.payment_date >= $1 AND t.payment_date <= $2
        ${branchClause}
    `;

    const principalQuery = `
        SELECT SUM(t.amount_paid) as total 
        FROM Transactions t
        JOIN Loans l ON t.loan_id = l.id
        WHERE (t.payment_type = 'principal' OR t.payment_type = 'settlement')
        AND t.payment_date >= $1 AND t.payment_date <= $2
        ${branchClause}
    `;
    
    const loansCountQuery = `
        SELECT COUNT(*) as count 
        FROM Loans l
        WHERE l.pledge_date >= $1 AND l.pledge_date <= $2
        ${targetBranch ? 'AND l.branch_id = $3' : ''}
    `;

    const [disbursedRes, interestRes, principalRepaidRes, discountRes, loansCountRes] = await Promise.all([
      db.query(baseTxQuery("'disbursement'"), params),
      db.query(baseTxQuery("'interest'"), params),
      db.query(principalQuery, params),
      db.query(baseTxQuery("'discount'"), params),
      db.query(loansCountQuery, params) 
    ]);

    const totalInterest = parseFloat(interestRes.rows[0].total || 0);
    const totalDiscount = parseFloat(discountRes.rows[0].total || 0);
    
    res.json({
      startDate,
      endDate,
      totalDisbursed: parseFloat(disbursedRes.rows[0].total || 0),
      totalInterest,
      totalPrincipalRepaid: parseFloat(principalRepaidRes.rows[0].total || 0),
      totalDiscount,
      netProfit: totalInterest - totalDiscount,
      loansCreatedCount: parseInt(loansCountRes.rows[0].count || 0) 
    });

  } catch (err) {
    res.status(500).send("Server Error");
  }
});

app.get('/api/reports/day-book', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const dateParam = req.query.date; 
    if (!dateParam) return res.status(400).json({ error: "Date is required." });

    const targetBranch = getTargetBranchId(req);
    const params = [dateParam];
    let branchClause = "";
    if (targetBranch) {
        branchClause = " AND l.branch_id = $2";
        params.push(targetBranch);
    }

    // Opening Balance
    // Sum of all INFLOW (Interest+Principal) - OUTFLOW (Disbursement) before this date
    // Scoped by branch
    const openingBalanceQuery = `
      SELECT 
        SUM(CASE WHEN t.payment_type IN ('interest', 'principal', 'settlement') THEN t.amount_paid ELSE 0 END) -
        SUM(CASE WHEN t.payment_type = 'disbursement' THEN t.amount_paid ELSE 0 END) as balance
      FROM Transactions t
      JOIN Loans l ON t.loan_id = l.id
      WHERE (t.payment_date AT TIME ZONE 'Asia/Kolkata')::date < $1::date
      ${branchClause}
    `;
    
    const dayTransactionsQuery = `
      SELECT t.*, l.book_loan_number, c.name as customer_name 
      FROM Transactions t
      JOIN Loans l ON t.loan_id = l.id
      JOIN Customers c ON l.customer_id = c.id
      WHERE (t.payment_date AT TIME ZONE 'Asia/Kolkata')::date = $1::date 
      AND t.payment_type != 'discount'
      ${branchClause}
      ORDER BY t.payment_date ASC
    `;

    const [openingRes, dayRes] = await Promise.all([
      db.query(openingBalanceQuery, params),
      db.query(dayTransactionsQuery, params)
    ]);

    res.json({
      date: dateParam,
      openingBalance: parseFloat(openingRes.rows[0].balance || 0),
      transactions: dayRes.rows
    });

  } catch (err) {
    console.error("Day Book Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// --- RECYCLE BIN ---
// Admin sees all. Manager sees their branch deleted items.
app.get('/api/recycle-bin/deleted', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);
    const params = [];
    let custWhere = " WHERE is_deleted = true";
    let loanWhere = " WHERE l.status = 'deleted' AND c.is_deleted = false";
    
    if (targetBranch) {
        custWhere += " AND branch_id = $1";
        loanWhere += " AND l.branch_id = $1";
        params.push(targetBranch);
    }

    const [deletedCustomers, deletedLoans] = await Promise.all([
      db.query(`SELECT id, name, phone_number, 'Customer' as type FROM Customers ${custWhere}`, params),
      db.query(`SELECT l.id, l.book_loan_number, c.name as customer_name, 'Loan' as type FROM Loans l JOIN Customers c ON l.customer_id = c.id ${loanWhere}`, params)
    ]);
    res.json({ customers: deletedCustomers.rows, loans: deletedLoans.rows });
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/customers/:id/restore', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    
    // Check branch
    const check = await db.query("SELECT branch_id FROM Customers WHERE id=$1", [id]);
    if (check.rows.length === 0) return res.status(404).send("Not found");
    if (req.user.role !== 'admin' && check.rows[0].branch_id !== req.user.branchId) return res.status(403).send("Denied");

    const restoreCustomerResult = await db.query("UPDATE Customers SET is_deleted = false WHERE id = $1 RETURNING id, name", [id]);
    await db.query("UPDATE Loans SET status = 'paid' WHERE customer_id = $1 AND status = 'deleted'", [id]);
    res.json({ message: `Customer '${restoreCustomerResult.rows[0].name}' restored.` });
  } catch (err) { res.status(500).send("Server Error"); }
});

app.delete('/api/customers/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    // Permanent Delete is Admin Only (Safety)
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
        res.json({ message: `Customer '${deleteCustomerResult.rows[0].name}' permanently deleted.` });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("PERMANENT DELETE Customer Error:", err.message);
        res.status(500).send("Server Error during permanent deletion.");
    } finally { client.release(); }
});

app.post('/api/loans/:id/restore', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    // Branch check
    const check = await db.query("SELECT branch_id FROM Loans WHERE id=$1", [id]);
    if (check.rows.length === 0) return res.status(404).send("Not found");
    if (req.user.role !== 'admin' && check.rows[0].branch_id !== req.user.branchId) return res.status(403).send("Denied");

    const customerCheck = await db.query("SELECT c.is_deleted FROM Customers c JOIN Loans l ON l.customer_id = c.id WHERE l.id = $1", [id]);
    if (customerCheck.rows[0].is_deleted) return res.status(400).json({ error: "Cannot restore loan. Customer is deleted." });
    
    const restoreLoanResult = await db.query("UPDATE Loans SET status = 'paid' WHERE id = $1 AND status = 'deleted' RETURNING id, book_loan_number", [id]);
    res.json({ message: `Loan #${restoreLoanResult.rows[0].book_loan_number} restored.` });
  } catch (err) { res.status(500).send("Server Error"); }
});

app.delete('/api/loans/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    // Permanent Delete is Admin Only
    const { id } = req.params;
    const loanId = parseInt(id);
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
        res.status(500).send("Server Error");
    } finally { client.release(); }
});

// --- RENEW ---
app.post('/api/loans/:id/renew', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  const oldLoanId = parseInt(req.params.id);
  const { interestPaid, newBookLoanNumber, newInterestRate } = req.body;

  if (isNaN(oldLoanId)) return res.status(400).json({ error: "Invalid Loan ID." });
  if (!newBookLoanNumber) return res.status(400).json({ error: "New Book Loan Number is required." });

  try {
    await client.query('BEGIN');
    
    // Fetch old loan (lock it)
    const oldLoanRes = await client.query(`
      SELECT l.*, pi.item_type, pi.description, pi.quality, 
             pi.weight, pi.gross_weight, pi.net_weight, pi.purity, l.appraised_value, pi.item_image_data
      FROM Loans l 
      JOIN PledgedItems pi ON l.id = pi.loan_id 
      WHERE l.id = $1 FOR UPDATE`, [oldLoanId]);

    if (oldLoanRes.rows.length === 0) throw new Error("Loan not found.");
    const oldLoan = oldLoanRes.rows[0];

    // Branch Access Check
    if (req.user.role !== 'admin' && oldLoan.branch_id !== req.user.branchId) {
        throw new Error("Access Denied. Cannot renew loan of another branch.");
    }

    if (oldLoan.status !== 'active' && oldLoan.status !== 'overdue') throw new Error("Can only renew Active or Overdue loans.");

    const txRes = await client.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [oldLoanId]);
    const transactions = txRes.rows;

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
    const payingNow = parseFloat(interestPaid) || 0;
    const unpaidInterest = outstandingInterest - payingNow;
    const interestToCapitalize = unpaidInterest > 0 ? unpaidInterest : 0;
    const newPrincipalAmount = currentPrincipalTotal + interestToCapitalize;

    if (payingNow > 0) {
        await client.query(
            "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)",
            [oldLoanId, payingNow, username]
        );
    }
    
    await client.query("UPDATE Loans SET status = 'renewed', closed_date = NOW() WHERE id = $1", [oldLoanId]);

    const newRate = newInterestRate || oldLoan.interest_rate;
    // IMPORTANT: New Loan inherits the SAME Branch ID
    const newLoanQuery = `
      INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number, appraised_value, pledge_date, due_date, branch_id) 
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '1 year', $6) 
      RETURNING id`;
      
    const newLoanRes = await client.query(newLoanQuery, [
        oldLoan.customer_id, 
        newPrincipalAmount, 
        newRate, 
        newBookLoanNumber, 
        oldLoan.appraised_value || 0,
        oldLoan.branch_id // Preserve Branch
    ]);
    const newLoanId = newLoanRes.rows[0].id;

    const itemQuery = `
      INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, gross_weight, net_weight, purity, item_image_data)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `;
    await client.query(itemQuery, [
        newLoanId, oldLoan.item_type, oldLoan.description, oldLoan.quality, 
        oldLoan.weight, oldLoan.gross_weight, oldLoan.net_weight, oldLoan.purity, oldLoan.item_image_data
    ]);

    let logMsg = `Renewed from #${oldLoan.book_loan_number}.`;
    if (interestToCapitalize > 0) logMsg += ` Principal increased by ₹${interestToCapitalize.toFixed(2)} (Unpaid Interest).`;
    
    await client.query(
        "INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username) VALUES ($1, 'renewal', $2, $3, $4)",
        [newLoanId, logMsg, 'Active', username] 
    );

    await client.query('COMMIT');
    res.json({ message: `Renewed! New Principal: ₹${newPrincipalAmount.toFixed(2)}`, newLoanId: newLoanId });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Renewal Error:", err.message);
    if (err.code === '23505') return res.status(400).json({ error: "New Book Loan Number already exists." });
    res.status(500).json({ error: err.message });
  } finally { client.release(); }
});

// --- SETTINGS (Admin Only) ---
app.get('/api/settings', async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM business_settings WHERE id = 1");
    if (result.rows.length > 0) { res.json(result.rows[0]); } 
    else { res.json({ business_name: 'Sri KuberaLakshmi Bankers' }); }
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

app.put('/api/settings', authenticateToken, authorizeAdmin, upload.single('logo'), async (req, res) => {
  try {
    const { business_name, address, phone_number, license_number, navbar_display_mode } = req.body;
    let logoUrl = req.body.existingLogoUrl;

    if (req.file) {
      const b64 = req.file.buffer.toString('base64');
      const mime = req.file.mimetype;
      logoUrl = `data:${mime};base64,${b64}`;
    }

    const displayMode = navbar_display_mode || 'both';

    const query = `
      INSERT INTO business_settings (id, business_name, address, phone_number, license_number, logo_url, navbar_display_mode, updated_at)
      VALUES (1, $1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (id) DO UPDATE 
      SET business_name = $1, address = $2, phone_number = $3, license_number = $4, logo_url = $5, navbar_display_mode = $6, updated_at = NOW()
      RETURNING *
    `;
    
    const result = await db.query(query, [business_name, address, phone_number, license_number, logoUrl, displayMode]);
    res.json(result.rows[0]);

  } catch (err) {
    res.status(500).send("Server Error");
  }
});

// --- SMART SEARCH (Scoped) ---
app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim() === '') return res.json([]);
    const cleanQuery = `%${q.trim()}%`; 

    const targetBranch = getTargetBranchId(req);
    const params = [cleanQuery];
    
    let loanSql = `SELECT id, book_loan_number, principal_amount, branch_id FROM Loans WHERE book_loan_number ILIKE $1 AND status != 'deleted'`;
    let custSql = `SELECT id, name, phone_number, branch_id FROM Customers WHERE (name ILIKE $1 OR phone_number ILIKE $1) AND is_deleted = false`;

    if (targetBranch) {
        loanSql += ` AND branch_id = $2`;
        custSql += ` AND branch_id = $2`;
        params.push(targetBranch);
    }
    
    const [loanRes, custRes] = await Promise.all([
      db.query(loanSql + " LIMIT 3", params),
      db.query(custSql + " LIMIT 5", params)
    ]);

    const results = [];
    loanRes.rows.forEach(loan => {
      results.push({
        type: 'loan',
        id: loan.id,
        title: `Loan #${loan.book_loan_number}`,
        subtitle: `₹${loan.principal_amount}`
      });
    });
    custRes.rows.forEach(cust => {
      results.push({
        type: 'customer',
        id: cust.id,
        title: cust.name,
        subtitle: cust.phone_number
      });
    });

    res.json(results);
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
