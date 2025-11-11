const express = require('express');
const db = require('./db');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// --- ⭐ 1. CONFIGURE CORS FOR PRODUCTION ---
// List of allowed origins (your frontend URLs)
const allowedOrigins = [
  'http://localhost:3000', // For local development
  'https://pledge-loan-frontend.onrender.com',
  'exp://192.168.29.6:8081'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or Postman)
    if (!origin) return callback(null, true);
    
    // Check if the origin is in our allowed list
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));
// --- END CORS CONFIG ---

app.use(express.json());

// --- ⭐ 2. USE RENDER'S PORT ---
// Render provides its port via the PORT environment variable
const PORT = process.env.PORT || 3001; 
// --- END PORT FIX ---

const JWT_SECRET = process.env.JWT_SECRET || 'a-very-strong-secret-key-that-you-should-change';

// --- MULTER CONFIGURATION (Using memoryStorage for BYTEA storage) ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verification Error:", err.message); // Log JWT errors
      return res.sendStatus(403); // Forbidden (token is invalid)
    }
    req.user = user;
    next();
  });
};

// --- NEW: AUTHENTICATION MIDDLEWARE FOR ADMINS ---
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403); // 403 Forbidden
  }
  next();
};

// --- UTILITY ROUTE (Public) ---
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
    if (!username || !password) {
      return res.status(400).send('Username and password are required.');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // --- ⭐ FIX: Changed 'Users' to 'users' ---
    const newUser = await db.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username",
      [username, hashedPassword]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).send('Username already exists.');
    }
    console.error("Registration Error:", err.message);
    res.status(500).send('Server error during registration.');
  }
});

// --- USER MANAGEMENT ROUTES (Admin Only) ---

// 1. Get all users
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    // Select all users but EXCLUDE their passwords
    const users = await db.query("SELECT id, username, role FROM users ORDER BY id ASC");
    res.json(users.rows);
  } catch (err) {
    console.error("GET Users Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// 2. Create a new staff user
app.post('/api/users/staff', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send('Username and password are required.');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Explicitly set the role as 'staff'
    const newUser = await db.query(
      "INSERT INTO users (username, password, role) VALUES ($1, $2, 'staff') RETURNING id, username, role",
      [username, hashedPassword]
    );
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') { // Handle duplicate username
      return res.status(400).send('Username already exists.');
    }
    console.error("Create Staff Error:", err.message);
    res.status(500).send('Server error during staff creation.');
  }
});

// 3. Change any user's password
app.put('/api/users/change-password', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) {
      return res.status(400).send('User ID and new password are required.');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    const result = await db.query(
      "UPDATE users SET password = $1 WHERE id = $2 RETURNING id, username",
      [hashedPassword, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('User not found.');
    }

    res.status(200).json({ message: `Password for ${result.rows[0].username} updated successfully.` });
  } catch (err) {
    console.error("Change Password Error:", err.message);
    res.status(500).send('Server error changing password.');
  }
});

// 4. Delete a staff user
app.delete('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = parseInt(id);

    if (isNaN(userId)) {
      return res.status(400).send('Invalid user ID.');
    }

    // Safety check: Do not allow an admin to delete their own account via this route
    if (userId === req.user.userId) {
      return res.status(400).send('Admin users cannot delete their own account.');
    }

    // Only allow deleting staff members
    const result = await db.query("DELETE FROM users WHERE id = $1 AND role = 'staff' RETURNING id, username", [userId]);

    if (result.rows.length === 0) {
      return res.status(404).send('Staff user not found or user is not a staff member.');
    }

    res.status(200).json({ message: `Staff user ${result.rows[0].username} deleted successfully.` });
  } catch (err) {
    console.error("Delete Staff Error:", err.message);
    res.status(500).send('Server error deleting user.');
  }
});

// --- END USER MANAGEMENT ROUTES ---

// --- This is the corrected login route ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).send('Username and password are required.');
    }

    const userResult = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (userResult.rows.length === 0) {
      return res.status(401).send('Invalid credentials.');
    }
    const user = userResult.rows[0];

    // Use the correct 'password' column from your file
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) {
      return res.status(401).send('Invalid credentials.');
    }

    console.log("BACKEND: Creating token for user:", user.username, "with role:", user.role);

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '30d' } // <-- FIX 1: Set to 30 days
    );

    // --- FIX 2: Send both the token AND the user object ---
    res.json({ 
        token: token,
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    });

  } catch (err) {
    console.error("Login Error:", err.message);
    res.status(500).send('Server error during login.');
  }
});

// --- CUSTOMER ROUTES (Protected) ---
// (No changes needed below this line, but including the full file)
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const allCustomers = await db.query("SELECT id, name, phone_number, address FROM Customers ORDER BY name ASC");
    res.json(allCustomers.rows);
  } catch (err) { console.error("GET Customers Error:", err.message); res.status(500).send("Server Error"); }
});

app.get('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });
    const customerResult = await db.query("SELECT * FROM Customers WHERE id = $1", [id]);
    if (customerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
    const customer = customerResult.rows[0];
    if (customer.customer_image_url) {
      const imageBase64 = customer.customer_image_url.toString('base64');
      let mimeType = 'image/jpeg'; 
      if (imageBase64.startsWith('/9j/')) mimeType = 'image/jpeg';
      else if (imageBase64.startsWith('iVBORw0KGgo')) mimeType = 'image/png';
      customer.customer_image_url = `data:${mimeType};base64,${imageBase64}`;
    }
    res.json(customer);
  } catch (err) {
    console.error("GET Customer Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.post('/api/customers', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address } = req.body;
    const imageBuffer = req.file ? req.file.buffer : null;
    if (!name || !phone_number) return res.status(400).json({ error: 'Name and phone are required.' });
    const newCustomerResult = await db.query(
      "INSERT INTO Customers (name, phone_number, address, customer_image_url) VALUES ($1, $2, $3, $4) RETURNING id, name, phone_number, address",
      [name, phone_number, address, imageBuffer]
    );
    res.status(201).json(newCustomerResult.rows[0]);
  } catch (err) {
    console.error("POST Customer Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.put('/api/customers/:id', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });
        const { name, phone_number, address } = req.body;
        let imageBuffer = null;
        let updateImage = false;

        if (req.file) { imageBuffer = req.file.buffer; updateImage = true; }
        else if (req.body.removeCurrentImage === 'true') { imageBuffer = null; updateImage = true; }

        let query; let values;
        if (updateImage) {
            query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3, customer_image_url = $4 WHERE id = $5 RETURNING id, name, phone_number, address";
            values = [name, phone_number, address, imageBuffer, id];
        } else {
            query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3 WHERE id = $4 RETURNING id, name, phone_number, address";
            values = [name, phone_number, address, id];
        }
        const updateCustomerResult = await db.query(query, values);
        if (updateCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
        res.json(updateCustomerResult.rows[0]);
    } catch (err) { console.error("PUT Customer Error:", err.message); res.status(500).send("Server Error"); }
});

// --- LOAN ROUTES (Protected & Ordered Correctly) ---
app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    const query = `
      SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status,
             c.name AS customer_name, c.phone_number
      FROM Loans l JOIN Customers c ON l.customer_id = c.id
      WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited')
      ORDER BY l.pledge_date DESC`; 
    const allLoans = await db.query(query);
    res.json(allLoans.rows);
  } catch (err) {
    console.error("GET All Loans Error:", err.message);
    if (err.detail) console.error("DB Error Detail:", err.detail); 
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/recent/created', authenticateToken, async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) {
    console.error("Recent Created Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/recent/closed', authenticateToken, async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'paid' ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) {
    console.error("Recent Closed Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/overdue', authenticateToken, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    const query = `
      SELECT l.id, l.due_date, c.name AS customer_name, l.principal_amount, l.book_loan_number, l.pledge_date
      FROM Loans l JOIN Customers c ON l.customer_id = c.id
      WHERE l.status = 'overdue'
      ORDER BY l.due_date ASC`;
    const overdueLoans = await db.query(query);
    res.json(overdueLoans.rows);
  } catch (err) {
    console.error("OVERDUE LOANS API ERROR:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/find-by-book-number/:bookNumber', authenticateToken, async (req, res) => {
  try {
    const { bookNumber } = req.params;
    const result = await db.query("SELECT id FROM Loans WHERE book_loan_number = $1", [bookNumber]);
    if (result.rows.length === 0) return res.status(404).json({ error: "No loan found." });
    res.json({ loanId: result.rows[0].id });
  } catch (err) {
    console.error("Find Loan Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.post('/api/loans/:id/add-principal', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { additionalAmount } = req.body;
  const loanId = parseInt(id);
  const amountToAdd = parseFloat(additionalAmount);
  if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid loan ID." });
  if (isNaN(amountToAdd) || amountToAdd <= 0) return res.status(400).json({ error: "Invalid additional amount specified." });
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
    await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date) VALUES ($1, $2, $3, NOW())", [loanId, amountToAdd, 'disbursement']);
    await client.query('COMMIT');
    res.json({ message: `Successfully added ₹${amountToAdd.toFixed(2)}. New principal is ₹${newPrincipal.toFixed(2)}.`, loan: updateResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK'); console.error("Add Principal Error:", err.message); res.status(500).send("Server Error.");
  } finally { client.release(); }
});

app.get('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    await db.query("UPDATE Loans SET status = 'overdue' WHERE id = $1 AND due_date < NOW() AND status = 'active'", [id]);
    const loanQuery = ` SELECT l.*, pi.item_type, pi.description, pi.quality, pi.weight, pi.item_image_data, c.name AS customer_name, c.phone_number, c.customer_image_url FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id JOIN Customers c ON l.customer_id = c.id WHERE l.id = $1`;
    const loanResult = await db.query(loanQuery, [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    let loanDetails = loanResult.rows[0];
    if (loanDetails.item_image_data) { const ib64 = loanDetails.item_image_data.toString('base64'); let mt = 'image/jpeg'; if (ib64.startsWith('/9j/')) mt = 'image/jpeg'; else if (ib64.startsWith('iVBORw0KGgo')) mt = 'image/png'; loanDetails.item_image_data_url = `data:${mt};base64,${ib64}`; } delete loanDetails.item_image_data;
    if (loanDetails.customer_image_url) { const cb64 = loanDetails.customer_image_url.toString('base64'); let mt = 'image/jpeg'; if (cb64.startsWith('/9j/')) mt = 'image/jpeg'; else if (cb64.startsWith('iVBORw0KGgo')) mt = 'image/png'; loanDetails.customer_image_url = `data:${mt};base64,${cb64}`; }
    const transactionsResult = await db.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date DESC", [id]);
    res.json({ loanDetails: loanDetails, transactions: transactionsResult.rows });
  } catch (err) { console.error("GET Loan Details Error:", err.message); res.status(500).send("Server Error"); }
});

app.post('/api/loans', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
  const client = await db.pool.connect();
  try {
    const { customer_id, principal_amount, interest_rate, book_loan_number, item_type, description, quality, weight, deductFirstMonthInterest } = req.body;
    const itemImageBuffer = req.file ? req.file.buffer : null;
    const principal = parseFloat(principal_amount);
    const rate = parseFloat(interest_rate); 

    if (!customer_id || isNaN(principal) || principal <= 0 || isNaN(rate) || rate <= 0 || !book_loan_number || !item_type || !description) {
         return res.status(400).send("Missing or invalid required loan/item fields (customer, principal, rate, book#, type, description).");
    }

    await client.query('BEGIN');
    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number) VALUES ($1, $2, $3, $4) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal, rate, book_loan_number]);
    const newLoanId = loanResult.rows[0].id;

    const itemQuery = `INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, item_image_data) VALUES ($1, $2, $3, $4, $5, $6)`;
    await client.query(itemQuery, [newLoanId, item_type, description, quality, weight, itemImageBuffer]);
    
    if (deductFirstMonthInterest === 'true') {
      console.log(`Loan ${newLoanId}: Deducting first month's interest.`);
      const firstMonthInterest = principal * (rate / 100);
      if (firstMonthInterest > 0) {
        const interestTxQuery = `
          INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date)
          VALUES ($1, $2, 'interest', NOW())
        `;
        await client.query(interestTxQuery, [newLoanId, firstMonthInterest]);
        console.log(`Loan ${newLoanId}: Logged pre-paid interest of ₹${firstMonthInterest}.`);
      }
    }

    await client.query('COMMIT');
    res.status(201).json({ message: "Loan created successfully", loanId: newLoanId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("POST Loan Error:", err.message);
    if (err.code === '23505') return res.status(400).send("Error: Book Loan Number already exists.");
    res.status(500).send("Server Error while creating loan");
  } finally { client.release(); }
});

app.get('/api/customers/:id/loans', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
     if (isNaN(id)) return res.status(400).json({ error: "Invalid customer ID." });
    await db.query("UPDATE Loans SET status = 'overdue' WHERE customer_id = $1 AND due_date < NOW() AND status = 'active'", [id]);
    const query = ` SELECT l.id AS loan_id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status, pi.description FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id WHERE l.customer_id = $1 ORDER BY l.pledge_date DESC`;
    const customerLoans = await db.query(query, [id]);
    res.json(customerLoans.rows);
  } catch (err) { console.error("GET Customer Loans Error:", err.message); res.status(500).send("Server Error"); }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const { loan_id, amount_paid, payment_type } = req.body;
    if (!loan_id || !amount_paid || parseFloat(amount_paid) <= 0) { return res.status(400).json({ error: 'Valid Loan ID and positive amount required.' }); }
    const validPaymentTypes = ['interest', 'principal'];
    const finalPaymentType = validPaymentTypes.includes(payment_type) ? payment_type : 'payment';
    const newTransaction = await db.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type) VALUES ($1, $2, $3) RETURNING *", [loan_id, amount_paid, finalPaymentType]);
    res.status(201).json(newTransaction.rows[0]);
  } catch (err) {
    console.error("POST Transaction Error:", err.message);
    if (err.code === '23503') { return res.status(404).json({ error: 'Loan not found.' }); }
    res.status(500).send("Server Error");
  }
});

app.post('/api/loans/:id/settle', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { discountAmount } = req.body;
    const loanId = parseInt(id);
    if (isNaN(loanId)) return res.status(400).json({ error: "Invalid loan ID." });

    const discount = parseFloat(discountAmount) || 0;

    const loanQuery = `SELECT principal_amount, pledge_date, status, interest_rate FROM Loans WHERE id = $1`;
    const loanResult = await db.query(loanQuery, [loanId]);

    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    const loan = loanResult.rows[0];

    if (loan.status !== 'active' && loan.status !== 'overdue') {
        return res.status(400).json({ error: `Cannot settle a loan with status '${loan.status}'.` });
    }

    const currentPrincipalTotal = parseFloat(loan.principal_amount);
    const monthlyInterestRatePercent = parseFloat(loan.interest_rate);
    const pledgeDate = new Date(loan.pledge_date);
    const today = new Date();

    if (isNaN(monthlyInterestRatePercent) || monthlyInterestRatePercent <= 0) {
        console.error(`Loan ID ${loanId}: Invalid stored interest rate.`);
        return res.status(500).json({ error: "Internal error: Invalid interest rate." });
    }

    const calculateTotalMonthsFactor = (startDate, endDate, isInitialPrincipal) => {
        if (endDate <= startDate) return 0;
        let fullMonthsPassed = 0;
        let tempDate = new Date(startDate);
        while (true) {
            const nextMonth = tempDate.getMonth() + 1;
            tempDate.setMonth(nextMonth);
            if (tempDate.getMonth() !== (nextMonth % 12)) tempDate.setDate(0); 
            if (tempDate <= endDate) { fullMonthsPassed++; }
            else { tempDate.setMonth(tempDate.getMonth() - 1); break; }
        }
        const oneDay = 1000 * 60 * 60 * 24;
        const remainingDays = Math.floor((endDate.getTime() - tempDate.getTime()) / oneDay);
        let partialFraction = 0; let totalMonthsFactor;
        if (fullMonthsPassed === 0) { totalMonthsFactor = 1.0; }
        else { if (remainingDays > 0) { partialFraction = (remainingDays <= 15) ? 0.5 : 1.0; } totalMonthsFactor = fullMonthsPassed + partialFraction; }
        if (totalMonthsFactor === 0 && (endDate.getTime() > startDate.getTime())) { totalMonthsFactor = 0.5; }
        return totalMonthsFactor;
    };

    const disbursementsResult = await db.query(
      "SELECT amount_paid, payment_date FROM Transactions WHERE loan_id = $1 AND payment_type = 'disbursement' ORDER BY payment_date ASC", 
      [loanId]
    );

    const subsequentDisbursementsSum = disbursementsResult.rows.reduce((sum, tx) => sum + parseFloat(tx.amount_paid), 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum;

    let disbursementEvents = [];
    if (initialPrincipal > 0) {
        disbursementEvents.push({ amount: initialPrincipal, date: pledgeDate, isInitial: true });
    }
    disbursementEvents = disbursementEvents.concat(
        disbursementsResult.rows.map(row => ({
            amount: parseFloat(row.amount_paid),
            date: new Date(row.payment_date),
            isInitial: false
        }))
    );
    
    let totalInterest = 0;
    let maxMonthsFactor = 0; 
    for (const event of disbursementEvents) {
        if (event.amount <= 0) continue;
        const monthsFactor = calculateTotalMonthsFactor(event.date, today, event.isInitial);
        const monthlyInterestRateDecimal = monthlyInterestRatePercent / 100;
        totalInterest += event.amount * monthlyInterestRateDecimal * monthsFactor;
        if (event.isInitial) maxMonthsFactor = monthsFactor; 
    }
    
    const totalMonthsFactorReport = maxMonthsFactor > 0 ? maxMonthsFactor : calculateTotalMonthsFactor(pledgeDate, today, true);
    const totalOwed = currentPrincipalTotal + totalInterest;
    const transactionsResult = await db.query("SELECT SUM(amount_paid) AS total_paid FROM Transactions WHERE loan_id = $1 AND payment_type != 'disbursement'", [loanId]);
    const totalPaid = parseFloat(transactionsResult.rows[0].total_paid) || 0;
    const finalBalance = totalOwed - totalPaid - discount;

    if (finalBalance > 1) {
        return res.status(400).json({
            error: `Cannot close loan. Owed: ₹${totalOwed.toFixed(2)} (Interest: ₹${totalInterest.toFixed(2)} based on ${totalMonthsFactorReport} months @ ${monthlyInterestRatePercent}% p.m.), Paid: ₹${totalPaid.toFixed(2)}, Discount: ₹${discount.toFixed(2)}. Outstanding balance: ₹${finalBalance.toFixed(2)}.`
        });
    }

    const closeLoan = await db.query("UPDATE Loans SET status = 'paid' WHERE id = $1 RETURNING *", [loanId]);
    res.json({ message: `Loan successfully closed. Total Interest: ₹${totalInterest.toFixed(2)} (for ${totalMonthsFactorReport} months @ ${monthlyInterestRatePercent}% p.m.), Discount: ₹${discount.toFixed(2)}.`, loan: closeLoan.rows[0] });

  } catch (err) {
    console.error("Settle Loan Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.put('/api/loans/:id', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    const username = req.user.username; 

    const {
        book_loan_number, interest_rate, pledge_date, due_date,
        item_type, description, quality, weight
    } = req.body;
    const newItemImageBuffer = req.file ? req.file.buffer : undefined;
    const removeItemImage = req.body.removeItemImage === 'true';

    if (isNaN(loanId) || loanId <= 0) {
        return res.status(400).json({ error: "Invalid loan ID." });
    }

    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');

        const currentDataQuery = `
            SELECT
                l.book_loan_number, l.interest_rate, l.pledge_date, l.due_date,
                pi.id AS item_id, pi.item_type, pi.description, pi.quality, pi.weight, pi.item_image_data
            FROM "loans" l
            LEFT JOIN "pledgeditems" pi ON l.id = pi.loan_id
            WHERE l.id = $1
            FOR UPDATE OF l;
        `;
        const currentResult = await client.query(currentDataQuery, [loanId]);

        if (currentResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: "Loan not found." });
        }
        const oldData = currentResult.rows[0];
        const itemId = oldData.item_id;

        const historyLogs = [];
        const loanUpdateFields = [];
        const loanUpdateValues = [];
        const itemUpdateFields = [];
        const itemUpdateValues = [];

        const addUpdate = (table, field, newValue, oldValue, fieldsArray, valuesArray, logLabel = field) => {
            if (newValue === undefined) {
                return;
            }
            let oldValCompare, newValCompare;
            const dateFields = ['pledge_date', 'due_date'];
            if (dateFields.includes(field)) {
                if (newValue === "" || newValue === null) {
                    newValCompare = null;
                } else {
                    newValCompare = newValue; 
                }
                if (oldValue === null || oldValue === undefined) {
                    oldValCompare = null;
                } else {
                    const d = new Date(oldValue);
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    oldValCompare = `${year}-${month}-${day}`;
                }
            } else {
                oldValCompare = oldValue;
                newValCompare = newValue;
                if (typeof oldValue === 'number' || !isNaN(parseFloat(oldValue))) {
                    oldValCompare = parseFloat(oldValue);
                    newValCompare = parseFloat(newValue);
                    if (oldValue === null) oldValCompare = null;
                    if (newValue === null) newValCompare = null;
                }
            }
            
            if (newValCompare !== oldValCompare) {
                let dbValue = newValue;
                if (dateFields.includes(field) && (newValue === "" || newValue === null)) {
                    dbValue = null; 
                }
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

        if (itemId) {
            addUpdate('pledgeditems', 'item_type', item_type, oldData.item_type, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'description', description, oldData.description, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'quality', quality, oldData.quality, itemUpdateFields, itemUpdateValues);
            addUpdate('pledgeditems', 'weight', weight, oldData.weight, itemUpdateFields, itemUpdateValues);

            if (newItemImageBuffer !== undefined || removeItemImage) {
                const finalImageValue = removeItemImage ? null : newItemImageBuffer;
                itemUpdateFields.push(`"item_image_data"`);
                itemUpdateValues.push(finalImageValue);
                historyLogs.push({
                    loan_id: loanId, field_changed: 'item_image', old_value: oldData.item_image_data ? '[Image Data]' : '[No Image]', new_value: finalImageValue ? '[New Image Data]' : '[Image Removed]', changed_by_username: username
                });
            }
        }

        if (loanUpdateFields.length > 0) {
            const loanSetClause = loanUpdateFields.map((field, i) => `${field} = $${i + 1}`).join(', ');
            loanUpdateValues.push(loanId); 
            const loanUpdateQuery = `UPDATE "loans" SET ${loanSetClause} WHERE id = $${loanUpdateValues.length}`;
            console.log("Executing Loan Update:", loanUpdateQuery);
            console.log("With values:", loanUpdateValues);
            await client.query(loanUpdateQuery, loanUpdateValues);
        }

        if (itemUpdateFields.length > 0 && itemId) {
            const itemSetClause = itemUpdateFields.map((field, i) => `${field} = $${i + 1}`).join(', ');
            itemUpdateValues.push(itemId); 
            const itemUpdateQuery = `UPDATE "pledgeditems" SET ${itemSetClause} WHERE id = $${itemUpdateValues.length}`;
            console.log("Executing Item Update:", itemUpdateQuery);
            console.log("With values:", itemUpdateValues);
            await client.query(itemUpdateQuery, itemUpdateValues);
        }

        if (historyLogs.length > 0) {
            const historyInsertQuery = `
                INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username)
                VALUES ($1, $2, $3, $4, $5)
            `;
            for (const log of historyLogs) {
                await client.query(historyInsertQuery, [log.loan_id, log.field_changed, log.old_value, log.new_value, log.changed_by_username]);
            }
            console.log(`Logged ${historyLogs.length} changes for loan ${loanId}`);
        }

        await client.query('COMMIT');
        res.json({ message: `Loan ${loanId} updated successfully. ${historyLogs.length} changes logged.` });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(`Error updating loan ${loanId}:`, err.message);
        if (err.code === '23505' && err.constraint === 'loans_book_loan_number_key') {
             return res.status(400).json({ error: "Book Loan Number already exists." });
        }
        res.status(500).send("Server Error while updating loan.");
    } finally {
        client.release();
    }
});

app.get('/api/loans/:id/history', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);

    if (isNaN(loanId) || loanId <= 0) {
        return res.status(400).json({ error: "Invalid loan ID." });
    }

    try {
        const historyQuery = `
            SELECT field_changed, old_value, new_value, changed_at, changed_by_username
            FROM loan_history
            WHERE loan_id = $1
            ORDER BY changed_at DESC;
        `;
        const historyResult = await db.query(historyQuery, [loanId]);
        res.json(historyResult.rows);
    } catch (err) {
        console.error(`Error fetching history for loan ${loanId}:`, err.message);
        res.status(500).send("Server Error fetching loan history.");
    }
});

// --- DASHBOARD ROUTES (Protected) ---
// --- ⭐ CHANGED: Added authorizeAdmin to protect this route ---
// --- DASHBOARD ROUTES (Protected) ---
app.get('/api/dashboard/stats', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");

    // 1. Queries for the React Web App
    const principalPromise = db.query(
      "SELECT SUM(principal_amount) FROM Loans WHERE status = 'active' OR status = 'overdue'"
    );
    const activeLoansPromise = db.query(
      "SELECT COUNT(*) FROM Loans WHERE status = 'active' OR status = 'overdue'"
    );
    const overdueLoansPromise = db.query(
      "SELECT COUNT(*) FROM Loans WHERE status = 'overdue'"
    );
    const interestThisMonthPromise = db.query(
      "SELECT SUM(amount_paid) FROM Transactions WHERE payment_type = 'interest' AND payment_date >= date_trunc('month', CURRENT_DATE)"
    );

    // 2. NEW Queries for the Flutter Mobile App
    const totalCustomersPromise = db.query("SELECT COUNT(*) FROM Customers");
    const totalLoansPromise = db.query("SELECT COUNT(*) FROM Loans"); // Counts *all* loans

    // 3. Wait for ALL queries to finish
    const [
      principalResult,
      activeLoansResult,
      overdueLoansResult,
      interestThisMonthResult,
      totalCustomersResult, // New result
      totalLoansResult      // New result
    ] = await Promise.all([
      principalPromise,
      activeLoansPromise,
      overdueLoansPromise,
      interestThisMonthPromise,
      totalCustomersPromise, // New query
      totalLoansPromise      // New query
    ]);

    // 4. Build the combined stats object
    const stats = {
      // --- Keys for React Web App ---
      totalPrincipalOut: parseFloat(principalResult.rows[0].sum) || 0,
      totalActiveLoans: parseInt(activeLoansResult.rows[0].count) || 0,
      totalOverdueLoans: parseInt(overdueLoansResult.rows[0].count) || 0,
      interestCollectedThisMonth: parseFloat(interestThisMonthResult.rows[0].sum) || 0,

      // --- New Keys for Flutter Mobile App ---
      totalCustomers: parseInt(totalCustomersResult.rows[0].count) || 0,
      totalLoans: parseInt(totalLoansResult.rows[0].count) || 0,
      totalValue: parseFloat(principalResult.rows[0].sum) || 0 // Re-using the same value as 'totalPrincipalOut'
    };

    res.json(stats);

  } catch (err) {
    console.error("Dashboard Stats Error:", err.message);
    res.status(500).send("Server Error while fetching dashboard stats.");
  }
});

// --- START THE SERVER ---
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});