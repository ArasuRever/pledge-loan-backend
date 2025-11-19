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
    totalMonthsFactor = 1.0; // Minimum 1 month
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

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password are required.');
    const userResult = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (userResult.rows.length === 0) return res.status(401).send('Invalid credentials.');
    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) return res.status(401).send('Invalid credentials.');
    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token: token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) { res.status(500).send('Server error during login.'); }
});

// --- USER MANAGEMENT ---
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await db.query("SELECT id, username, role FROM users ORDER BY id ASC");
    res.json(users.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/users/staff', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Username and password are required.');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await db.query("INSERT INTO users (username, password, role) VALUES ($1, $2, 'staff') RETURNING id, username, role", [username, hashedPassword]);
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('Username already exists.');
    res.status(500).send('Server error during staff creation.');
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
    if (userId === req.user.userId) return res.status(400).send('Admin users cannot delete their own account.');
    const result = await db.query("DELETE FROM users WHERE id = $1 AND role = 'staff' RETURNING id, username", [userId]);
    if (result.rows.length === 0) return res.status(404).send('Staff user not found.');
    res.status(200).json({ message: `Staff user ${result.rows[0].username} deleted successfully.` });
  } catch (err) { res.status(500).send('Server error deleting user.'); }
});

// --- CUSTOMERS ---
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const allCustomers = await db.query("SELECT id, name, phone_number, address FROM Customers WHERE is_deleted = false ORDER BY name ASC");
    res.json(allCustomers.rows);
  } catch (err) { res.status(500).send("Server Error"); }
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

app.post('/api/customers', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address } = req.body;
    const imageBuffer = req.file ? req.file.buffer : null;
    if (!name || !phone_number) return res.status(400).json({ error: 'Name and phone are required.' });
    const newCustomerResult = await db.query(
      "INSERT INTO Customers (name, phone_number, address, customer_image_url, is_deleted) VALUES ($1, $2, $3, $4, false) RETURNING id, name, phone_number, address",
      [name, phone_number, address, imageBuffer]
    );
    res.status(201).json(newCustomerResult.rows[0]);
  } catch (err) { res.status(500).send("Server Error"); }
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
          query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3, customer_image_url = $4 WHERE id = $5 AND is_deleted = false RETURNING id, name, phone_number, address";
          values = [name, phone_number, address, imageBuffer, id];
        } else {
          query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3 WHERE id = $4 AND is_deleted = false RETURNING id, name, phone_number, address";
          values = [name, phone_number, address, id];
        }
        const updateCustomerResult = await db.query(query, values);
        if (updateCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });
        res.json(updateCustomerResult.rows[0]);
    } catch (err) { res.status(500).send("Server Error"); }
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
app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    const query = `
      SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status,
             c.name AS customer_name, c.phone_number
      FROM Loans l JOIN Customers c ON l.customer_id = c.id
      WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited') AND c.is_deleted = false
      ORDER BY l.pledge_date DESC`; 
    const allLoans = await db.query(query);
    res.json(allLoans.rows);
  } catch (err) { res.status(500).send("Server Error"); }
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
    const query = `SELECT l.id, l.due_date, c.name AS customer_name, l.principal_amount, l.book_loan_number, l.pledge_date FROM Loans l JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'overdue' AND c.is_deleted = false ORDER BY l.due_date ASC`;
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
    const currentPrincipal = parseFloat(loanResult.rows[0].principal_amount);
    const newPrincipal = currentPrincipal + amountToAdd;
    const updateResult = await client.query("UPDATE Loans SET principal_amount = $1 WHERE id = $2 RETURNING *", [newPrincipal, loanId]);
    await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4)", [loanId, amountToAdd, 'disbursement', username]);
    await client.query('COMMIT');
    res.json({ message: `Successfully added ₹${amountToAdd.toFixed(2)}.`, loan: updateResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK'); console.error("Add Principal Error:", err.message); res.status(500).send("Server Error.");
  } finally { client.release(); }
});

// --- ⭐ 5. UPDATED LOAN DETAIL ROUTE (WITH SERVER-SIDE BREAKDOWN) ---
app.get('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid loan ID." });
    
    await db.query("UPDATE Loans SET status = 'overdue' WHERE id = $1 AND due_date < NOW() AND status = 'active'", [id]);

    const loanQuery = `
      SELECT l.*, pi.item_type, pi.description, pi.quality, pi.weight, pi.item_image_data, 
             c.name AS customer_name, c.phone_number, c.customer_image_url 
      FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id JOIN Customers c ON l.customer_id = c.id 
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
        totalPaid += amount;
        if (tx.payment_type === 'principal') principalPaid += amount;
        else if (tx.payment_type === 'interest') interestPaid += amount;
      }
    });

    const subsequentDisbursementsSum = disbursementTxs.reduce((sum, tx) => sum + tx.amount, 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum; 
    const disbursements = [];
    
    // --- BUILD THE BREAKDOWN ON THE SERVER ---
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
            label: event.isInitial ? 'Initial Principal' : `Top-up #${index}`, // 0 index will be init if exists
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
        // --- SEND BREAKDOWN TO FRONTENDS ---
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
    const { customer_id, principal_amount, interest_rate, book_loan_number, item_type, description, quality, weight, deductFirstMonthInterest } = req.body;
    const itemImageBuffer = req.file ? req.file.buffer : null;
    const principal = parseFloat(principal_amount);
    const rate = parseFloat(interest_rate); 

    if (!customer_id || isNaN(principal) || principal <= 0 || isNaN(rate) || rate <= 0 || !book_loan_number || !item_type || !description) return res.status(400).send("Missing fields.");
    
    const customerCheck = await client.query("SELECT is_deleted FROM Customers WHERE id = $1", [customer_id]);
    if (customerCheck.rows.length === 0 || customerCheck.rows[0].is_deleted) return res.status(404).send("Customer not found.");

    await client.query('BEGIN');
    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number) VALUES ($1, $2, $3, $4) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal, rate, book_loan_number]);
    const newLoanId = loanResult.rows[0].id;

    const itemQuery = `INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, item_image_data) VALUES ($1, $2, $3, $4, $5, $6)`;
    await client.query(itemQuery, [newLoanId, item_type, description, quality, weight, itemImageBuffer]);
    
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
    if (err.code === '23505') return res.status(400).send("Error: Book Loan Number already exists.");
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

    const currentPrincipalTotal = parseFloat(loan.principal_amount);
    const monthlyInterestRatePercent = parseFloat(loan.interest_rate);
    const pledgeDate = new Date(loan.pledge_date);
    const today = new Date();

    const disbursementsResult = await client.query("SELECT amount_paid, payment_date FROM Transactions WHERE loan_id = $1 AND payment_type = 'disbursement' ORDER BY payment_date ASC", [loanId]);
    const subsequentDisbursementsSum = disbursementsResult.rows.reduce((sum, tx) => sum + parseFloat(tx.amount_paid), 0);
    const initialPrincipal = currentPrincipalTotal - subsequentDisbursementsSum;
    
    let disbursementEvents = [];
    if (initialPrincipal > 0) disbursementEvents.push({ amount: initialPrincipal, date: pledgeDate, isInitial: true });
    disbursementEvents = disbursementEvents.concat(disbursementsResult.rows.map(row => ({ amount: parseFloat(row.amount_paid), date: new Date(row.payment_date), isInitial: false })));
    
    let totalInterest = 0;
    for (const event of disbursementEvents) {
      if (event.amount <= 0) continue;
      const monthsFactor = calculateTotalMonthsFactor(event.date, today);
      totalInterest += event.amount * (monthlyInterestRatePercent / 100) * monthsFactor;
    }
    
    const totalOwed = currentPrincipalTotal + totalInterest;
    const paidResult = await client.query("SELECT SUM(amount_paid) AS total_paid FROM Transactions WHERE loan_id = $1 AND payment_type != 'disbursement'", [loanId]);
    const previouslyPaid = parseFloat(paidResult.rows[0].total_paid) || 0;

    const outstandingAfterSettlement = totalOwed - previouslyPaid - finalPayment - discount;

    if (outstandingAfterSettlement > 2) { 
      await client.query('ROLLBACK');
      return res.status(400).json({
          error: `Insufficient funds to close. Total Owed: ${totalOwed.toFixed(2)}, Paid Before: ${previouslyPaid.toFixed(2)}, This Payment: ${finalPayment.toFixed(2)}, Discount: ${discount.toFixed(2)}. Remaining: ${outstandingAfterSettlement.toFixed(2)}`
      });
    }

    if (finalPayment > 0) {
       await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'settlement', NOW(), $3)", [loanId, finalPayment, username]);
    }
    if (discount > 0) {
       await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'discount', NOW(), $3)", [loanId, discount, username]);
    }

    const closeLoan = await client.query("UPDATE Loans SET status = 'paid', closed_date = NOW() WHERE id = $1 RETURNING *", [loanId]);
    await client.query('COMMIT');
    res.json({ message: `Loan successfully closed.`, loan: closeLoan.rows[0] });

  } catch (err) {
    await client.query('ROLLBACK'); console.error("Settle Loan Error:", err.message); res.status(500).send("Server Error");
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

app.put('/api/loans/:id', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    const username = req.user.username; 
    const { book_loan_number, interest_rate, pledge_date, due_date, item_type, description, quality, weight } = req.body;
    const newItemImageBuffer = req.file ? req.file.buffer : undefined;
    const removeItemImage = req.body.removeItemImage === 'true';

    if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid loan ID." });
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        const currentDataQuery = `SELECT l.book_loan_number, l.interest_rate, l.pledge_date, l.due_date, l.status, pi.id AS item_id, pi.item_type, pi.description, pi.quality, pi.weight, pi.item_image_data FROM "loans" l LEFT JOIN "pledgeditems" pi ON l.id = pi.loan_id WHERE l.id = $1 FOR UPDATE OF l`;
        const currentResult = await client.query(currentDataQuery, [loanId]);
        if (currentResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Loan not found." }); }
        const oldData = currentResult.rows[0];
        const itemId = oldData.item_id;
        if (oldData.status === 'deleted') { await client.query('ROLLBACK'); return res.status(400).json({ error: "Cannot edit a deleted loan." }); }

        const historyLogs = [];
        const loanUpdateFields = []; const loanUpdateValues = [];
        const itemUpdateFields = []; const itemUpdateValues = [];

        const addUpdate = (table, field, newValue, oldValue, fieldsArray, valuesArray, logLabel = field) => {
            if (newValue === undefined) return;
            let oldValCompare, newValCompare;
            const dateFields = ['pledge_date', 'due_date'];
            if (dateFields.includes(field)) {
                newValCompare = (newValue === "" || newValue === null) ? null : newValue; 
                if (oldValue === null || oldValue === undefined) oldValCompare = null;
                else {
                    const d = new Date(oldValue);
                    const year = d.getFullYear();
                    const month = String(d.getMonth() + 1).padStart(2, '0');
                    const day = String(d.getDate()).padStart(2, '0');
                    oldValCompare = `${year}-${month}-${day}`;
                }
            } else {
                oldValCompare = oldValue; newValCompare = newValue;
                if (typeof oldValue === 'number' || !isNaN(parseFloat(oldValue))) {
                    oldValCompare = parseFloat(oldValue); newValCompare = parseFloat(newValue);
                    if (oldValue === null) oldValCompare = null; if (newValue === null) newValCompare = null;
                }
            }
            if (newValCompare !== oldValCompare) {
                let dbValue = newValue;
                if (dateFields.includes(field) && (newValue === "" || newValue === null)) dbValue = null; 
                fieldsArray.push(`"${field}"`); valuesArray.push(dbValue);
                historyLogs.push({ loan_id: loanId, field_changed: logLabel, old_value: String(oldValue ?? 'null'), new_value: String(dbValue ?? 'null'), changed_by_username: username });
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
                itemUpdateFields.push(`"item_image_data"`); itemUpdateValues.push(finalImageValue);
                historyLogs.push({ loan_id: loanId, field_changed: 'item_image', old_value: oldData.item_image_data ? '[Image Data]' : '[No Image]', new_value: finalImageValue ? '[New Image Data]' : '[Image Removed]', changed_by_username: username });
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
        await client.query('ROLLBACK'); console.error(`Error updating loan ${loanId}:`, err.message);
        if (err.code === '23505') return res.status(400).json({ error: "Book Loan Number already exists." });
        res.status(500).send("Server Error while updating loan.");
    } finally { client.release(); }
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

app.get('/api/dashboard/stats', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    const [principalResult, activeLoansResult, overdueLoansResult, interestThisMonthResult, totalCustomersResult, totalLoansResult, totalPaidResult, totalForfeitedResult] = await Promise.all([
      db.query("SELECT SUM(principal_amount) FROM Loans WHERE status = 'active' OR status = 'overdue'"),
      db.query("SELECT COUNT(*) FROM Loans WHERE status = 'active' OR status = 'overdue'"),
      db.query("SELECT COUNT(*) FROM Loans WHERE status = 'overdue'"),
      db.query("SELECT SUM(amount_paid) FROM Transactions WHERE payment_type = 'interest' AND payment_date >= date_trunc('month', CURRENT_DATE)"),
      db.query("SELECT COUNT(*) FROM Customers WHERE is_deleted = false"),
      db.query("SELECT COUNT(*) FROM Loans WHERE status != 'deleted'"), 
      db.query("SELECT COUNT(*) FROM Loans WHERE status = 'paid'"),
      db.query("SELECT COUNT(*) FROM Loans WHERE status = 'forfeited'") 
    ]);
    res.json({
      totalPrincipalOut: parseFloat(principalResult.rows[0].sum) || 0,
      totalActiveLoans: parseInt(activeLoansResult.rows[0].count) || 0,
      totalOverdueLoans: parseInt(overdueLoansResult.rows[0].count) || 0,
      interestCollectedThisMonth: parseFloat(interestThisMonthResult.rows[0].sum) || 0,
      totalCustomers: parseInt(totalCustomersResult.rows[0].count) || 0,
      totalLoans: parseInt(totalLoansResult.rows[0].count) || 0,
      totalValue: parseFloat(principalResult.rows[0].sum) || 0,
      loansActive: parseInt(activeLoansResult.rows[0].count) || 0,
      loansOverdue: parseInt(overdueLoansResult.rows[0].count) || 0,
      loansPaid: parseInt(totalPaidResult.rows[0].count) || 0,
      loansForfeited: parseInt(totalForfeitedResult.rows[0].count) || 0
    });
  } catch (err) { console.error("Dashboard Stats Error:", err.message); res.status(500).send("Server Error."); }
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

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});