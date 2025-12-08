const express = require('express');
const db = require('./db');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

const allowedOrigins = [
  'http://localhost:3000', 
  'https://pledge-loan-frontend.onrender.com',
  'exp://192.168.29.6:8081' 
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(null, true); 
    }
    return callback(null, true);
  }
}));

app.use(express.json());

const PORT = process.env.PORT || 3001; 
const JWT_SECRET = process.env.JWT_SECRET || 'a-very-strong-secret-key-that-you-should-change';
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; 
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
};

const authorizeManagement = (req, res, next) => {
  if (['admin', 'manager'].includes(req.user.role)) next();
  else return res.sendStatus(403);
};

const getTargetBranchId = (req) => {
  const { role, branchId: userBranchId } = req.user;
  const { branchId: queryBranchId } = req.query;
  if (role === 'admin') {
    if (queryBranchId && queryBranchId !== 'all') return parseInt(queryBranchId);
    return null; 
  } else return userBranchId;
};

// ==========================================
// 🧠 CORE CALCULATION ENGINE (FIXED)
// ==========================================

const parseDate = (dateInput) => {
  const d = new Date(dateInput);
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
};

// --- ROBUST 15-DAY SPLIT & MIN 1 MONTH LOGIC ---
const calculateGoldLoanMonths = (startDate, endDate) => {
  const start = parseDate(startDate);
  const end = parseDate(endDate);

  // 1. Initial Creation / Same Day Rule:
  if (end.getTime() <= start.getTime()) return 1.0;

  // 2. Count Full Months Step-by-Step
  let tempDate = new Date(start);
  let fullMonths = 0;

  while (true) {
    let nextMonth = new Date(tempDate);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    
    // Handle end-of-month clipping (e.g. Jan 31 -> Feb 28)
    if (nextMonth.getDate() !== tempDate.getDate()) {
       nextMonth.setDate(0); 
    }

    if (nextMonth > end) break;
    tempDate = nextMonth;
    fullMonths++;
  }

  // 3. Calculate Days in the "Partial" Month
  const oneDay = 1000 * 60 * 60 * 24;
  const diffTime = Math.abs(end - tempDate);
  const diffDays = Math.ceil(diffTime / oneDay); 

  // 4. Apply 15-Day Rule
  let extra = 0.0;
  if (diffDays === 0) {
      extra = 0.0;
  } else if (diffDays <= 15) {
      extra = 0.5;
  } else {
      extra = 1.0;
  }

  let total = fullMonths + extra;

  // 5. Enforce Minimum 1 Month Rule
  if (total < 1.0) return 1.0;

  return total;
};

const calculateLoanFinancials = (loan, transactions) => {
  const rate = parseFloat(loan.interest_rate) / 100;
  const today = new Date();
  const endDate = loan.status === 'paid' && loan.closed_date ? new Date(loan.closed_date) : today;

  let rawEvents = [];

  // A. Initial Principal
  const disbursements = transactions.filter(t => t.payment_type === 'disbursement');
  const topUpSum = disbursements.reduce((sum, t) => sum + parseFloat(t.amount_paid), 0);
  const initialPrincipal = parseFloat(loan.principal_amount) - topUpSum;

  if (initialPrincipal > 0) {
    rawEvents.push({ 
      type: 'disburse', 
      date: new Date(loan.pledge_date), 
      amount: initialPrincipal,
      isInitial: true
    });
  }

  // B. Transactions
  transactions.forEach(t => {
    const d = new Date(t.payment_date);
    const amt = parseFloat(t.amount_paid);
    
    if (t.payment_type === 'disbursement') {
      rawEvents.push({ type: 'disburse', date: d, amount: amt });
    } else if (['interest', 'principal', 'settlement'].includes(t.payment_type)) {
      rawEvents.push({ type: 'payment', date: d, amount: amt, originalType: t.payment_type });
    } else if (t.payment_type === 'discount') {
      rawEvents.push({ type: 'discount', date: d, amount: amt });
    } else if (t.payment_type === 'sale') {
      rawEvents.push({ type: 'payment', date: d, amount: amt, originalType: 'sale' });
    }
  });

  // C. Group Events by Date
  const eventsMap = new Map();

  rawEvents.forEach(ev => {
    const dateKey = parseDate(ev.date).getTime();
    if (!eventsMap.has(dateKey)) {
        eventsMap.set(dateKey, {
            date: parseDate(ev.date),
            disburse: 0, payment: 0, discount: 0, types: new Set(), topupDetails: [] 
        });
    }
    const group = eventsMap.get(dateKey);
    if (ev.type === 'disburse') {
        group.disburse += ev.amount;
        group.topupDetails.push({ amount: ev.amount, isInitial: ev.isInitial });
    } else if (ev.type === 'payment') {
        group.payment += ev.amount;
        group.types.add(ev.originalType);
    } else if (ev.type === 'discount') {
        group.discount += ev.amount;
    }
  });

  const processedEvents = Array.from(eventsMap.values()).sort((a, b) => a.date - b.date);

  // Add Final Report Event
  processedEvents.push({ 
      date: parseDate(endDate), 
      isReport: true,
      disburse: 0, payment: 0, discount: 0, types: new Set(), topupDetails: []
  });

  // --- CALCULATION LOOP ---
  let activePrincipals = []; 
  let accruedInterestSnapshot = 0; 
  
  let totalPrincipalPaid = 0;
  let totalInterestPaid = 0;
  let totalDiscount = 0;
  let breakdown = [];

  let interestPaidOnCurrentBuckets = 0;
  let lastInterestPaymentDate = null; 

  for (let i = 0; i < processedEvents.length; i++) {
    const event = processedEvents[i];
    const evtDate = event.date;

    // 1. Handle New Disbursements
    if (event.disburse > 0) {
        event.topupDetails.forEach(detail => {
            activePrincipals.push({ 
                amount: detail.amount, 
                startDate: evtDate, 
                label: detail.isInitial ? "Initial Principal" : `Top-up`
            });
        });
    }

    // 2. Accrue Interest
    if (event.payment > 0 || event.isReport || event.discount > 0 || event.disburse > 0) {
      let currentSnapshot = 0;
      let currentRows = []; 

      activePrincipals.forEach((p) => {
        const isNewChunk = p.startDate.getTime() >= evtDate.getTime();
        if (!isNewChunk || event.isReport) {
          let factor = calculateGoldLoanMonths(p.startDate, evtDate);
          const interest = p.amount * rate * factor;
          currentSnapshot += interest;
          
          if (interest > 0 || event.isReport) {
             if (event.payment > 0 || event.isReport || event.discount > 0) {
                 currentRows.push({
                   label: `Int. on ${p.amount} (${p.label})`,
                   date: p.startDate.toISOString(),
                   endDate: evtDate.toISOString(),
                   amount: p.amount,
                   grossInterest: interest,
                   rate: rate,
                   status: 'accrued'
                 });
             }
          }
        }
      });

      if (event.payment > 0 || event.isReport || event.discount > 0) {
          accruedInterestSnapshot = currentSnapshot;
      }

      // --- GENERATE ACCRUAL ROWS ---
      if (event.payment > 0 || event.isReport || event.discount > 0) {
          if (interestPaidOnCurrentBuckets > 0) {
              let paidRemaining = interestPaidOnCurrentBuckets;
              currentRows.forEach(row => {
                  if (paidRemaining > 0) {
                      const deduction = Math.min(row.grossInterest, paidRemaining);
                      row.grossInterest -= deduction;
                      paidRemaining -= deduction;
                      if (lastInterestPaymentDate && new Date(row.date) < lastInterestPaymentDate) {
                          row.date = lastInterestPaymentDate.toISOString();
                      }
                  }
                  const netMonths = row.grossInterest / (row.amount * row.rate);
                  row.months = netMonths;
                  row.interest = row.grossInterest.toFixed(2);
                  row.amount = row.amount.toFixed(2);
                  if (row.grossInterest > 0) breakdown.push(row);
              });
          } else {
              currentRows.forEach(row => {
                  const netMonths = row.grossInterest / (row.amount * row.rate);
                  row.months = netMonths;
                  row.interest = row.grossInterest.toFixed(2);
                  row.amount = row.amount.toFixed(2);
                  breakdown.push(row);
              });
          }
      }

      // 3. Apply Discount (Principal Write-off Logic)
      if (event.discount > 0) {
         totalDiscount += event.discount;

         const netInterestOwed = Math.max(0, accruedInterestSnapshot - interestPaidOnCurrentBuckets);
         const discountCoveringInterest = Math.min(event.discount, netInterestOwed);
         
         if (discountCoveringInterest > 0) {
             interestPaidOnCurrentBuckets += discountCoveringInterest;
         }

         // Use remaining discount to write off principal
         const remainingDiscount = event.discount - discountCoveringInterest;
         if (remainingDiscount > 0) {
             const totalActive = activePrincipals.reduce((s,p)=>s+p.amount,0);
             const newBal = Math.max(0, totalActive - remainingDiscount);
             
             if (newBal <= 0.5) {
                 activePrincipals = []; // Calculations STOP here
                 accruedInterestSnapshot = 0;
                 interestPaidOnCurrentBuckets = 0;
                 lastInterestPaymentDate = null;
             } else {
                 const nextMonthDate = addOneMonth(evtDate);
                 activePrincipals = [{ amount: newBal, startDate: nextMonthDate, label: "Balance c/f" }];
                 interestPaidOnCurrentBuckets = 0; 
                 accruedInterestSnapshot = 0;
                 lastInterestPaymentDate = null; 
             }
         }

         breakdown.push({
            label: `Discount Applied`,
            amount: (-event.discount).toFixed(2),
            date: evtDate.toISOString(),
            status: 'payment'
         });
      }

      // 4. Apply Payment
      if (event.payment > 0) {
        let paymentAmount = event.payment;
        
        const netInterestOwed = Math.max(0, accruedInterestSnapshot - interestPaidOnCurrentBuckets);
        const interestCovered = Math.min(paymentAmount, netInterestOwed);
        
        totalInterestPaid += interestCovered;
        interestPaidOnCurrentBuckets += interestCovered;
        
        if (interestCovered > 0) lastInterestPaymentDate = evtDate; 

        paymentAmount -= interestCovered;
        
        if (paymentAmount > 0) {
          totalPrincipalPaid += paymentAmount;
          const totalActivePrincipal = activePrincipals.reduce((sum, p) => sum + p.amount, 0);
          const newPrincipalBalance = totalActivePrincipal - paymentAmount;

          if (newPrincipalBalance <= 0.5) { 
             activePrincipals = [];
             accruedInterestSnapshot = 0;
             interestPaidOnCurrentBuckets = 0;
             lastInterestPaymentDate = null; 
          } else {
             const nextMonthDate = addOneMonth(evtDate);
             activePrincipals = [{
               amount: newPrincipalBalance,
               startDate: nextMonthDate,
               label: "Balance c/f"
             }];
             interestPaidOnCurrentBuckets = 0; 
             accruedInterestSnapshot = 0;
             lastInterestPaymentDate = null; 
          }
        }
        
        breakdown.push({
          label: `Payment Received (${Array.from(event.types).join('+')})`,
          amount: (-event.payment).toFixed(2),
          date: evtDate.toISOString(),
          status: 'payment'
        });
      }
    }
  }

  const currentPrincipal = activePrincipals.reduce((sum, p) => sum + p.amount, 0);
  const finalOutstandingInterest = Math.max(0, accruedInterestSnapshot - interestPaidOnCurrentBuckets);
  const amountDue = currentPrincipal + finalOutstandingInterest;

  return {
    totalInterestOwed: (totalInterestPaid + finalOutstandingInterest).toFixed(2),
    principalPaid: totalPrincipalPaid.toFixed(2),
    interestPaid: totalInterestPaid.toFixed(2),
    totalPaid: (totalPrincipalPaid + totalInterestPaid + totalDiscount).toFixed(2),
    outstandingPrincipal: currentPrincipal.toFixed(2),
    outstandingInterest: finalOutstandingInterest.toFixed(2),
    amountDue: amountDue.toFixed(2),
    breakdown: breakdown.reverse()
  };
};

// --- AUTH & USER ROUTES ---

app.get('/', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT NOW()');
    res.status(200).json({ message: "Welcome to Pledge Loan API", db_status: "Connected", db_time: rows[0].now });
  } catch (err) { res.status(500).json({ message: "DB Error" }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Required');
    const query = `SELECT u.*, b.branch_name FROM users u LEFT JOIN branches b ON u.branch_id = b.id WHERE u.username = $1`;
    const userResult = await db.query(query, [username]);
    if (userResult.rows.length === 0) return res.status(401).send('Invalid');
    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) return res.status(401).send('Invalid');
    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role, branchId: user.branch_id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, branchId: user.branch_id, branchName: user.branch_name || 'Main' } });
  } catch (err) { res.status(500).send('Error'); }
});

app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const users = await db.query(`SELECT u.id, u.username, u.role, u.branch_id, b.branch_name FROM users u LEFT JOIN branches b ON u.branch_id = b.id ORDER BY u.id ASC`);
    res.json(users.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.post('/api/users/create', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { username, password, role, branchId } = req.body; 
    if (!username || !password) return res.status(400).send('Required');
    const validRoles = ['admin', 'manager', 'staff'];
    const assignedRole = validRoles.includes(role) ? role : 'staff';
    const assignedBranch = branchId || 1; 
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await db.query("INSERT INTO users (username, password, role, branch_id) VALUES ($1, $2, $3, $4) RETURNING id, username, role, branch_id", [username, hashedPassword, assignedRole, assignedBranch]);
    res.status(201).json(newUser.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).send('Username exists.');
    res.status(500).send('Error');
  }
});

app.put('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, role, branchId } = req.body;
    const check = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (check.rows.length === 0) return res.status(404).json({ error: "Not found" });
    const oldUser = check.rows[0];
    const newUsername = username || oldUser.username;
    const newRole = role || oldUser.role;
    const newBranchId = (branchId !== undefined) ? branchId : oldUser.branch_id;
    const result = await db.query("UPDATE users SET username = $1, role = $2, branch_id = $3 WHERE id = $4 RETURNING id, username, role, branch_id", [newUsername, newRole, newBranchId, id]);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.put('/api/users/change-password', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { userId, newPassword } = req.body;
    if (!userId || !newPassword) return res.status(400).send('Required');
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    const result = await db.query("UPDATE users SET password = $1 WHERE id = $2 RETURNING id, username", [hashedPassword, userId]);
    if (result.rows.length === 0) return res.status(404).send('Not found.');
    res.status(200).json({ message: `Password updated.` });
  } catch (err) { res.status(500).send('Error'); }
});

app.delete('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = parseInt(id);
    if (userId === req.user.userId) return res.status(400).send('Cannot delete self.');
    const result = await db.query("DELETE FROM users WHERE id = $1 RETURNING id, username", [userId]);
    if (result.rows.length === 0) return res.status(404).send('Not found.');
    res.status(200).json({ message: `User deleted.` });
  } catch (err) { res.status(500).send('Error'); }
});

// --- CUSTOMERS ---

app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);
    if (targetBranch) await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [targetBranch]);
    else await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");

    let query = `SELECT c.id, c.name, c.phone_number, c.address, c.customer_image_url, c.branch_id, b.branch_name, COUNT(CASE WHEN l.status = 'active' THEN 1 END)::int AS active_loan_count, COUNT(CASE WHEN l.status = 'overdue' THEN 1 END)::int AS overdue_loan_count, COUNT(CASE WHEN l.status = 'paid' THEN 1 END)::int AS paid_loan_count FROM Customers c LEFT JOIN Loans l ON c.id = l.customer_id AND l.status != 'deleted' LEFT JOIN Branches b ON c.branch_id = b.id WHERE c.is_deleted = false`;
    const params = [];
    if (targetBranch) { query += ` AND c.branch_id = $1`; params.push(targetBranch); }
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
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const query = `SELECT c.*, b.branch_name FROM Customers c LEFT JOIN Branches b ON c.branch_id = b.id WHERE c.id = $1 AND c.is_deleted = false`;
    const customerResult = await db.query(query, [id]);
    if (customerResult.rows.length === 0) return res.status(404).json({ error: "Not found." });
    const customer = customerResult.rows[0];
    const userRole = req.user.role;
    const userBranchId = parseInt(req.user.branchId || 0);
    const customerBranchId = parseInt(customer.branch_id || 0);
    if (userRole !== 'admin' && customerBranchId !== userBranchId) return res.status(403).json({ error: "Access Denied." });
    if (customer.customer_image_url) {
      const b64 = customer.customer_image_url.toString('base64');
      let mimeType = b64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
      customer.customer_image_url = `data:${mimeType};base64,${b64}`;
    }
    res.json(customer);
  } catch (err) { res.status(500).send("Error"); }
});

app.post('/api/customers', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation } = req.body;
    const imageBuffer = req.file ? req.file.buffer : null;
    if (!name || !phone_number) return res.status(400).json({ error: 'Name/Phone required.' });
    let assignedBranch = req.user.branchId;
    if (req.user.role === 'admin' && req.body.branchId) assignedBranch = parseInt(req.body.branchId);
    const newCustomerResult = await db.query(`INSERT INTO Customers (name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, customer_image_url, is_deleted, branch_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, $9) RETURNING *`, [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, imageBuffer, assignedBranch || 1]);
    res.status(201).json(newCustomerResult.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.put('/api/customers/:id', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const checkBranch = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
        if (checkBranch.rows.length === 0) return res.status(404).json({ error: "Not found." });
        if (req.user.role !== 'admin' && checkBranch.rows[0].branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });
        const { name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation } = req.body;
        let imageBuffer = null;
        let updateImage = false;
        if (req.file) { imageBuffer = req.file.buffer; updateImage = true; }
        else if (req.body.removeCurrentImage === 'true') { imageBuffer = null; updateImage = true; }
        let query, values;
        if (updateImage) {
          query = `UPDATE Customers SET name = $1, phone_number = $2, address = $3, id_proof_type = $4, id_proof_number = $5, nominee_name = $6, nominee_relation = $7, customer_image_url = $8 WHERE id = $9 AND is_deleted = false RETURNING *`;
          values = [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, imageBuffer, id];
        } else {
          query = `UPDATE Customers SET name = $1, phone_number = $2, address = $3, id_proof_type = $4, id_proof_number = $5, nominee_name = $6, nominee_relation = $7 WHERE id = $8 AND is_deleted = false RETURNING *`;
          values = [name, phone_number, address, id_proof_type, id_proof_number, nominee_name, nominee_relation, id];
        }
        const updateCustomerResult = await db.query(query, values);
        res.json(updateCustomerResult.rows[0]);
    } catch (err) { res.status(500).send("Error"); }
});

app.delete('/api/customers/:id', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const cust = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
    if (cust.rows.length === 0) return res.status(404).json({ error: "Not found." });
    if (req.user.role !== 'admin' && cust.rows[0].branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });
    const activeLoanCheck = await db.query("SELECT COUNT(*) FROM Loans WHERE customer_id = $1 AND status IN ('active', 'overdue')", [id]);
    if (parseInt(activeLoanCheck.rows[0].count) > 0) return res.status(400).json({ error: "Active loans exist." });
    const deleteCustomerResult = await db.query("UPDATE Customers SET is_deleted = true WHERE id = $1 RETURNING id, name", [id]);
    await db.query("UPDATE Loans SET status = 'deleted' WHERE customer_id = $1 AND status IN ('paid', 'forfeited')", [id]);
    res.json({ message: `Customer deleted.` });
  } catch (err) { res.status(500).send("Error"); }
});

// --- LOANS & TRANSACTIONS ---

app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);
    if (targetBranch) await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active' AND branch_id = $1", [targetBranch]);
    else await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    let query = `SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status, c.name AS customer_name, c.phone_number, b.branch_name FROM Loans l JOIN Customers c ON l.customer_id = c.id LEFT JOIN Branches b ON l.branch_id = b.id WHERE l.status IN ('active', 'overdue', 'paid', 'forfeited') AND c.is_deleted = false`;
    const params = [];
    if (targetBranch) { query += ` AND l.branch_id = $1`; params.push(targetBranch); }
    query += ` ORDER BY l.pledge_date DESC`;
    const allLoans = await db.query(query, params);
    res.json(allLoans.rows);
  } catch (err) { res.status(500).send("Error"); }
});

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
    
    let base = `SELECT l.id, l.due_date, l.principal_amount, l.book_loan_number, l.pledge_date, c.name AS customer_name, c.phone_number, c.address FROM Loans l JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'overdue' AND c.is_deleted = false`;
    const { q, params } = getScopedLoanQuery(base, req);
    const finalQ = q + ` ORDER BY l.due_date ASC`;
    const overdueLoans = await db.query(finalQ, params);
    res.json(overdueLoans.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/api/loans/find-by-book-number/:bookNumber', authenticateToken, async (req, res) => {
  try {
    const { bookNumber } = req.params;
    const targetBranch = getTargetBranchId(req);
    let query = "SELECT id FROM Loans WHERE book_loan_number = $1 AND status != 'deleted'";
    let params = [bookNumber];
    if (targetBranch) { query += " AND branch_id = $2"; params.push(targetBranch); }
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
  if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid ID." });
  if (isNaN(amountToAdd) || amountToAdd <= 0) return res.status(400).json({ error: "Invalid amount." });
  
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const loanResult = await client.query("SELECT principal_amount, status, branch_id FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Not found." }); }
    const currentLoan = loanResult.rows[0];
    if (req.user.role !== 'admin' && currentLoan.branch_id !== req.user.branchId) { await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." }); }
    if (currentLoan.status !== 'active' && currentLoan.status !== 'overdue') { await client.query('ROLLBACK'); return res.status(400).json({ error: `Cannot add principal.` }); }
    
    const currentPrincipal = parseFloat(currentLoan.principal_amount);
    const newPrincipal = currentPrincipal + amountToAdd;
    const updateResult = await client.query("UPDATE Loans SET principal_amount = $1 WHERE id = $2 RETURNING *", [newPrincipal, loanId]);
    await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4)", [loanId, amountToAdd, 'disbursement', username]);
    await client.query('COMMIT');
    res.json({ message: `Added ₹${amountToAdd.toFixed(2)}.`, loan: updateResult.rows[0] });
  } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error."); } finally { client.release(); }
});

// --- FORFEIT / SELL LOAN ENDPOINT ---
app.post('/api/loans/:id/forfeit', authenticateToken, upload.fields([{ name: 'signature', maxCount: 1 }, { name: 'photo', maxCount: 1 }]), async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  try {
    const loanId = parseInt(req.params.id);
    const { salePrice, notes } = req.body; 
    const finalSalePrice = parseFloat(salePrice) || 0;

    const signatureBuffer = req.files['signature'] ? req.files['signature'][0].buffer : null;
    const photoBuffer = req.files['photo'] ? req.files['photo'][0].buffer : null;

    await client.query('BEGIN');

    // 1. Validate Loan
    const loanRes = await client.query("SELECT * FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanRes.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Not found." }); }
    const loan = loanRes.rows[0];
    
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) { 
      await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." }); 
    }
    if (loan.status !== 'active' && loan.status !== 'overdue') {
      await client.query('ROLLBACK'); return res.status(400).json({ error: "Loan is not active." }); 
    }

    // 2. Record the 'Sale' as a transaction
    if (finalSalePrice > 0) {
      await client.query(
        "INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'sale', NOW(), $3)",
        [loanId, finalSalePrice, username]
      );
    }

    // 3. Update Loan Status and Save Proofs
    await client.query(
      `UPDATE Loans 
       SET status = 'forfeited', 
           closed_date = NOW(), 
           sale_price = $1, 
           forfeiture_signature_proof = $2, 
           forfeiture_photo_proof = $3 
       WHERE id = $4`,
      [finalSalePrice, signatureBuffer, photoBuffer, loanId]
    );

    // 4. Log History
    await client.query(
      "INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username) VALUES ($1, 'status', $2, 'forfeited', $3)",
      [loanId, loan.status, username]
    );

    await client.query('COMMIT');
    res.json({ message: "Loan forfeited successfully." });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).send("Server Error during forfeiture.");
  } finally {
    client.release();
  }
});

app.get('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const loanResult = await db.query("SELECT l.*, pi.item_type, pi.description, pi.quality, pi.weight, pi.gross_weight, pi.net_weight, pi.purity, pi.item_image_data, c.name AS customer_name, c.phone_number, c.address, c.customer_image_url FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id JOIN Customers c ON l.customer_id = c.id WHERE l.id = $1", [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Not found." });
    let loanDetails = loanResult.rows[0];
    if (req.user.role !== 'admin' && loanDetails.branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });

    const transactionsResult = await db.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [id]);
    
    const financials = calculateLoanFinancials(loanDetails, transactionsResult.rows);

    if (loanDetails.item_image_data) {
        const b64 = loanDetails.item_image_data.toString('base64');
        const mime = b64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
        loanDetails.item_image_data_url = `data:${mime};base64,${b64}`;
    } delete loanDetails.item_image_data;
    if (loanDetails.customer_image_url) {
        const b64 = loanDetails.customer_image_url.toString('base64');
        const mime = b64.startsWith('/9j/') ? 'image/jpeg' : 'image/png';
        loanDetails.customer_image_url = `data:${mime};base64,${b64}`;
    }

    res.json({ 
        loanDetails: loanDetails, 
        transactions: transactionsResult.rows.sort((a, b) => new Date(b.payment_date) - new Date(a.payment_date)),
        interestBreakdown: financials.breakdown, 
        calculated: financials
    });
  } catch (err) { res.status(500).send("Error"); }
});

app.post('/api/loans', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username; 
  try {
    const { customer_id, principal_amount, interest_rate, book_loan_number, item_type, description, quality, gross_weight, net_weight, purity, appraised_value, deductFirstMonthInterest } = req.body;
    const itemImageBuffer = req.file ? req.file.buffer : null;
    const principal = parseFloat(principal_amount);
    const rate = parseFloat(interest_rate); 
    if (!customer_id || isNaN(principal) || principal <= 0 || isNaN(rate) || rate <= 0 || !book_loan_number || !item_type || !description) return res.status(400).send("Missing fields.");
    const customerCheck = await client.query("SELECT branch_id, is_deleted FROM Customers WHERE id = $1", [customer_id]);
    if (customerCheck.rows.length === 0 || customerCheck.rows[0].is_deleted) return res.status(404).send("Customer not found.");
    const custBranch = customerCheck.rows[0].branch_id;
    if (req.user.role !== 'admin' && custBranch !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });

    await client.query('BEGIN');
    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number, appraised_value, branch_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal, rate, book_loan_number, appraised_value || 0, custBranch]);
    const newLoanId = loanResult.rows[0].id;
    const finalGrossWeight = gross_weight || req.body.weight; 
    const itemQuery = `INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, gross_weight, net_weight, purity, item_image_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`;
    await client.query(itemQuery, [newLoanId, item_type, description, quality, finalGrossWeight, finalGrossWeight, net_weight, purity, itemImageBuffer]);
    if (deductFirstMonthInterest === 'true') {
      const firstMonthInterest = principal * (rate / 100);
      if (firstMonthInterest > 0) await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)", [newLoanId, firstMonthInterest, username]);
    }
    await client.query('COMMIT');
    res.status(201).json({ message: "Loan created", loanId: newLoanId });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(400).json({ error: "Book Loan Number already exists." });
    res.status(500).send("Error");
  } finally { client.release(); }
});

app.get('/api/customers/:id/loans', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const cust = await db.query("SELECT branch_id FROM Customers WHERE id = $1", [id]);
    if (cust.rows.length > 0 && req.user.role !== 'admin' && cust.rows[0].branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });
    await db.query("UPDATE Loans SET status = 'overdue' WHERE customer_id = $1 AND due_date < NOW() AND status = 'active'", [id]);
    const query = `SELECT l.id AS loan_id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date, l.status, pi.description FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id WHERE l.customer_id = $1 AND l.status != 'deleted' ORDER BY l.pledge_date DESC`;
    const customerLoans = await db.query(query, [id]);
    res.json(customerLoans.rows);
  } catch (err) { res.status(500).send("Error"); }
});

// --- SMART SPLIT LOGIC PRESERVED ---
app.post('/api/transactions', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  try {
    const { loan_id, amount_paid, payment_type } = req.body; 
    const loanId = parseInt(loan_id);
    const paymentAmount = parseFloat(amount_paid);
    await client.query('BEGIN');
    const loanCheck = await client.query("SELECT * FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    if (loanCheck.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Not found." }); }
    const loan = loanCheck.rows[0];
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) { await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." }); }

    if (payment_type === 'interest') {
      const txRes = await client.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [loanId]);
      const financials = calculateLoanFinancials(loan, txRes.rows);
      const outstandingInterest = parseFloat(financials.outstandingInterest);

      if (paymentAmount > outstandingInterest) {
        const interestPart = outstandingInterest > 0 ? outstandingInterest : 0;
        const principalPart = paymentAmount - interestPart;
        let txs = [];
        if (interestPart > 0) {
           const r = await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3) RETURNING *", [loanId, interestPart, username]);
           txs.push(r.rows[0]);
        }
        const r2 = await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'principal', NOW(), $3) RETURNING *", [loanId, principalPart, username]);
        txs.push(r2.rows[0]);
        await client.query('COMMIT');
        return res.status(201).json(txs);
      }
    }
    const newTx = await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, $3, NOW(), $4) RETURNING *", [loanId, paymentAmount, payment_type, username]);
    await client.query('COMMIT');
    res.status(201).json([newTx.rows[0]]);
  } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error"); } finally { client.release(); }
});

app.post('/api/loans/:id/settle', authenticateToken, async (req, res) => {
  const client = await db.pool.connect();
  const username = req.user.username;
  try {
    const loanId = parseInt(req.params.id);
    const { discountAmount, settlementAmount } = req.body;
    const discount = parseFloat(discountAmount) || 0;
    const finalPayment = parseFloat(settlementAmount) || 0;
    await client.query('BEGIN');
    const loanRes = await client.query("SELECT * FROM Loans WHERE id = $1 FOR UPDATE", [loanId]);
    const loan = loanRes.rows[0];
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) { await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." }); }
    const txRes = await client.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date ASC", [loanId]);
    const financials = calculateLoanFinancials(loan, txRes.rows);
    const outstandingInterest = parseFloat(financials.outstandingInterest);
    const totalDue = parseFloat(financials.amountDue);
    const remaining = totalDue - finalPayment - discount;
    if (remaining > 1.0) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Insufficient funds. Due: ${totalDue}` }); }

    if (finalPayment > 0) {
        let interestPart = 0; let principalPart = 0;
        
        // NEW: Deduct Discount from Interest Owed First!
        const netInterestOwed = Math.max(0, outstandingInterest - discount);
        
        if (netInterestOwed > 0) {
            if (finalPayment >= netInterestOwed) { interestPart = netInterestOwed; principalPart = finalPayment - netInterestOwed; } 
            else { interestPart = finalPayment; }
        } else { principalPart = finalPayment; }
        
        if (interestPart > 0) await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'interest', NOW(), $3)", [loanId, interestPart, username]);
        if (principalPart > 0) await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'principal', NOW(), $3)", [loanId, principalPart, username]);
    }
    if (discount > 0) await client.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type, payment_date, changed_by_username) VALUES ($1, $2, 'discount', NOW(), $3)", [loanId, discount, username]);
    await client.query("UPDATE Loans SET status = 'paid', closed_date = NOW() WHERE id = $1", [loanId]);
    await client.query('COMMIT');
    res.json({ message: "Settled" });
  } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error"); } finally { client.release(); }
});

app.delete('/api/loans/:id', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const loanResult = await db.query("SELECT status, book_loan_number, branch_id FROM Loans WHERE id = $1", [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Not found." });
    const loan = loanResult.rows[0];
    if (req.user.role !== 'admin' && loan.branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied." });
    if (loan.status === 'active' || loan.status === 'overdue') return res.status(400).json({ error: "Settle first." });
    const deleteLoanResult = await db.query("UPDATE Loans SET status = 'deleted' WHERE id = $1 RETURNING id, book_loan_number", [id]);
    res.json({ message: `Loan #${deleteLoanResult.rows[0].book_loan_number} recycled.` });
  } catch (err) { res.status(500).send("Error"); }
});

app.put('/api/loans/:id', authenticateToken, upload.single('itemPhoto'), async (req, res) => {
    const { id } = req.params;
    const loanId = parseInt(id);
    const username = req.user.username; 
    const { book_loan_number, interest_rate, pledge_date, due_date, appraised_value, item_type, description, quality, gross_weight, net_weight, purity } = req.body;
    const newItemImageBuffer = req.file ? req.file.buffer : undefined;
    const removeItemImage = req.body.removeItemImage === 'true';
    if (isNaN(loanId) || loanId <= 0) return res.status(400).json({ error: "Invalid ID." });
    const client = await db.pool.connect();
    try {
        await client.query('BEGIN');
        const currentDataQuery = `SELECT l.*, pi.id AS item_id, pi.* FROM "loans" l LEFT JOIN "pledgeditems" pi ON l.id = pi.loan_id WHERE l.id = $1 FOR UPDATE OF l`;
        const currentResult = await client.query(currentDataQuery, [loanId]);
        if (currentResult.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Not found." }); }
        const oldData = currentResult.rows[0];
        if (req.user.role !== 'admin' && oldData.branch_id !== req.user.branchId) { await client.query('ROLLBACK'); return res.status(403).json({ error: "Access Denied." }); }
        const itemId = oldData.item_id;
        const historyLogs = [];
        const loanUpdateFields = []; const loanUpdateValues = [];
        const itemUpdateFields = []; const itemUpdateValues = [];

        const addUpdate = (table, field, newValue, oldValue, fieldsArray, valuesArray, logLabel = field) => {
            if (newValue === undefined) return; 
            let dbValue = newValue === "" ? null : newValue;
            let oldValCompare = oldValue; let newValCompare = dbValue;
            if (['pledge_date', 'due_date'].includes(field)) {
                if (oldValue) { const d = new Date(oldValue); oldValCompare = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; } else oldValCompare = null;
                newValCompare = dbValue; 
            } else if (typeof oldValue === 'number' || !isNaN(parseFloat(oldValue))) {
                if (oldValue !== null) oldValCompare = parseFloat(oldValue);
                if (dbValue !== null) newValCompare = parseFloat(dbValue);
            }
            if (newValCompare !== oldValCompare) {
                fieldsArray.push(`"${field}"`); valuesArray.push(dbValue);
                historyLogs.push({ loan_id: loanId, field_changed: logLabel, old_value: String(oldValue ?? 'null'), new_value: String(dbValue ?? 'null'), changed_by_username: username });
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
                historyLogs.push({ loan_id: loanId, field_changed: 'item_image', old_value: oldData.item_image_data ? '[Image]' : '[None]', new_value: finalImageValue ? '[New]' : '[Removed]', changed_by_username: username });
            }
        }

        if (loanUpdateFields.length > 0) {
            const setClause = loanUpdateFields.map((f, i) => `${f}=$${i+1}`).join(', ');
            loanUpdateValues.push(loanId);
            await client.query(`UPDATE "loans" SET ${setClause} WHERE id=$${loanUpdateValues.length}`, loanUpdateValues);
        }
        if (itemUpdateFields.length > 0 && itemId) {
            const setClause = itemUpdateFields.map((f, i) => `${f}=$${i+1}`).join(', ');
            itemUpdateValues.push(itemId);
            await client.query(`UPDATE "pledgeditems" SET ${setClause} WHERE id=$${itemUpdateValues.length}`, itemUpdateValues);
        }
        if (historyLogs.length > 0) {
            const q = `INSERT INTO loan_history (loan_id, field_changed, old_value, new_value, changed_by_username) VALUES ($1, $2, $3, $4, $5)`;
            for (const log of historyLogs) await client.query(q, [log.loan_id, log.field_changed, log.old_value, log.new_value, log.changed_by_username]);
        }
        await client.query('COMMIT');
        res.json({ message: `Updated.` });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error"); } finally { client.release(); }
});

app.get('/api/loans/:id/history', authenticateToken, async (req, res) => {
    const { id } = req.params; const loanId = parseInt(id);
    if (isNaN(loanId)) return res.status(400).json({ error: "Invalid ID." });
    const check = await db.query("SELECT branch_id FROM Loans WHERE id=$1", [loanId]);
    if(check.rows.length > 0 && req.user.role!=='admin' && check.rows[0].branch_id !== req.user.branchId) return res.status(403).json({ error: "Access Denied."});
    try {
        const q = `(SELECT id, changed_at, changed_by_username, 'edit' AS event_type, field_changed, old_value, new_value, NULL AS amount_paid, NULL AS payment_type FROM loan_history WHERE loan_id = $1) UNION ALL (SELECT id, payment_date AS changed_at, changed_by_username, 'transaction' AS event_type, NULL AS field_changed, NULL AS old_value, NULL AS new_value, amount_paid, payment_type FROM Transactions WHERE loan_id = $1) ORDER BY changed_at DESC`;
        const resH = await db.query(q, [loanId]);
        res.json(resH.rows);
    } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/branches', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    if (req.user.role === 'admin') { const r = await db.query("SELECT * FROM branches ORDER BY id ASC"); res.json(r.rows); }
    else { const r = await db.query("SELECT * FROM branches WHERE id = $1", [req.user.branchId]); res.json(r.rows); }
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/branches/:id', authenticateToken, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (req.user.role !== 'admin' && req.user.branchId !== id) return res.status(403).send("Denied");
    const r = await db.query("SELECT * FROM branches WHERE id = $1", [id]);
    if (r.rows.length === 0) return res.status(404).send("Not found");
    res.json(r.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.post('/api/branches', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { branch_name, branch_code, address, phone_number } = req.body;
    if (!branch_name || !branch_code) return res.status(400).json({ error: "Name/Code required." });
    const r = await db.query("INSERT INTO branches (branch_name, branch_code, address, phone_number) VALUES ($1, $2, $3, $4) RETURNING *", [branch_name, branch_code, address, phone_number]);
    res.status(201).json(r.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.put('/api/branches/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { branch_name, branch_code, address, phone_number, license_number, is_active } = req.body;
    const ex = await db.query("SELECT * FROM branches WHERE id = $1", [id]);
    if (ex.rows.length === 0) return res.status(404).send("Not found");
    const old = ex.rows[0];
    const r = await db.query(`UPDATE branches SET branch_name=$1, branch_code=$2, address=$3, phone_number=$4, license_number=$5, is_active=$6 WHERE id=$7 RETURNING *`,
      [branch_name||old.branch_name, branch_code||old.branch_code, address||old.address, phone_number||old.phone_number, license_number||old.license_number, is_active!==undefined?is_active:old.is_active, id]);
    res.json(r.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req);
    let wc = " WHERE 1=1 "; const p = [];
    if (targetBranch) { wc += ` AND branch_id = $1`; p.push(targetBranch); }
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'" + (targetBranch ? ` AND branch_id=${targetBranch}` : ""));
    const [pRes, aRes, oRes, cRes, lRes, pdRes, fRes, dRes] = await Promise.all([
      db.query(`SELECT SUM(principal_amount) FROM Loans ${wc} AND (status='active' OR status='overdue')`, p),
      db.query(`SELECT COUNT(*) FROM Loans ${wc} AND (status='active' OR status='overdue')`, p),
      db.query(`SELECT COUNT(*) FROM Loans ${wc} AND status='overdue'`, p),
      db.query(`SELECT COUNT(*) FROM Customers ${wc} AND is_deleted=false`, p),
      db.query(`SELECT COUNT(*) FROM Loans ${wc} AND status!='deleted'`, p),
      db.query(`SELECT COUNT(*) FROM Loans ${wc} AND status='paid'`, p),
      db.query(`SELECT COUNT(*) FROM Loans ${wc} AND status='forfeited'`, p),
      db.query(`SELECT SUM(principal_amount) FROM Loans ${wc} AND status!='deleted'`, p)
    ]);
    let totalInt = 0;
    const lQ = `SELECT * FROM Loans ${wc} AND (status='active' OR status='overdue')`;
    const lR = await db.query(lQ, p);
    if (lR.rows.length > 0) {
        const ids = lR.rows.map(l => l.id);
        const tR = await db.query(`SELECT * FROM Transactions WHERE loan_id = ANY($1::int[])`, [ids]);
        for (const loan of lR.rows) {
            const txs = tR.rows.filter(t => t.loan_id === loan.id);
            const fin = calculateLoanFinancials(loan, txs);
            totalInt += parseFloat(fin.outstandingInterest);
        }
    }
    res.json({
      totalPrincipalOut: parseFloat(pRes.rows[0].sum || 0),
      totalInterestAccrued: totalInt, 
      totalActiveLoans: parseInt(aRes.rows[0].count || 0),
      totalOverdueLoans: parseInt(oRes.rows[0].count || 0),
      totalCustomers: parseInt(cRes.rows[0].count || 0),
      totalLoans: parseInt(lRes.rows[0].count || 0),
      totalValue: parseFloat(dRes.rows[0].sum || 0),
      loansActive: parseInt(aRes.rows[0].count || 0),
      loansOverdue: parseInt(oRes.rows[0].count || 0),
      loansPaid: parseInt(pdRes.rows[0].count || 0),
      loansForfeited: parseInt(fRes.rows[0].count || 0)
    });
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/reports/financial-summary', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    if (!startDate || !endDate) return res.status(400).json({ error: "Required." });
    const targetBranch = getTargetBranchId(req);
    const p = [startDate, endDate]; let bc = "";
    if (targetBranch) { bc = " AND l.branch_id = $3"; p.push(targetBranch); }
    const q1 = `SELECT SUM(t.amount_paid) as total FROM Transactions t JOIN Loans l ON t.loan_id=l.id WHERE t.payment_type='disbursement' AND t.payment_date >= $1 AND t.payment_date <= $2 ${bc}`;
    const q2 = `SELECT SUM(t.amount_paid) as total FROM Transactions t JOIN Loans l ON t.loan_id=l.id WHERE t.payment_type='interest' AND t.payment_date >= $1 AND t.payment_date <= $2 ${bc}`;
    const q3 = `SELECT SUM(t.amount_paid) as total FROM Transactions t JOIN Loans l ON t.loan_id=l.id WHERE (t.payment_type='principal' OR t.payment_type='settlement') AND t.payment_date >= $1 AND t.payment_date <= $2 ${bc}`;
    const q4 = `SELECT SUM(t.amount_paid) as total FROM Transactions t JOIN Loans l ON t.loan_id=l.id WHERE t.payment_type='discount' AND t.payment_date >= $1 AND t.payment_date <= $2 ${bc}`;
    const q5 = `SELECT COUNT(*) as count FROM Loans l WHERE l.pledge_date >= $1 AND l.pledge_date <= $2 ${targetBranch ? 'AND l.branch_id = $3' : ''}`;
    const [r1, r2, r3, r4, r5] = await Promise.all([db.query(q1,p), db.query(q2,p), db.query(q3,p), db.query(q4,p), db.query(q5,p)]);
    res.json({ startDate, endDate, totalDisbursed: parseFloat(r1.rows[0].total||0), totalInterest: parseFloat(r2.rows[0].total||0), totalPrincipalRepaid: parseFloat(r3.rows[0].total||0), totalDiscount: parseFloat(r4.rows[0].total||0), netProfit: parseFloat(r2.rows[0].total||0)-parseFloat(r4.rows[0].total||0), loansCreatedCount: parseInt(r5.rows[0].count||0) });
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/reports/day-book', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const dateParam = req.query.date; if (!dateParam) return res.status(400).json({ error: "Date required" });
    const targetBranch = getTargetBranchId(req); const p = [dateParam]; let bc = "";
    if (targetBranch) { bc = " AND l.branch_id = $2"; p.push(targetBranch); }
    const q1 = `SELECT SUM(CASE WHEN t.payment_type IN ('interest','principal','settlement') THEN t.amount_paid ELSE 0 END) - SUM(CASE WHEN t.payment_type='disbursement' THEN t.amount_paid ELSE 0 END) as balance FROM Transactions t JOIN Loans l ON t.loan_id=l.id WHERE (t.payment_date AT TIME ZONE 'Asia/Kolkata')::date < $1::date ${bc}`;
    const q2 = `SELECT t.*, l.book_loan_number, c.name as customer_name FROM Transactions t JOIN Loans l ON t.loan_id=l.id JOIN Customers c ON l.customer_id=c.id WHERE (t.payment_date AT TIME ZONE 'Asia/Kolkata')::date = $1::date AND t.payment_type != 'discount' ${bc} ORDER BY t.payment_date ASC`;
    const [r1, r2] = await Promise.all([db.query(q1, p), db.query(q2, p)]);
    res.json({ date: dateParam, openingBalance: parseFloat(r1.rows[0].balance||0), transactions: r2.rows });
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/recycle-bin/deleted', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const targetBranch = getTargetBranchId(req); const p = []; let cw = " WHERE is_deleted=true"; let lw = " WHERE l.status='deleted' AND c.is_deleted=false";
    if (targetBranch) { cw += " AND branch_id=$1"; lw += " AND l.branch_id=$1"; p.push(targetBranch); }
    const [c, l] = await Promise.all([db.query(`SELECT id, name, phone_number, 'Customer' as type FROM Customers ${cw}`, p), db.query(`SELECT l.id, l.book_loan_number, c.name as customer_name, 'Loan' as type FROM Loans l JOIN Customers c ON l.customer_id=c.id ${lw}`, p)]);
    res.json({ customers: c.rows, loans: l.rows });
  } catch (err) { res.status(500).send("Error"); }
});

app.post('/api/customers/:id/restore', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const check = await db.query("SELECT branch_id FROM Customers WHERE id=$1", [id]);
    if (check.rows.length === 0) return res.status(404).send("Not found");
    if (req.user.role !== 'admin' && check.rows[0].branch_id !== req.user.branchId) return res.status(403).send("Denied");
    await db.query("UPDATE Customers SET is_deleted=false WHERE id=$1", [id]);
    await db.query("UPDATE Loans SET status='paid' WHERE customer_id=$1 AND status='deleted'", [id]);
    res.json({ message: "Restored." });
  } catch (err) { res.status(500).send("Error"); }
});

app.delete('/api/customers/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    const id = parseInt(req.params.id); const client = await db.pool.connect();
    try { await client.query('BEGIN');
        const lR = await client.query("SELECT id FROM Loans WHERE customer_id=$1", [id]);
        const lIds = lR.rows.map(r => r.id);
        if (lIds.length > 0) { const s = lIds.join(','); await client.query(`DELETE FROM PledgedItems WHERE loan_id IN (${s})`); await client.query(`DELETE FROM Transactions WHERE loan_id IN (${s})`); await client.query(`DELETE FROM loan_history WHERE loan_id IN (${s})`); await client.query(`DELETE FROM Loans WHERE customer_id=$1`, [id]); }
        await client.query("DELETE FROM Customers WHERE id=$1 AND is_deleted=true", [id]);
        await client.query('COMMIT'); res.json({ message: "Deleted." });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error"); } finally { client.release(); }
});

app.post('/api/loans/:id/restore', authenticateToken, authorizeManagement, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const check = await db.query("SELECT branch_id FROM Loans WHERE id=$1", [id]);
    if (check.rows.length === 0) return res.status(404).send("Not found");
    if (req.user.role !== 'admin' && check.rows[0].branch_id !== req.user.branchId) return res.status(403).send("Denied");
    await db.query("UPDATE Loans SET status='paid' WHERE id=$1 AND status='deleted'", [id]);
    res.json({ message: "Restored." });
  } catch (err) { res.status(500).send("Error"); }
});

app.delete('/api/loans/:id/permanent-delete', authenticateToken, authorizeAdmin, async (req, res) => {
    const id = parseInt(req.params.id); const client = await db.pool.connect();
    try { await client.query('BEGIN');
        await client.query("DELETE FROM PledgedItems WHERE loan_id=$1", [id]);
        await client.query("DELETE FROM Transactions WHERE loan_id=$1", [id]);
        await client.query("DELETE FROM loan_history WHERE loan_id=$1", [id]);
        await client.query("DELETE FROM Loans WHERE id=$1 AND status='deleted'", [id]);
        await client.query('COMMIT'); res.json({ message: "Deleted." });
    } catch (err) { await client.query('ROLLBACK'); res.status(500).send("Error"); } finally { client.release(); }
});

app.get('/api/settings', async (req, res) => {
  try { const r = await db.query("SELECT * FROM business_settings WHERE id=1"); if(r.rows.length>0) res.json(r.rows[0]); else res.json({ business_name: 'Bankers' }); } catch (err) { res.status(500).send("Error"); }
});

app.put('/api/settings', authenticateToken, authorizeAdmin, upload.single('logo'), async (req, res) => {
  try {
    const { business_name, address, phone_number, license_number, navbar_display_mode } = req.body;
    let logoUrl = req.body.existingLogoUrl;
    if (req.file) { const b64 = req.file.buffer.toString('base64'); logoUrl = `data:${req.file.mimetype};base64,${b64}`; }
    const q = `INSERT INTO business_settings (id, business_name, address, phone_number, license_number, logo_url, navbar_display_mode, updated_at) VALUES (1, $1, $2, $3, $4, $5, $6, NOW()) ON CONFLICT (id) DO UPDATE SET business_name=$1, address=$2, phone_number=$3, license_number=$4, logo_url=$5, navbar_display_mode=$6, updated_at=NOW() RETURNING *`;
    const r = await db.query(q, [business_name, address, phone_number, license_number, logoUrl, navbar_display_mode||'both']);
    res.json(r.rows[0]);
  } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query; if (!q || q.trim() === '') return res.json([]);
    const cq = `%${q.trim()}%`; const targetBranch = getTargetBranchId(req); const p = [cq];
    let lSql = `SELECT id, book_loan_number, principal_amount, branch_id FROM Loans WHERE book_loan_number ILIKE $1 AND status!='deleted'`;
    let cSql = `SELECT id, name, phone_number, branch_id FROM Customers WHERE (name ILIKE $1 OR phone_number ILIKE $1) AND is_deleted=false`;
    if (targetBranch) { lSql += ` AND branch_id=$2`; cSql += ` AND branch_id=$2`; p.push(targetBranch); }
    const [lR, cR] = await Promise.all([db.query(lSql+" LIMIT 3", p), db.query(cSql+" LIMIT 5", p)]);
    const resArr = [];
    lR.rows.forEach(l => resArr.push({ type: 'loan', id: l.id, title: `Loan #${l.book_loan_number}`, subtitle: `₹${l.principal_amount}` }));
    cR.rows.forEach(c => resArr.push({ type: 'customer', id: c.id, title: c.name, subtitle: c.phone_number }));
    res.json(resArr);
  } catch (err) { res.status(500).send("Error"); }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});