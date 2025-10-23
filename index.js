const express = require('express');
const db = require('./db');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
const PORT = 3001;

// --- MULTER & FILE SERVING CONFIG ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- UTILITY ROUTE ---
app.get('/', async (req, res) => {
  try {
    const { rows } = await db.query('SELECT NOW()');
    res.status(200).json({ message: "Welcome!", db_status: "Connected", db_time: rows[0].now });
  } catch (err) {
    res.status(500).json({ message: "DB connection failed.", db_status: "Error" });
  }
});

// --- CUSTOMER ROUTES ---
app.get('/api/customers', async (req, res) => {
  try {
    const allCustomers = await db.query("SELECT id, name, phone_number, address FROM Customers ORDER BY name ASC");
    res.json(allCustomers.rows);
  } catch (err) { res.status(500).send("Server Error"); }
});

// === GET A SINGLE CUSTOMER (ROBUST VERSION) ===
app.get('/api/customers/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id); // Ensure ID is treated as a number
    if (isNaN(id)) { // Check if the ID is a valid number
      return res.status(400).json({ error: "Invalid customer ID." });
    }

    const customerResult = await db.query("SELECT * FROM Customers WHERE id = $1", [id]);

    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: "Customer not found." });
    }

    // Convert BYTEA image buffer to Base64 Data URL if it exists
    const customerData = customerResult.rows[0];
    if (customerData.customer_image_url) {
        const imageBase64 = customerData.customer_image_url.toString('base64');
        let mimeType = 'image/jpeg'; // Basic inference, adjust if needed
        if (imageBase64.startsWith('/9j/')) mimeType = 'image/jpeg';
        else if (imageBase64.startsWith('iVBORw0KGgo')) mimeType = 'image/png';
        customerData.customer_image_url = `data:${mimeType};base64,${imageBase64}`;
    }

    res.json(customerData); 
  } catch (err) { 
    console.error("GET Customer Error:", err.message);
    res.status(500).send("Server Error"); 
  }
});

app.post('/api/customers', upload.single('photo'), async (req, res) => {
  try {
    const { name, phone_number, address } = req.body;
    // Get the image data as a Buffer from memory
    const imageBuffer = req.file ? req.file.buffer : null; 

    if (!name || !phone_number) return res.status(400).json({ error: 'Name and phone are required.' });

    // Insert the Buffer into the BYTEA column
    const newCustomerResult = await db.query(
      "INSERT INTO Customers (name, phone_number, address, customer_image_url) VALUES ($1, $2, $3, $4) RETURNING id, name, phone_number, address", // Don't return image here
      [name, phone_number, address, imageBuffer] // Pass the buffer directly
    );

    res.status(201).json(newCustomerResult.rows[0]); // Send back data without the image buffer

  } catch (err) { 
    console.error("POST Customer Error:", err.message);
    res.status(500).send("Server Error"); 
  }
});

app.put('/api/customers/:id', upload.single('photo'), async (req, res) => {
  try {
    const id = parseInt(req.params.id);
     if (isNaN(id)) return res.status(400).json({ error: "Invalid ID." });
    const { name, phone_number, address } = req.body;
    let imageBuffer = null;
    let updateImage = false; // Flag to know if we need to update the image column

    if (req.file) { // New image uploaded
      imageBuffer = req.file.buffer;
      updateImage = true;
    } else if (req.body.removeCurrentImage === 'true') { // Request to remove image
       imageBuffer = null; // Set to null to clear the DB field
       updateImage = true;
    } // If no file and no remove flag, we don't update the image column

    let query;
    let values;

    if (updateImage) {
      // Update all fields including the image
      query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3, customer_image_url = $4 WHERE id = $5 RETURNING id, name, phone_number, address";
      values = [name, phone_number, address, imageBuffer, id];
    } else {
      // Update only text fields, leave image as is
      query = "UPDATE Customers SET name = $1, phone_number = $2, address = $3 WHERE id = $4 RETURNING id, name, phone_number, address";
      values = [name, phone_number, address, id];
    }

    const updateCustomerResult = await db.query(query, values);

    if (updateCustomerResult.rows.length === 0) return res.status(404).json({ error: "Customer not found." });

    res.json(updateCustomerResult.rows[0]); // Send back updated data (without image)

  } catch (err) {
    console.error("PUT Customer Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// --- LOAN ROUTES ---
app.get('/api/loans', async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'"); // Update status first
    const query = `
      SELECT l.id, l.book_loan_number, l.principal_amount, l.pledge_date, l.due_date,
             c.name AS customer_name, c.phone_number
      FROM Loans l JOIN Customers c ON l.customer_id = c.id
      WHERE l.status = 'active'
      ORDER BY l.pledge_date DESC`;
    const allLoans = await db.query(query);
    res.json(allLoans.rows);
  } catch (err) {
    console.error("GET Loans Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// === CREATE A NEW PLEDGE LOAN (with Item Photo in DB) ===
// Use upload.single() middleware for the item photo
app.post('/api/loans', upload.single('itemPhoto'), async (req, res) => {
  const client = await db.pool.connect();
  try {
    const { 
      customer_id, principal_amount, interest_rate, book_loan_number, 
      item_type, description, quality, weight 
    } = req.body;

    // Get the item image buffer from req.file
    const itemImageBuffer = req.file ? req.file.buffer : null; 

    await client.query('BEGIN');

    const loanQuery = `INSERT INTO Loans (customer_id, principal_amount, interest_rate, book_loan_number) VALUES ($1, $2, $3, $4) RETURNING id`;
    const loanResult = await client.query(loanQuery, [customer_id, principal_amount, interest_rate, book_loan_number]);
    const newLoanId = loanResult.rows[0].id;

    // Update item query to include item_image_data
    const itemQuery = `INSERT INTO PledgedItems (loan_id, item_type, description, quality, weight, item_image_data) VALUES ($1, $2, $3, $4, $5, $6)`;
    await client.query(itemQuery, [newLoanId, item_type, description, quality, weight, itemImageBuffer]); // Pass buffer

    await client.query('COMMIT');
    res.status(201).json({ message: "Loan created successfully", loanId: newLoanId });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("POST Loan Error:", err.message);
    if (err.code === '23505') return res.status(400).send("Error: Book Loan Number already exists.");
    res.status(500).send("Server Error while creating loan");
  } finally { client.release(); }
});

app.get('/api/customers/:id/loans', async (req, res) => {
  try {
    const { id } = req.params;
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'"); // Update status first
    const query = `
      SELECT l.id AS loan_id, l.principal_amount, l.pledge_date, l.due_date, pi.description,
      CASE WHEN l.status = 'paid' THEN 'paid' WHEN l.status = 'forfeited' THEN 'forfeited' WHEN l.status = 'overdue' THEN 'overdue' ELSE 'active' END AS status
      FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id
      WHERE l.customer_id = $1 ORDER BY l.pledge_date DESC`;
    const customerLoans = await db.query(query, [id]);
    res.json(customerLoans.rows);
  } catch (err) {
    console.error("Error fetching customer loans:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/:id', async (req, res) => { /* ... */ });
app.get('/api/loans/find-by-book-number/:bookNumber', async (req, res) => { /* ... */ });

// === GET A SINGLE LOAN (with Item Photo from DB) ===
app.get('/api/loans/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Ensure the query selects item_image_data
    const loanQuery = `SELECT l.*, pi.item_type, pi.description, pi.quality, pi.weight, pi.item_image_data FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id WHERE l.id = $1`;
    const loanResult = await db.query(loanQuery, [id]);

    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });

    let loanDetails = loanResult.rows[0];

    // Convert item image BYTEA to Base64 Data URL
    if (loanDetails.item_image_data) {
      const imageBase64 = loanDetails.item_image_data.toString('base64');
      let mimeType = 'image/jpeg'; // Default assumption
      // Basic MIME type inference (can be expanded)
      if (imageBase64.startsWith('/9j/')) mimeType = 'image/jpeg';
      else if (imageBase64.startsWith('iVBORw0KGgo')) mimeType = 'image/png';
      // ... add more checks ...
      loanDetails.item_image_data_url = `data:${mimeType};base64,${imageBase64}`; // Store as a new property
    }
    delete loanDetails.item_image_data; // Remove the large buffer

    const transactionsResult = await db.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date DESC", [id]);

    res.json({ loanDetails: loanDetails, transactions: transactionsResult.rows });
  } catch (err) { 
    console.error("GET Loan Details Error:", err.message);
    res.status(500).send("Server Error"); 
  }
});

app.get('/api/loans/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const loanQuery = `SELECT l.*, pi.* FROM Loans l LEFT JOIN PledgedItems pi ON l.id = pi.loan_id WHERE l.id = $1`;
    const loanResult = await db.query(loanQuery, [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    const transactionsResult = await db.query("SELECT * FROM Transactions WHERE loan_id = $1 ORDER BY payment_date DESC", [id]);
    res.json({ loanDetails: loanResult.rows[0], transactions: transactionsResult.rows });
  } catch (err) {
    console.error("GET Loan Details Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/find-by-book-number/:bookNumber', async (req, res) => {
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

// --- TRANSACTION & SETTLEMENT ---
app.post('/api/transactions', async (req, res) => {
  try {
    const { loan_id, amount_paid, payment_type } = req.body;
    if (!loan_id || !amount_paid) return res.status(400).json({ error: 'Loan ID and amount are required.' });
    const newTransaction = await db.query("INSERT INTO Transactions (loan_id, amount_paid, payment_type) VALUES ($1, $2, $3) RETURNING *", [loan_id, amount_paid, payment_type || 'payment']);
    res.status(201).json(newTransaction.rows[0]);
  } catch (err) {
    console.error("POST Transaction Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.post('/api/loans/:id/settle', async (req, res) => {
  try {
    const { id } = req.params;
    const { discountAmount } = req.body;
    const discount = parseFloat(discountAmount) || 0;
    const loanResult = await db.query("SELECT * FROM Loans WHERE id = $1", [id]);
    if (loanResult.rows.length === 0) return res.status(404).json({ error: "Loan not found." });
    const loan = loanResult.rows[0];
    const principal = parseFloat(loan.principal_amount);
    const interestRate = parseFloat(loan.interest_rate);
    const pledgeDate = new Date(loan.pledge_date);
    const today = new Date();
    const daysElapsed = Math.max(1, Math.ceil((today - pledgeDate) / (1000 * 60 * 60 * 24)));
    const totalInterest = (principal * interestRate * daysElapsed) / (100 * 365);
    const totalOwed = principal + totalInterest;
    const transactionsResult = await db.query("SELECT SUM(amount_paid) AS total_paid FROM Transactions WHERE loan_id = $1", [id]);
    const totalPaid = parseFloat(transactionsResult.rows[0].total_paid) || 0;
    const finalBalance = totalOwed - totalPaid - discount;
    if (finalBalance > 1) return res.status(400).json({ error: `Cannot close loan. After a discount of ₹${discount.toFixed(2)}, an outstanding balance of ₹${finalBalance.toFixed(2)} still remains.` });
    const closeLoan = await db.query("UPDATE Loans SET status = 'paid' WHERE id = $1 RETURNING *", [id]);
    res.json({ message: `Loan successfully closed with a discount of ₹${discount.toFixed(2)}.`, loan: closeLoan.rows[0] });
  } catch (err) {
    console.error("Settle Loan Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// --- DASHBOARD & OVERDUE ROUTES ---
app.get('/api/dashboard/stats', async (req, res) => {
  try {
    await db.query("UPDATE Loans SET status = 'overdue' WHERE due_date < NOW() AND status = 'active'");
    const activePromise = db.query("SELECT COUNT(*) FROM Loans WHERE status = 'active' OR status = 'overdue'");
    const disbursedPromise = db.query("SELECT SUM(principal_amount) FROM Loans WHERE status = 'active' OR status = 'overdue'");
    const overduePromise = db.query("SELECT COUNT(*) FROM Loans WHERE status = 'overdue'");
    const [active, disbursed, overdue] = await Promise.all([activePromise, disbursedPromise, overduePromise]);
    res.json({ active_loans: active.rows[0].count, total_disbursed: disbursed.rows[0].sum || 0, overdue_loans: overdue.rows[0].count });
  } catch (err) {
    console.error("Dashboard Stats Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/recent/created', async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) {
    console.error("Recent Created Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.get('/api/loans/recent/closed', async (req, res) => {
  try {
    const query = `SELECT l.id, l.principal_amount, c.name AS customer_name FROM Loans l LEFT JOIN Customers c ON l.customer_id = c.id WHERE l.status = 'paid' ORDER BY l.created_at DESC LIMIT 5`;
    res.json((await db.query(query)).rows);
  } catch (err) {
    console.error("Recent Closed Error:", err.message);
    res.status(500).send("Server Error");
  }
});

// === UPDATE A CUSTOMER (with Photo Upload) ===
app.put('/api/customers/:id', upload.single('photo'), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone_number, address } = req.body;
    let imageUrl = req.body.existingImageUrl || null; 

    if (req.file) {
      imageUrl = req.file.path.replace(/\\/g, "/"); 
    }

    const updateCustomer = await db.query(
      "UPDATE Customers SET name = $1, phone_number = $2, address = $3, customer_image_url = $4 WHERE id = $5 RETURNING *",
      [name, phone_number, address, imageUrl, id]
    );

    if (updateCustomer.rows.length === 0) {
      return res.status(404).json({ error: "Customer not found." });
    }
    res.json(updateCustomer.rows[0]);
  } catch (err) {
    console.error("PUT Customer Error:", err.message);
    res.status(500).send("Server Error");
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});