const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// PostgreSQL connection using DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Middleware to check technician role
const requireTechnician = (req, res, next) => {
  if (req.user.role !== 'technician') {
    return res.status(403).json({ error: 'Technician access required' });
  }
  next();
};

// Initialize default admin (run once)
const initializeAdmin = async () => {
  try {
    const checkAdmin = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
    
    if (checkAdmin.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO admins (username, password, role) VALUES ($1, $2, $3)',
        ['admin', hashedPassword, 'admin']
      );
      console.log('Default admin created: username=admin, password=admin123');
    }
  } catch (error) {
    console.error('Error initializing admin:', error);
  }
};

// Routes

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const admin = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, admin.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        role: admin.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create Technician (Admin only)
app.post('/api/technicians', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, fullName } = req.body;

    if (!username || !password || !fullName) {
      return res.status(400).json({ error: 'Username, password, and full name required' });
    }

    // Check if username already exists
    const existingUser = await pool.query(
      'SELECT * FROM technicians WHERE username = $1',
      [username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO technicians (username, password, full_name, role, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [username, hashedPassword, fullName, 'technician', req.user.id]
    );

    const technician = result.rows[0];
    delete technician.password;

    res.status(201).json({
      message: 'Technician created successfully',
      technician
    });
  } catch (error) {
    console.error('Create technician error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get All Technicians (Admin only)
app.get('/api/technicians', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, full_name, role, created_at FROM technicians ORDER BY created_at DESC'
    );

    res.json({
      technicians: result.rows
    });
  } catch (error) {
    console.error('Get technicians error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Technician Login
app.post('/api/technician/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const result = await pool.query('SELECT * FROM technicians WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const technician = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, technician.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: technician.id, username: technician.username, role: technician.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      technician: {
        id: technician.id,
        username: technician.username,
        fullName: technician.full_name,
        role: technician.role
      }
    });
  } catch (error) {
    console.error('Technician login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register Individual (Admin only)
app.post('/api/individuals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const {
      fullName,
      province,
      district,
      sector,
      cell,
      village,
      idNumber,
      plotNumber
    } = req.body;

    if (!fullName || !province || !district || !sector || !cell || !village || !idNumber || !plotNumber) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if ID number already exists
    const existingIndividual = await pool.query(
      'SELECT * FROM individuals WHERE id_number = $1',
      [idNumber]
    );

    if (existingIndividual.rows.length > 0) {
      return res.status(409).json({ error: 'ID number already exists' });
    }

    const result = await pool.query(
      `INSERT INTO individuals 
       (full_name, province, district, sector, cell, village, id_number, plot_number, registered_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [fullName, province, district, sector, cell, village, idNumber, plotNumber, req.user.id]
    );

    res.status(201).json({
      message: 'Individual registered successfully',
      individual: result.rows[0]
    });
  } catch (error) {
    console.error('Register individual error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get All Individuals (Admin only)
app.get('/api/individuals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT i.*, t.full_name as technician_name, t.username as technician_username
      FROM individuals i
      LEFT JOIN technicians t ON i.assigned_technician = t.id
      ORDER BY i.registration_date DESC
    `);

    res.json({
      individuals: result.rows
    });
  } catch (error) {
    console.error('Get individuals error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Assign Technician to Individual (Admin only)
app.put('/api/individuals/:id/assign-technician', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { technicianId } = req.body;

    if (!technicianId) {
      return res.status(400).json({ error: 'Technician ID required' });
    }

    // Check if technician exists
    const technicianCheck = await pool.query('SELECT * FROM technicians WHERE id = $1', [technicianId]);
    if (technicianCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Technician not found' });
    }

    // Check if individual exists
    const individualCheck = await pool.query('SELECT * FROM individuals WHERE id = $1', [id]);
    if (individualCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Individual not found' });
    }

    const result = await pool.query(
      'UPDATE individuals SET assigned_technician = $1 WHERE id = $2 RETURNING *',
      [technicianId, id]
    );

    res.json({
      message: 'Technician assigned successfully',
      individual: result.rows[0]
    });
  } catch (error) {
    console.error('Assign technician error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Assigned Individuals (Technician only)
app.get('/api/technician/assigned-individuals', authenticateToken, requireTechnician, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM individuals WHERE assigned_technician = $1 ORDER BY registration_date DESC',
      [req.user.id]
    );

    res.json({
      assignedIndividuals: result.rows
    });
  } catch (error) {
    console.error('Get assigned individuals error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate Report (Technician only)
app.post('/api/reports', authenticateToken, requireTechnician, async (req, res) => {
  try {
    const { individualId, reportTitle, reportContent, reportType } = req.body;

    if (!individualId || !reportTitle || !reportContent) {
      return res.status(400).json({ error: 'Individual ID, report title, and content are required' });
    }

    // Check if individual is assigned to this technician
    const individualCheck = await pool.query(
      'SELECT * FROM individuals WHERE id = $1 AND assigned_technician = $2',
      [individualId, req.user.id]
    );

    if (individualCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Individual not found or not assigned to you' });
    }

    const result = await pool.query(
      `INSERT INTO reports 
       (individual_id, technician_id, report_title, report_content, report_type) 
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [individualId, req.user.id, reportTitle, reportContent, reportType || 'general']
    );

    res.status(201).json({
      message: 'Report generated successfully',
      report: result.rows[0]
    });
  } catch (error) {
    console.error('Generate report error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Reports by Technician
app.get('/api/technician/reports', authenticateToken, requireTechnician, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, i.full_name as individual_name, i.id_number
      FROM reports r
      JOIN individuals i ON r.individual_id = i.id
      WHERE r.technician_id = $1
      ORDER BY r.created_at DESC
    `, [req.user.id]);

    res.json({
      reports: result.rows
    });
  } catch (error) {
    console.error('Get technician reports error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get All Reports (Admin only)
app.get('/api/reports', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, i.full_name as individual_name, i.id_number, t.full_name as technician_name
      FROM reports r
      JOIN individuals i ON r.individual_id = i.id
      JOIN technicians t ON r.technician_id = t.id
      ORDER BY r.created_at DESC
    `);

    res.json({
      reports: result.rows
    });
  } catch (error) {
    console.error('Get all reports error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeAdmin();
});

// Export for testing
module.exports = app;
