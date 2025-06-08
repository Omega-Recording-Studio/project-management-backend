const express = require('express');
const { body, validationResult, param } = require('express-validator');
const { 
  authenticateToken, 
  requireAdminOrMadmin,
  requireAdmin,
  canAccessBilling 
} = require('../middleware/auth');

const router = express.Router();

// Apply authentication and billing access to all invoice routes
router.use(authenticateToken);
router.use((req, res, next) => {
  if (!canAccessBilling(req.user.roles)) {
    return res.status(403).json({ 
      error: 'Access denied. Billing access requires admin or madmin role.' 
    });
  }
  next();
});

// =====================================================
// INVOICE ROUTES
// =====================================================

// GET /api/invoices - Get all invoices
router.get('/', async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const { status, client_id, project_id, limit = 50, offset = 0, search } = req.query;

    // Build dynamic query
    let query = `
      SELECT 
        i.*,
        c.name as client_name,
        c.email as client_email,
        p.name as project_name
      FROM invoices i
      LEFT JOIN users c ON i.client_id = c.id
      LEFT JOIN projects p ON i.project_id = p.id
      WHERE 1=1
    `;
    
    const queryParams = [];
    let paramCount = 0;

    // Apply filters
    if (status) {
      paramCount++;
      query += ` AND i.status = $${paramCount}`;
      queryParams.push(status);
    }

    if (client_id) {
      paramCount++;
      query += ` AND i.client_id = $${paramCount}`;
      queryParams.push(client_id);
    }

    if (project_id) {
      paramCount++;
      query += ` AND i.project_id = $${paramCount}`;
      queryParams.push(project_id);
    }

    if (search) {
      paramCount++;
      query += ` AND (i.number ILIKE $${paramCount} OR i.description ILIKE $${paramCount} OR c.name ILIKE $${paramCount})`;
      queryParams.push(`%${search}%`);
    }

    // Add ordering and pagination
    query += ` ORDER BY i.created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    queryParams.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, queryParams);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM invoices i
      LEFT JOIN users c ON i.client_id = c.id
      WHERE 1=1
    `;
    
    const countParams = [];
    let countParamCount = 0;

    if (status) {
      countParamCount++;
      countQuery += ` AND i.status = $${countParamCount}`;
      countParams.push(status);
    }

    if (client_id) {
      countParamCount++;
      countQuery += ` AND i.client_id = $${countParamCount}`;
      countParams.push(client_id);
    }

    if (project_id) {
      countParamCount++;
      countQuery += ` AND i.project_id = $${countParamCount}`;
      countParams.push(project_id);
    }

    if (search) {
      countParamCount++;
      countQuery += ` AND (i.number ILIKE $${countParamCount} OR i.description ILIKE $${countParamCount} OR c.name ILIKE $${countParamCount})`;
      countParams.push(`%${search}%`);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    // Check for overdue invoices and update status
    await pool.query(`
      UPDATE invoices 
      SET status = 'overdue' 
      WHERE status = 'pending' 
      AND due_date < CURRENT_DATE
    `);

    res.json({
      invoices: result.rows,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < total
      }
    });

  } catch (error) {
    console.error('Get invoices error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch invoices' 
    });
  }
});

// GET /api/invoices/:id - Get single invoice
router.get('/:id', [
  param('id').isUUID().withMessage('Invalid invoice ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    const result = await pool.query(`
      SELECT 
        i.*,
        c.name as client_name,
        c.email as client_email,
        c.username as client_username,
        p.name as project_name,
        p.description as project_description
      FROM invoices i
      LEFT JOIN users c ON i.client_id = c.id
      LEFT JOIN projects p ON i.project_id = p.id
      WHERE i.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Invoice not found' 
      });
    }

    const invoice = result.rows[0];

    res.json(invoice);

  } catch (error) {
    console.error('Get invoice error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch invoice' 
    });
  }
});

// POST /api/invoices - Create new invoice
router.post('/', [
  body('client_id')
    .isUUID()
    .withMessage('Valid client ID is required'),
  body('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be valid UUID'),
  body('amount')
    .isNumeric()
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be a positive number'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Description must be less than 5000 characters'),
  body('date')
    .isISO8601()
    .withMessage('Valid invoice date is required (YYYY-MM-DD)'),
  body('due_date')
    .isISO8601()
    .withMessage('Valid due date is required (YYYY-MM-DD)')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { client_id, project_id, amount, description, date, due_date } = req.body;
    const pool = req.app.locals.db;

    // Validate that client exists and is approved
    const clientResult = await pool.query(
      'SELECT name, email, approved FROM users WHERE id = $1',
      [client_id]
    );

    if (clientResult.rows.length === 0) {
      return res.status(400).json({ 
        error: 'Client not found' 
      });
    }

    const client = clientResult.rows[0];
    if (!client.approved) {
      return res.status(400).json({ 
        error: 'Cannot create invoice for unapproved client' 
      });
    }

    // Validate project if provided
    if (project_id) {
      const projectResult = await pool.query(
        'SELECT name FROM projects WHERE id = $1',
        [project_id]
      );

      if (projectResult.rows.length === 0) {
        return res.status(400).json({ 
          error: 'Project not found' 
        });
      }
    }

    // Validate date logic
    if (new Date(due_date) < new Date(date)) {
      return res.status(400).json({ 
        error: 'Due date cannot be before invoice date' 
      });
    }

    // Generate invoice number
    const year = new Date(date).getFullYear();
    const countResult = await pool.query(
      'SELECT COUNT(*) as count FROM invoices WHERE EXTRACT(YEAR FROM date) = $1',
      [year]
    );
    
    const invoiceCount = parseInt(countResult.rows[0].count) + 1;
    const invoiceNumber = `${year}${String(invoiceCount).padStart(4, '0')}`;

    const result = await pool.query(`
      INSERT INTO invoices (number, client_id, project_id, amount, description, date, due_date, status, paid_amount)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `, [invoiceNumber, client_id, project_id, amount, description, date, due_date, 'pending', 0]);

    const newInvoice = result.rows[0];

    res.status(201).json({
      message: 'Invoice created successfully',
      invoice: {
        ...newInvoice,
        client_name: client.name,
        client_email: client.email
      }
    });

  } catch (error) {
    console.error('Create invoice error:', error);
    res.status(500).json({ 
      error: 'Failed to create invoice' 
    });
  }
});

// PUT /api/invoices/:id - Update invoice
router.put('/:id', [
  param('id').isUUID().withMessage('Invalid invoice ID'),
  body('client_id')
    .optional()
    .isUUID()
    .withMessage('Client ID must be valid UUID'),
  body('project_id')
    .optional()
    .isUUID()
    .withMessage('Project ID must be valid UUID'),
  body('amount')
    .optional()
    .isNumeric()
    .isFloat({ min: 0.01 })
    .withMessage('Amount must be a positive number'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Description must be less than 5000 characters'),
  body('date')
    .optional()
    .isISO8601()
    .withMessage('Invoice date must be valid (YYYY-MM-DD)'),
  body('due_date')
    .optional()
    .isISO8601()
    .withMessage('Due date must be valid (YYYY-MM-DD)'),
  body('status')
    .optional()
    .isIn(['pending', 'paid', 'overdue', 'cancelled'])
    .withMessage('Status must be pending, paid, overdue, or cancelled')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    // Get existing invoice
    const existingInvoice = await pool.query(
      'SELECT * FROM invoices WHERE id = $1',
      [id]
    );

    if (existingInvoice.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Invoice not found' 
      });
    }

    const invoice = existingInvoice.rows[0];
    const updates = req.body;

    // Validate client if being updated
    if (updates.client_id) {
      const clientResult = await pool.query(
        'SELECT approved FROM users WHERE id = $1',
        [updates.client_id]
      );

      if (clientResult.rows.length === 0 || !clientResult.rows[0].approved) {
        return res.status(400).json({ 
          error: 'Invalid or unapproved client' 
        });
      }
    }

    // Validate project if being updated
    if (updates.project_id) {
      const projectResult = await pool.query(
        'SELECT id FROM projects WHERE id = $1',
        [updates.project_id]
      );

      if (projectResult.rows.length === 0) {
        return res.status(400).json({ 
          error: 'Project not found' 
        });
      }
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];
    let paramCount = 0;

    for (const [key, value] of Object.entries(updates)) {
      if (['client_id', 'project_id', 'amount', 'description', 'date', 'due_date', 'status'].includes(key)) {
        paramCount++;
        updateFields.push(`${key} = $${paramCount}`);
        updateValues.push(value);
      }
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ 
        error: 'No valid fields to update' 
      });
    }

    // Add updated_at
    paramCount++;
    updateFields.push(`updated_at = $${paramCount}`);
    updateValues.push(new Date());

    // Add ID for WHERE clause
    paramCount++;
    updateValues.push(id);

    const updateQuery = `
      UPDATE invoices 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedInvoice = result.rows[0];

    // Get client and project details
    const detailsResult = await pool.query(`
      SELECT 
        c.name as client_name,
        c.email as client_email,
        p.name as project_name
      FROM invoices i
      LEFT JOIN users c ON i.client_id = c.id
      LEFT JOIN projects p ON i.project_id = p.id
      WHERE i.id = $1
    `, [id]);

    const details = detailsResult.rows[0];

    res.json({
      message: 'Invoice updated successfully',
      invoice: {
        ...updatedInvoice,
        ...details
      }
    });

  } catch (error) {
    console.error('Update invoice error:', error);
    res.status(500).json({ 
      error: 'Failed to update invoice' 
    });
  }
});

// PUT /api/invoices/:id/payment - Add payment to invoice
router.put('/:id/payment', [
  param('id').isUUID().withMessage('Invalid invoice ID'),
  body('amount')
    .isNumeric()
    .isFloat({ min: 0.01 })
    .withMessage('Payment amount must be a positive number'),
  body('markAsPaid')
    .optional()
    .isBoolean()
    .withMessage('markAsPaid must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;
    const { amount, markAsPaid = false } = req.body;

    // Get existing invoice
    const existingInvoice = await pool.query(
      'SELECT * FROM invoices WHERE id = $1',
      [id]
    );

    if (existingInvoice.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Invoice not found' 
      });
    }

    const invoice = existingInvoice.rows[0];

    if (invoice.status === 'cancelled') {
      return res.status(400).json({ 
        error: 'Cannot add payment to cancelled invoice' 
      });
    }

    const currentPaidAmount = parseFloat(invoice.paid_amount);
    const invoiceAmount = parseFloat(invoice.amount);
    const paymentAmount = parseFloat(amount);

    // Validate payment amount
    if (markAsPaid) {
      // Mark as fully paid - set paid amount to invoice amount
      var newPaidAmount = invoiceAmount;
      var newStatus = 'paid';
    } else {
      // Add partial payment
      var newPaidAmount = currentPaidAmount + paymentAmount;
      
      if (newPaidAmount > invoiceAmount) {
        return res.status(400).json({ 
          error: `Payment amount exceeds remaining balance. Remaining: $${(invoiceAmount - currentPaidAmount).toFixed(2)}` 
        });
      }

      // Determine new status
      var newStatus = newPaidAmount >= invoiceAmount ? 'paid' : 'pending';
    }

    const result = await pool.query(`
      UPDATE invoices 
      SET paid_amount = $1, status = $2, updated_at = NOW()
      WHERE id = $3
      RETURNING *
    `, [newPaidAmount, newStatus, id]);

    const updatedInvoice = result.rows[0];

    res.json({
      message: markAsPaid ? 'Invoice marked as paid' : 'Payment added successfully',
      invoice: updatedInvoice,
      payment: {
        amount: markAsPaid ? (invoiceAmount - currentPaidAmount) : paymentAmount,
        newBalance: invoiceAmount - newPaidAmount,
        totalPaid: newPaidAmount
      }
    });

  } catch (error) {
    console.error('Add payment error:', error);
    res.status(500).json({ 
      error: 'Failed to add payment' 
    });
  }
});

// DELETE /api/invoices/:id - Delete invoice (Admin only)
router.delete('/:id', [
  requireAdmin,
  param('id').isUUID().withMessage('Invalid invoice ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    // Check if invoice exists
    const existingInvoice = await pool.query(
      'SELECT number FROM invoices WHERE id = $1',
      [id]
    );

    if (existingInvoice.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Invoice not found' 
      });
    }

    const invoiceNumber = existingInvoice.rows[0].number;

    // Delete invoice
    await pool.query('DELETE FROM invoices WHERE id = $1', [id]);

    res.json({
      message: `Invoice ${invoiceNumber} deleted successfully`
    });

  } catch (error) {
    console.error('Delete invoice error:', error);
    res.status(500).json({ 
      error: 'Failed to delete invoice' 
    });
  }
});

// GET /api/invoices/stats/overview - Get invoice statistics
router.get('/stats/overview', async (req, res) => {
  try {
    const pool = req.app.locals.db;

    const statsQuery = `
      SELECT 
        COUNT(*) as total_invoices,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_invoices,
        COUNT(CASE WHEN status = 'paid' THEN 1 END) as paid_invoices,
        COUNT(CASE WHEN status = 'overdue' THEN 1 END) as overdue_invoices,
        COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_invoices,
        COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END), 0) as pending_revenue,
        COALESCE(SUM(CASE WHEN status = 'overdue' THEN amount ELSE 0 END), 0) as overdue_revenue,
        COALESCE(AVG(CASE WHEN status = 'paid' THEN amount END), 0) as average_invoice_amount
      FROM invoices
    `;

    const result = await pool.query(statsQuery);
    const stats = result.rows[0];

    res.json({
      stats: {
        total: parseInt(stats.total_invoices),
        pending: parseInt(stats.pending_invoices),
        paid: parseInt(stats.paid_invoices),
        overdue: parseInt(stats.overdue_invoices),
        cancelled: parseInt(stats.cancelled_invoices),
        totalRevenue: parseFloat(stats.total_revenue),
        pendingRevenue: parseFloat(stats.pending_revenue),
        overdueRevenue: parseFloat(stats.overdue_revenue),
        averageAmount: parseFloat(stats.average_invoice_amount)
      }
    });

  } catch (error) {
    console.error('Get invoice stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch invoice statistics' 
    });
  }
});

// GET /api/invoices/export/csv - Export invoices as CSV
router.get('/export/csv', async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const { status, start_date, end_date } = req.query;

    // Build query with filters
    let query = `
      SELECT 
        i.number,
        i.date,
        i.due_date,
        i.amount,
        i.paid_amount,
        i.status,
        i.description,
        c.name as client_name,
        c.email as client_email,
        p.name as project_name
      FROM invoices i
      LEFT JOIN users c ON i.client_id = c.id
      LEFT JOIN projects p ON i.project_id = p.id
      WHERE 1=1
    `;
    
    const queryParams = [];
    let paramCount = 0;

    if (status) {
      paramCount++;
      query += ` AND i.status = $${paramCount}`;
      queryParams.push(status);
    }

    if (start_date) {
      paramCount++;
      query += ` AND i.date >= $${paramCount}`;
      queryParams.push(start_date);
    }

    if (end_date) {
      paramCount++;
      query += ` AND i.date <= $${paramCount}`;
      queryParams.push(end_date);
    }

    query += ` ORDER BY i.date DESC`;

    const result = await pool.query(query, queryParams);

    // Generate CSV content
    const headers = [
      'Invoice Number', 'Date', 'Due Date', 'Amount', 'Paid Amount', 
      'Balance', 'Status', 'Client Name', 'Client Email', 'Project', 'Description'
    ];
    
    let csvContent = headers.join(',') + '\n';
    
    result.rows.forEach(row => {
      const balance = (parseFloat(row.amount) - parseFloat(row.paid_amount)).toFixed(2);
      const csvRow = [
        `"${row.number}"`,
        `"${row.date}"`,
        `"${row.due_date}"`,
        `"${row.amount}"`,
        `"${row.paid_amount}"`,
        `"${balance}"`,
        `"${row.status}"`,
        `"${row.client_name || ''}"`,
        `"${row.client_email || ''}"`,
        `"${row.project_name || ''}"`,
        `"${(row.description || '').replace(/"/g, '""')}"`
      ];
      csvContent += csvRow.join(',') + '\n';
    });

    // Set headers for file download
    const filename = `invoices_export_${new Date().toISOString().split('T')[0]}.csv`;
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    
    res.send(csvContent);

  } catch (error) {
    console.error('Export CSV error:', error);
    res.status(500).json({ 
      error: 'Failed to export invoices' 
    });
  }
});

module.exports = router;