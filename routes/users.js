const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult, param } = require('express-validator');
const { 
  authenticateToken, 
  requireAdmin, 
  requireAdminOrMadmin 
} = require('../middleware/auth');

const router = express.Router();

// Apply authentication to all user routes
router.use(authenticateToken);

// =====================================================
// USER MANAGEMENT ROUTES
// =====================================================

// GET /api/users - Get all users (Admin only)
router.get('/', requireAdmin, async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const { limit = 50, offset = 0, approved, search } = req.query;

    // Build dynamic query
    let query = `
      SELECT 
        id, email, username, name, roles, approved, created_at, updated_at
      FROM users
      WHERE 1=1
    `;
    
    const queryParams = [];
    let paramCount = 0;

    // Filter by approval status
    if (approved !== undefined) {
      paramCount++;
      query += ` AND approved = $${paramCount}`;
      queryParams.push(approved === 'true');
    }

    // Search filter
    if (search) {
      paramCount++;
      query += ` AND (name ILIKE $${paramCount} OR email ILIKE $${paramCount} OR username ILIKE $${paramCount})`;
      queryParams.push(`%${search}%`);
    }

    // Add ordering and pagination
    query += ` ORDER BY created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    queryParams.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, queryParams);

    // Get total count
    let countQuery = 'SELECT COUNT(*) as total FROM users WHERE 1=1';
    const countParams = [];
    let countParamCount = 0;

    if (approved !== undefined) {
      countParamCount++;
      countQuery += ` AND approved = $${countParamCount}`;
      countParams.push(approved === 'true');
    }

    if (search) {
      countParamCount++;
      countQuery += ` AND (name ILIKE $${countParamCount} OR email ILIKE $${countParamCount} OR username ILIKE $${countParamCount})`;
      countParams.push(`%${search}%`);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    res.json({
      users: result.rows,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < total
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch users' 
    });
  }
});

// GET /api/users/:id - Get single user
router.get('/:id', [
  param('id').isUUID().withMessage('Invalid user ID')
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

    // Users can view their own profile, admins can view any profile
    if (id !== req.user.id && !req.user.roles.includes('admin')) {
      return res.status(403).json({ 
        error: 'Access denied. You can only view your own profile.' 
      });
    }

    const result = await pool.query(`
      SELECT 
        id, email, username, name, roles, approved, created_at, updated_at
      FROM users 
      WHERE id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    const user = result.rows[0];

    // Get user's project statistics if they have project access
    const userRoles = user.roles || [];
    let projectStats = null;

    if (userRoles.includes('user') || userRoles.includes('admin') || userRoles.includes('madmin')) {
      const statsResult = await pool.query(`
        SELECT 
          COUNT(*) as total_projects,
          COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_projects,
          COUNT(CASE WHEN status = 'ongoing' THEN 1 END) as ongoing_projects,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_projects
        FROM projects
        WHERE created_by = $1
      `, [id]);

      if (statsResult.rows.length > 0) {
        const stats = statsResult.rows[0];
        projectStats = {
          total: parseInt(stats.total_projects),
          pending: parseInt(stats.pending_projects),
          ongoing: parseInt(stats.ongoing_projects),
          completed: parseInt(stats.completed_projects)
        };
      }
    }

    res.json({
      user,
      projectStats
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch user' 
    });
  }
});

// POST /api/users - Create new user (Admin only)
router.post('/', [
  requireAdmin,
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('name')
    .trim()
    .isLength({ min: 2 })
    .withMessage('Name must be at least 2 characters'),
  body('username')
    .trim()
    .isLength({ min: 3 })
    .withMessage('Username must be at least 3 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('roles')
    .isArray()
    .withMessage('Roles must be an array')
    .custom((roles) => {
      const validRoles = ['staff', 'user', 'madmin', 'admin'];
      const invalidRoles = roles.filter(role => !validRoles.includes(role));
      if (invalidRoles.length > 0) {
        throw new Error(`Invalid roles: ${invalidRoles.join(', ')}`);
      }
      if (!roles.includes('staff')) {
        throw new Error('All users must have staff role');
      }
      return true;
    }),
  body('approved')
    .optional()
    .isBoolean()
    .withMessage('Approved must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { email, password, name, username, roles, approved = true } = req.body;
    const pool = req.app.locals.db;

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        error: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (email, username, password_hash, name, roles, approved)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, email, username, name, roles, approved, created_at
    `, [email, username, passwordHash, name, roles, approved]);

    const newUser = result.rows[0];

    res.status(201).json({
      message: 'User created successfully',
      user: newUser
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ 
      error: 'Failed to create user' 
    });
  }
});

// PUT /api/users/:id - Update user
router.put('/:id', [
  param('id').isUUID().withMessage('Invalid user ID'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2 })
    .withMessage('Name must be at least 2 characters'),
  body('username')
    .optional()
    .trim()
    .isLength({ min: 3 })
    .withMessage('Username must be at least 3 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('roles')
    .optional()
    .isArray()
    .withMessage('Roles must be an array')
    .custom((roles) => {
      const validRoles = ['staff', 'user', 'madmin', 'admin'];
      const invalidRoles = roles.filter(role => !validRoles.includes(role));
      if (invalidRoles.length > 0) {
        throw new Error(`Invalid roles: ${invalidRoles.join(', ')}`);
      }
      if (!roles.includes('staff')) {
        throw new Error('All users must have staff role');
      }
      return true;
    }),
  body('approved')
    .optional()
    .isBoolean()
    .withMessage('Approved must be a boolean')
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

    // Check permissions
    const isOwnProfile = id === req.user.id;
    const isAdmin = req.user.roles.includes('admin');

    if (!isOwnProfile && !isAdmin) {
      return res.status(403).json({ 
        error: 'Access denied. You can only update your own profile or must be admin.' 
      });
    }

    // Get existing user
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    const user = existingUser.rows[0];
    const updates = req.body;

    // Regular users can only update their own name, email, username
    if (!isAdmin) {
      const allowedFields = ['name', 'email', 'username'];
      const submittedFields = Object.keys(updates);
      const invalidFields = submittedFields.filter(field => !allowedFields.includes(field));
      
      if (invalidFields.length > 0) {
        return res.status(403).json({ 
          error: `Access denied. You can only update: ${allowedFields.join(', ')}` 
        });
      }
    }

    // Check for duplicate email/username
    if (updates.email || updates.username) {
      const duplicateCheck = await pool.query(
        'SELECT id FROM users WHERE (email = $1 OR username = $2) AND id != $3',
        [updates.email || user.email, updates.username || user.username, id]
      );

      if (duplicateCheck.rows.length > 0) {
        return res.status(400).json({ 
          error: 'Email or username already exists' 
        });
      }
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];
    let paramCount = 0;

    const allowedFields = isAdmin ? 
      ['name', 'email', 'username', 'roles', 'approved'] : 
      ['name', 'email', 'username'];

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
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
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING id, email, username, name, roles, approved, created_at, updated_at
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedUser = result.rows[0];

    res.json({
      message: 'User updated successfully',
      user: updatedUser
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ 
      error: 'Failed to update user' 
    });
  }
});

// PUT /api/users/:id/password - Reset user password (Admin only)
router.put('/:id/password', [
  requireAdmin,
  param('id').isUUID().withMessage('Invalid user ID'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
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
    const { newPassword } = req.body;

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT username, email FROM users WHERE id = $1',
      [id]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    // Hash new password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, id]
    );

    res.json({
      message: `Password reset successfully for user: ${existingUser.rows[0].username}`
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      error: 'Failed to reset password' 
    });
  }
});

// PUT /api/users/:id/approve - Approve user (Admin only)
router.put('/:id/approve', [
  requireAdmin,
  param('id').isUUID().withMessage('Invalid user ID')
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

    // Check if user exists
    const existingUser = await pool.query(
      'SELECT username, email, approved FROM users WHERE id = $1',
      [id]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    const user = existingUser.rows[0];

    if (user.approved) {
      return res.status(400).json({ 
        error: 'User is already approved' 
      });
    }

    // Approve user
    await pool.query(
      'UPDATE users SET approved = true, updated_at = NOW() WHERE id = $1',
      [id]
    );

    res.json({
      message: `User approved successfully: ${user.username} (${user.email})`
    });

  } catch (error) {
    console.error('Approve user error:', error);
    res.status(500).json({ 
      error: 'Failed to approve user' 
    });
  }
});

// GET /api/users/stats/overview - Get user statistics (Admin only)
router.get('/stats/overview', requireAdmin, async (req, res) => {
  try {
    const pool = req.app.locals.db;

    const statsQuery = `
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN approved = true THEN 1 END) as approved_users,
        COUNT(CASE WHEN approved = false THEN 1 END) as pending_users,
        COUNT(CASE WHEN 'admin' = ANY(roles) THEN 1 END) as admin_users,
        COUNT(CASE WHEN 'madmin' = ANY(roles) THEN 1 END) as madmin_users,
        COUNT(CASE WHEN 'user' = ANY(roles) THEN 1 END) as user_role_users,
        COUNT(CASE WHEN array_length(roles, 1) = 1 AND 'staff' = ANY(roles) THEN 1 END) as staff_only_users
      FROM users
    `;

    const result = await pool.query(statsQuery);
    const stats = result.rows[0];

    res.json({
      stats: {
        total: parseInt(stats.total_users),
        approved: parseInt(stats.approved_users),
        pending: parseInt(stats.pending_users),
        admins: parseInt(stats.admin_users),
        madmins: parseInt(stats.madmin_users),
        users: parseInt(stats.user_role_users),
        staffOnly: parseInt(stats.staff_only_users)
      }
    });

  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch user statistics' 
    });
  }
});

module.exports = router;