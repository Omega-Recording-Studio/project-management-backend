const express = require('express');
const { body, validationResult, param } = require('express-validator');
const { 
  authenticateToken, 
  requireUser, 
  requireAdmin,
  requireOwnerOrAdmin,
  canAccessProjects,
  canDeleteProjects
} = require('../middleware/auth');

const router = express.Router();

// Apply authentication to all project routes
router.use(authenticateToken);

// =====================================================
// PROJECT ROUTES
// =====================================================

// GET /api/projects - Get all projects (with filtering)
router.get('/', async (req, res) => {
  try {
    // Check if user can access projects
    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project access requires user, madmin, or admin role.' 
      });
    }

    const pool = req.app.locals.db;
    const { status, search, user_id, limit = 50, offset = 0 } = req.query;

    // Build dynamic query
    let query = `
      SELECT 
        p.*,
        u.name as created_by_name,
        u.username as created_by_username
      FROM projects p
      LEFT JOIN users u ON p.created_by = u.id
      WHERE 1=1
    `;
    
    const queryParams = [];
    let paramCount = 0;

    // Apply filters
    if (status) {
      paramCount++;
      query += ` AND p.status = $${paramCount}`;
      queryParams.push(status);
    }

    if (search) {
      paramCount++;
      query += ` AND (p.name ILIKE $${paramCount} OR p.description ILIKE $${paramCount})`;
      queryParams.push(`%${search}%`);
    }

    if (user_id) {
      paramCount++;
      query += ` AND p.created_by = $${paramCount}`;
      queryParams.push(user_id);
    }

    // For regular users, only show their own projects unless they're admin/madmin
    if (!req.user.roles.includes('admin') && !req.user.roles.includes('madmin')) {
      paramCount++;
      query += ` AND p.created_by = $${paramCount}`;
      queryParams.push(req.user.id);
    }

    // Add ordering and pagination
    query += ` ORDER BY p.created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    queryParams.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, queryParams);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM projects p
      WHERE 1=1
    `;
    
    const countParams = [];
    let countParamCount = 0;

    if (status) {
      countParamCount++;
      countQuery += ` AND p.status = $${countParamCount}`;
      countParams.push(status);
    }

    if (search) {
      countParamCount++;
      countQuery += ` AND (p.name ILIKE $${countParamCount} OR p.description ILIKE $${countParamCount})`;
      countParams.push(`%${search}%`);
    }

    if (user_id) {
      countParamCount++;
      countQuery += ` AND p.created_by = $${countParamCount}`;
      countParams.push(user_id);
    }

    if (!req.user.roles.includes('admin') && !req.user.roles.includes('madmin')) {
      countParamCount++;
      countQuery += ` AND p.created_by = $${countParamCount}`;
      countParams.push(req.user.id);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    res.json({
      projects: result.rows,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < total
      }
    });

  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch projects' 
    });
  }
});

// GET /api/projects/:id - Get single project
router.get('/:id', [
  param('id').isUUID().withMessage('Invalid project ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project access requires user, madmin, or admin role.' 
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    const result = await pool.query(`
      SELECT 
        p.*,
        u.name as created_by_name,
        u.username as created_by_username,
        u.email as created_by_email
      FROM projects p
      LEFT JOIN users u ON p.created_by = u.id
      WHERE p.id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Project not found' 
      });
    }

    const project = result.rows[0];

    // Check if user can access this specific project
    if (!req.user.roles.includes('admin') && 
        !req.user.roles.includes('madmin') && 
        project.created_by !== req.user.id) {
      return res.status(403).json({ 
        error: 'Access denied. You can only view your own projects.' 
      });
    }

    res.json(project);

  } catch (error) {
    console.error('Get project error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch project' 
    });
  }
});

// POST /api/projects - Create new project
router.post('/', [
  body('name')
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Project name is required and must be less than 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Description must be less than 5000 characters'),
  body('start_date')
    .isISO8601()
    .withMessage('Valid start date is required (YYYY-MM-DD)'),
  body('end_date')
    .optional()
    .isISO8601()
    .withMessage('End date must be valid (YYYY-MM-DD)'),
  body('status')
    .optional()
    .isIn(['pending', 'ongoing', 'completed'])
    .withMessage('Status must be pending, ongoing, or completed')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project creation requires user, madmin, or admin role.' 
      });
    }

    const { name, description, start_date, end_date, status = 'pending' } = req.body;
    const pool = req.app.locals.db;

    // Validate date logic
    if (end_date && new Date(end_date) < new Date(start_date)) {
      return res.status(400).json({ 
        error: 'End date cannot be before start date' 
      });
    }

    // For regular users, end_date can only be set when status is completed
    if (!req.user.roles.includes('admin') && !req.user.roles.includes('madmin')) {
      if (end_date && status !== 'completed') {
        return res.status(400).json({ 
          error: 'End date can only be set when project status is completed' 
        });
      }
    }

    const result = await pool.query(`
      INSERT INTO projects (name, description, start_date, end_date, status, created_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [name, description, start_date, end_date, status, req.user.id]);

    const newProject = result.rows[0];

    // Get creator details
    const userResult = await pool.query(
      'SELECT name, username FROM users WHERE id = $1',
      [req.user.id]
    );

    res.status(201).json({
      message: 'Project created successfully',
      project: {
        ...newProject,
        created_by_name: userResult.rows[0]?.name,
        created_by_username: userResult.rows[0]?.username
      }
    });

  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ 
      error: 'Failed to create project' 
    });
  }
});

// PUT /api/projects/:id - Update project
router.put('/:id', [
  param('id').isUUID().withMessage('Invalid project ID'),
  body('name')
    .optional()
    .trim()
    .isLength({ min: 1, max: 255 })
    .withMessage('Project name must be less than 255 characters'),
  body('description')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Description must be less than 5000 characters'),
  body('start_date')
    .optional()
    .isISO8601()
    .withMessage('Start date must be valid (YYYY-MM-DD)'),
  body('end_date')
    .optional()
    .isISO8601()
    .withMessage('End date must be valid (YYYY-MM-DD)'),
  body('status')
    .optional()
    .isIn(['pending', 'ongoing', 'completed'])
    .withMessage('Status must be pending, ongoing, or completed')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project access requires user, madmin, or admin role.' 
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    // First, get the existing project
    const existingProject = await pool.query(
      'SELECT * FROM projects WHERE id = $1',
      [id]
    );

    if (existingProject.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Project not found' 
      });
    }

    const project = existingProject.rows[0];

    // Check permissions
    const canEdit = req.user.roles.includes('admin') || 
                   req.user.roles.includes('madmin') || 
                   project.created_by === req.user.id;

    if (!canEdit) {
      return res.status(403).json({ 
        error: 'Access denied. You can only edit your own projects.' 
      });
    }

    const updates = req.body;

    // For regular users, validate end_date rules
    if (!req.user.roles.includes('admin') && !req.user.roles.includes('madmin')) {
      if (updates.end_date && updates.status !== 'completed') {
        return res.status(400).json({ 
          error: 'End date can only be set when project status is completed' 
        });
      }
    }

    // Build dynamic update query
    const updateFields = [];
    const updateValues = [];
    let paramCount = 0;

    for (const [key, value] of Object.entries(updates)) {
      if (['name', 'description', 'start_date', 'end_date', 'status'].includes(key)) {
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
      UPDATE projects 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramCount}
      RETURNING *
    `;

    const result = await pool.query(updateQuery, updateValues);
    const updatedProject = result.rows[0];

    // Get creator details
    const userResult = await pool.query(
      'SELECT name, username FROM users WHERE id = $1',
      [updatedProject.created_by]
    );

    res.json({
      message: 'Project updated successfully',
      project: {
        ...updatedProject,
        created_by_name: userResult.rows[0]?.name,
        created_by_username: userResult.rows[0]?.username
      }
    });

  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ 
      error: 'Failed to update project' 
    });
  }
});

// PUT /api/projects/:id/complete - Mark project as completed
router.put('/:id/complete', [
  param('id').isUUID().withMessage('Invalid project ID')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project access requires user, madmin, or admin role.' 
      });
    }

    const pool = req.app.locals.db;
    const { id } = req.params;

    // Get existing project
    const existingProject = await pool.query(
      'SELECT * FROM projects WHERE id = $1',
      [id]
    );

    if (existingProject.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Project not found' 
      });
    }

    const project = existingProject.rows[0];

    // Check permissions
    const canComplete = req.user.roles.includes('admin') || 
                       req.user.roles.includes('madmin') || 
                       project.created_by === req.user.id;

    if (!canComplete) {
      return res.status(403).json({ 
        error: 'Access denied. You can only complete your own projects.' 
      });
    }

    if (project.status === 'completed') {
      return res.status(400).json({ 
        error: 'Project is already completed' 
      });
    }

    // Mark as completed with current date as end_date
    const result = await pool.query(`
      UPDATE projects 
      SET status = 'completed', 
          end_date = CURRENT_DATE,
          updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `, [id]);

    const completedProject = result.rows[0];

    // Get creator details
    const userResult = await pool.query(
      'SELECT name, username FROM users WHERE id = $1',
      [completedProject.created_by]
    );

    res.json({
      message: 'Project marked as completed',
      project: {
        ...completedProject,
        created_by_name: userResult.rows[0]?.name,
        created_by_username: userResult.rows[0]?.username
      }
    });

  } catch (error) {
    console.error('Complete project error:', error);
    res.status(500).json({ 
      error: 'Failed to complete project' 
    });
  }
});

// DELETE /api/projects/:id - Delete project (Admin only)
router.delete('/:id', [
  requireAdmin,
  param('id').isUUID().withMessage('Invalid project ID')
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

    // Check if project exists
    const existingProject = await pool.query(
      'SELECT * FROM projects WHERE id = $1',
      [id]
    );

    if (existingProject.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Project not found' 
      });
    }

    // Delete project (CASCADE will handle related records)
    await pool.query('DELETE FROM projects WHERE id = $1', [id]);

    res.json({
      message: 'Project deleted successfully'
    });

  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ 
      error: 'Failed to delete project' 
    });
  }
});

// GET /api/projects/stats/overview - Get project statistics
router.get('/stats/overview', async (req, res) => {
  try {
    if (!canAccessProjects(req.user.roles)) {
      return res.status(403).json({ 
        error: 'Access denied. Project access requires user, madmin, or admin role.' 
      });
    }

    const pool = req.app.locals.db;

    // Build query based on user role
    let whereClause = '';
    let queryParams = [];

    if (!req.user.roles.includes('admin') && !req.user.roles.includes('madmin')) {
      whereClause = 'WHERE created_by = $1';
      queryParams.push(req.user.id);
    }

    const statsQuery = `
      SELECT 
        COUNT(*) as total_projects,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_projects,
        COUNT(CASE WHEN status = 'ongoing' THEN 1 END) as ongoing_projects,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_projects,
        ROUND(
          COUNT(CASE WHEN status = 'completed' THEN 1 END) * 100.0 / 
          NULLIF(COUNT(*), 0), 
          2
        ) as completion_rate
      FROM projects
      ${whereClause}
    `;

    const result = await pool.query(statsQuery, queryParams);
    const stats = result.rows[0];

    res.json({
      stats: {
        total: parseInt(stats.total_projects),
        pending: parseInt(stats.pending_projects),
        ongoing: parseInt(stats.ongoing_projects),
        completed: parseInt(stats.completed_projects),
        completionRate: parseFloat(stats.completion_rate) || 0
      }
    });

  } catch (error) {
    console.error('Get project stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch project statistics' 
    });
  }
});

module.exports = router;