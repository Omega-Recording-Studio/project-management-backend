const express = require('express');
const { body, validationResult, param } = require('express-validator');
const { authenticateToken, requireStaff } = require('../middleware/auth');

const router = express.Router();

// Apply authentication to all time entry routes
router.use(authenticateToken);

// =====================================================
// TIME TRACKING ROUTES
// =====================================================

// GET /api/time-entries - Get time entries for current user
router.get('/', async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const { limit = 10, offset = 0, date, month } = req.query;

    // Build query with filters
    let query = `
      SELECT * FROM time_entries 
      WHERE user_id = $1
    `;
    const queryParams = [req.user.id];
    let paramCount = 1;

    // Filter by specific date
    if (date) {
      paramCount++;
      query += ` AND date = $${paramCount}`;
      queryParams.push(date);
    }

    // Filter by month (YYYY-MM format)
    if (month) {
      paramCount++;
      query += ` AND date >= $${paramCount}`;
      queryParams.push(`${month}-01`);
      
      paramCount++;
      query += ` AND date < $${paramCount}`;
      // Calculate next month
      const [year, monthNum] = month.split('-');
      const nextMonth = parseInt(monthNum) === 12 ? 
        `${parseInt(year) + 1}-01-01` : 
        `${year}-${String(parseInt(monthNum) + 1).padStart(2, '0')}-01`;
      queryParams.push(nextMonth);
    }

    // Add ordering and pagination
    query += ` ORDER BY created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    queryParams.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, queryParams);

    // Get total count
    let countQuery = `
      SELECT COUNT(*) as total FROM time_entries WHERE user_id = $1
    `;
    const countParams = [req.user.id];
    let countParamCount = 1;

    if (date) {
      countParamCount++;
      countQuery += ` AND date = $${countParamCount}`;
      countParams.push(date);
    }

    if (month) {
      countParamCount++;
      countQuery += ` AND date >= $${countParamCount}`;
      countParams.push(`${month}-01`);
      
      countParamCount++;
      countQuery += ` AND date < $${countParamCount}`;
      const [year, monthNum] = month.split('-');
      const nextMonth = parseInt(monthNum) === 12 ? 
        `${parseInt(year) + 1}-01-01` : 
        `${year}-${String(parseInt(monthNum) + 1).padStart(2, '0')}-01`;
      countParams.push(nextMonth);
    }

    const countResult = await pool.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    // Calculate duration for each entry
    const entriesWithDuration = result.rows.map(entry => {
      let duration = null;
      if (entry.clock_out) {
        const clockIn = new Date(entry.clock_in);
        const clockOut = new Date(entry.clock_out);
        const diffMs = clockOut - clockIn;
        const hours = Math.floor(diffMs / (1000 * 60 * 60));
        const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
        duration = `${hours}:${String(minutes).padStart(2, '0')}`;
      }
      
      return {
        ...entry,
        duration
      };
    });

    res.json({
      timeEntries: entriesWithDuration,
      pagination: {
        total,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: (parseInt(offset) + parseInt(limit)) < total
      }
    });

  } catch (error) {
    console.error('Get time entries error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch time entries' 
    });
  }
});

// GET /api/time-entries/current - Get current active time entry
router.get('/current', async (req, res) => {
  try {
    const pool = req.app.locals.db;

    const result = await pool.query(`
      SELECT * FROM time_entries 
      WHERE user_id = $1 AND clock_out IS NULL
      ORDER BY created_at DESC
      LIMIT 1
    `, [req.user.id]);

    if (result.rows.length === 0) {
      return res.json({
        currentEntry: null,
        isClockedIn: false
      });
    }

    const entry = result.rows[0];
    const clockIn = new Date(entry.clock_in);
    const now = new Date();
    const diffMs = now - clockIn;
    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    const currentDuration = `${hours}:${String(minutes).padStart(2, '0')}`;

    res.json({
      currentEntry: {
        ...entry,
        currentDuration
      },
      isClockedIn: true
    });

  } catch (error) {
    console.error('Get current time entry error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch current time entry' 
    });
  }
});

// GET /api/time-entries/today - Get today's summary
router.get('/today', async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const today = new Date().toISOString().split('T')[0];

    const result = await pool.query(`
      SELECT * FROM time_entries 
      WHERE user_id = $1 AND date = $2
      ORDER BY created_at DESC
    `, [req.user.id, today]);

    let totalWorkedMs = 0;
    let clockInTime = null;
    let clockOutTime = null;
    let status = 'Not Started';
    let isCurrentlyClockedIn = false;

    if (result.rows.length > 0) {
      // Get first entry for clock in time
      const firstEntry = result.rows[result.rows.length - 1];
      clockInTime = firstEntry.clock_in;

      // Check if currently clocked in
      const currentEntry = result.rows.find(entry => !entry.clock_out);
      if (currentEntry) {
        isCurrentlyClockedIn = true;
        status = 'In Progress';
      } else {
        status = 'Completed';
        // Get last clock out time
        const lastEntry = result.rows[0];
        clockOutTime = lastEntry.clock_out;
      }

      // Calculate total worked time
      result.rows.forEach(entry => {
        if (entry.clock_out) {
          const clockIn = new Date(entry.clock_in);
          const clockOut = new Date(entry.clock_out);
          totalWorkedMs += (clockOut - clockIn);
        } else if (isCurrentlyClockedIn) {
          // Add current session time
          const clockIn = new Date(entry.clock_in);
          const now = new Date();
          totalWorkedMs += (now - clockIn);
        }
      });
    }

    // Format total worked time
    const totalHours = Math.floor(totalWorkedMs / (1000 * 60 * 60));
    const totalMinutes = Math.floor((totalWorkedMs % (1000 * 60 * 60)) / (1000 * 60));
    const totalWorked = `${totalHours}:${String(totalMinutes).padStart(2, '0')}`;

    res.json({
      date: today,
      clockInTime,
      clockOutTime,
      totalWorked,
      status,
      isCurrentlyClockedIn,
      entriesCount: result.rows.length
    });

  } catch (error) {
    console.error('Get today summary error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch today\'s summary' 
    });
  }
});

// GET /api/time-entries/stats - Get time tracking statistics
router.get('/stats', async (req, res) => {
  try {
    const pool = req.app.locals.db;
    const { period = 'month' } = req.query; // week, month, year

    let dateFilter = '';
    let periodName = '';

    switch (period) {
      case 'week':
        dateFilter = `date >= CURRENT_DATE - INTERVAL '7 days'`;
        periodName = 'This Week';
        break;
      case 'year':
        dateFilter = `date >= CURRENT_DATE - INTERVAL '1 year'`;
        periodName = 'This Year';
        break;
      default: // month
        dateFilter = `date >= CURRENT_DATE - INTERVAL '30 days'`;
        periodName = 'This Month';
    }

    const statsQuery = `
      SELECT 
        COUNT(*) as total_entries,
        COUNT(CASE WHEN clock_out IS NOT NULL THEN 1 END) as completed_entries,
        COUNT(CASE WHEN clock_out IS NULL THEN 1 END) as active_entries,
        COUNT(DISTINCT date) as days_worked,
        COALESCE(
          SUM(
            CASE 
              WHEN clock_out IS NOT NULL THEN 
                EXTRACT(EPOCH FROM (clock_out - clock_in)) / 3600
              ELSE 0
            END
          ), 
          0
        ) as total_hours
      FROM time_entries 
      WHERE user_id = $1 AND ${dateFilter}
    `;

    const result = await pool.query(statsQuery, [req.user.id]);
    const stats = result.rows[0];

    // Get average hours per day
    const avgHoursPerDay = stats.days_worked > 0 ? 
      (parseFloat(stats.total_hours) / parseInt(stats.days_worked)).toFixed(2) : 0;

    res.json({
      period: periodName,
      stats: {
        totalEntries: parseInt(stats.total_entries),
        completedEntries: parseInt(stats.completed_entries),
        activeEntries: parseInt(stats.active_entries),
        daysWorked: parseInt(stats.days_worked),
        totalHours: parseFloat(stats.total_hours).toFixed(2),
        averageHoursPerDay: parseFloat(avgHoursPerDay)
      }
    });

  } catch (error) {
    console.error('Get time stats error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch time statistics' 
    });
  }
});

// POST /api/time-entries/clock-in - Clock in
router.post('/clock-in', async (req, res) => {
  try {
    const pool = req.app.locals.db;

    // Check if user is already clocked in
    const existingEntry = await pool.query(`
      SELECT id FROM time_entries 
      WHERE user_id = $1 AND clock_out IS NULL
    `, [req.user.id]);

    if (existingEntry.rows.length > 0) {
      return res.status(400).json({ 
        error: 'You are already clocked in. Please clock out first.' 
      });
    }

    const now = new Date();
    const today = now.toISOString().split('T')[0];

    const result = await pool.query(`
      INSERT INTO time_entries (user_id, clock_in, date)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [req.user.id, now, today]);

    const newEntry = result.rows[0];

    res.status(201).json({
      message: 'Clocked in successfully',
      timeEntry: newEntry
    });

  } catch (error) {
    console.error('Clock in error:', error);
    res.status(500).json({ 
      error: 'Failed to clock in' 
    });
  }
});

// PUT /api/time-entries/clock-out - Clock out
router.put('/clock-out', async (req, res) => {
  try {
    const pool = req.app.locals.db;

    // Find current active entry
    const activeEntry = await pool.query(`
      SELECT * FROM time_entries 
      WHERE user_id = $1 AND clock_out IS NULL
      ORDER BY created_at DESC
      LIMIT 1
    `, [req.user.id]);

    if (activeEntry.rows.length === 0) {
      return res.status(400).json({ 
        error: 'You are not currently clocked in.' 
      });
    }

    const entry = activeEntry.rows[0];
    const now = new Date();

    const result = await pool.query(`
      UPDATE time_entries 
      SET clock_out = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING *
    `, [now, entry.id]);

    const updatedEntry = result.rows[0];

    // Calculate duration
    const clockIn = new Date(updatedEntry.clock_in);
    const clockOut = new Date(updatedEntry.clock_out);
    const diffMs = clockOut - clockIn;
    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    const duration = `${hours}:${String(minutes).padStart(2, '0')}`;

    res.json({
      message: 'Clocked out successfully',
      timeEntry: {
        ...updatedEntry,
        duration
      }
    });

  } catch (error) {
    console.error('Clock out error:', error);
    res.status(500).json({ 
      error: 'Failed to clock out' 
    });
  }
});

// DELETE /api/time-entries/:id - Delete time entry (own entries only)
router.delete('/:id', [
  param('id').isUUID().withMessage('Invalid time entry ID')
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

    // Check if entry exists and belongs to user
    const existingEntry = await pool.query(
      'SELECT * FROM time_entries WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (existingEntry.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Time entry not found or you do not have permission to delete it' 
      });
    }

    const entry = existingEntry.rows[0];

    // Don't allow deletion of active (not clocked out) entries
    if (!entry.clock_out) {
      return res.status(400).json({ 
        error: 'Cannot delete an active time entry. Please clock out first.' 
      });
    }

    await pool.query('DELETE FROM time_entries WHERE id = $1', [id]);

    res.json({
      message: 'Time entry deleted successfully'
    });

  } catch (error) {
    console.error('Delete time entry error:', error);
    res.status(500).json({ 
      error: 'Failed to delete time entry' 
    });
  }
});

module.exports = router;