const jwt = require('jsonwebtoken');

// =====================================================
// Authentication Middleware
// =====================================================

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        error: 'Access denied. No token provided.' 
      });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user details from database
    const pool = req.app.locals.db;
    const result = await pool.query(
      'SELECT id, email, username, name, roles, approved FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        error: 'Invalid token. User not found.' 
      });
    }

    const user = result.rows[0];

    // Check if user is still approved
    if (!user.approved) {
      return res.status(403).json({ 
        error: 'Account has been suspended. Contact administrator.' 
      });
    }

    // Add user to request object
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token.' });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired.' });
    }
    
    res.status(500).json({ error: 'Token verification failed.' });
  }
};

// =====================================================
// Role-based Authorization Middleware
// =====================================================

const requireRole = (requiredRoles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ 
          error: 'Authentication required.' 
        });
      }

      const userRoles = req.user.roles || [];
      const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

      if (!hasRequiredRole) {
        return res.status(403).json({ 
          error: `Access denied. Required roles: ${requiredRoles.join(' or ')}`,
          userRoles: userRoles
        });
      }

      next();
    } catch (error) {
      console.error('Role middleware error:', error);
      res.status(500).json({ error: 'Authorization check failed.' });
    }
  };
};

// =====================================================
// Specific Role Middleware Functions
// =====================================================

const requireAdmin = requireRole(['admin']);
const requireAdminOrMadmin = requireRole(['admin', 'madmin']);
const requireUser = requireRole(['user', 'admin', 'madmin']);
const requireStaff = requireRole(['staff', 'user', 'admin', 'madmin']); // All users should have staff

// =====================================================
// Owner or Admin Middleware
// =====================================================

const requireOwnerOrAdmin = (resourceField = 'created_by') => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ 
          error: 'Authentication required.' 
        });
      }

      // Admin can access anything
      if (req.user.roles.includes('admin') || req.user.roles.includes('madmin')) {
        return next();
      }

      // For other users, check if they own the resource
      // This will be verified in the route handler with the actual resource
      req.requireOwnership = {
        userId: req.user.id,
        field: resourceField
      };
      
      next();
    } catch (error) {
      console.error('Owner/Admin middleware error:', error);
      res.status(500).json({ error: 'Authorization check failed.' });
    }
  };
};

// =====================================================
// Utility Functions
// =====================================================

const hasRole = (userRoles, requiredRole) => {
  return userRoles && userRoles.includes(requiredRole);
};

const canAccessProjects = (userRoles) => {
  return hasRole(userRoles, 'admin') || hasRole(userRoles, 'madmin') || hasRole(userRoles, 'user');
};

const canAccessBilling = (userRoles) => {
  return hasRole(userRoles, 'admin') || hasRole(userRoles, 'madmin');
};

const canDeleteProjects = (userRoles) => {
  return hasRole(userRoles, 'admin');
};

module.exports = {
  authenticateToken,
  requireRole,
  requireAdmin,
  requireAdminOrMadmin,
  requireUser,
  requireStaff,
  requireOwnerOrAdmin,
  hasRole,
  canAccessProjects,
  canAccessBilling,
  canDeleteProjects
};