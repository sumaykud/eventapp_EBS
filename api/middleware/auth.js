const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const { verifyToken, validateUserSession } = require('../authentication.js');

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Enhanced security configuration
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Enhanced middleware to authenticate JWT token with session validation
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {Function} next - Next function (for middleware chaining)
 * @returns {Object} - Authentication result
 */
const authenticateToken = async (req, res, next) => {
  try {
    // Add security headers
    Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        error: 'Access token required',
        code: 'TOKEN_MISSING'
      });
    }

    // Verify JWT token using enhanced verifyToken function
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(403).json({ 
        error: 'Invalid or expired token',
        code: 'TOKEN_INVALID'
      });
    }

    // Validate session if sessionId exists
    if (decoded.sessionId) {
      const isValidSession = await validateUserSession(decoded.sessionId, decoded.userId);
      if (!isValidSession) {
        return res.status(403).json({ 
          error: 'Session expired or invalid',
          code: 'SESSION_INVALID'
        });
      }
    }
    
    // Fetch user from database with enhanced fields
    const { data: user, error } = await supabase
      .from('users')
      .select(`
        id, email, name, phone, role, is_active, 
        photo, ebs_join_date, is_baptized, baptism_date,
        created_at, updated_at, last_login
      `)
      .eq('id', decoded.userId)
      .is('deleted_at', null)
      .single();

    if (error || !user) {
      return res.status(403).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    if (!user.is_active) {
      return res.status(403).json({ 
        error: 'Account is deactivated',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Attach enhanced user info to request object
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      role: user.role,
      isActive: user.is_active,
      photo: user.photo,
      ebsJoinDate: user.ebs_join_date,
      isBaptized: user.is_baptized,
      baptismDate: user.baptism_date,
      createdAt: user.created_at,
      updatedAt: user.updated_at,
      lastLogin: user.last_login,
      sessionId: decoded.sessionId,
      tokenData: decoded
    };

    // Add request metadata
    req.auth = {
      tokenType: decoded.tokenType,
      issuedAt: decoded.iat,
      expiresAt: decoded.exp,
      sessionId: decoded.sessionId
    };

    // If using as middleware, call next()
    if (next) {
      return next();
    }

    // If using as standalone function, return success
    return { success: true, user: req.user };

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ 
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ 
        error: 'Invalid token',
        code: 'TOKEN_INVALID'
      });
    }

    console.error('Authentication middleware error:', error);
    return res.status(500).json({ 
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Middleware to check if user has required role
 * @param {string|Array} requiredRoles - Required role(s) for access
 * @returns {Function} - Middleware function
 */
const requireRole = (requiredRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const userRole = req.user.role;
    const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

    if (!roles.includes(userRole)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: roles,
        current: userRole
      });
    }

    if (next) {
      return next();
    }
  };
};

/**
 * Utility function to extract and verify token without middleware pattern
 * @param {Object} req - Request object
 * @returns {Object} - Verification result
 */
const verifyTokenFromRequest = async (req) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return { success: false, error: 'Token missing' };
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, role, is_active')
      .eq('id', decoded.userId)
      .single();

    if (error || !user || !user.is_active) {
      return { success: false, error: 'User not found or inactive' };
    }

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isActive: user.is_active,
        tokenData: decoded
      }
    };

  } catch (error) {
    return { 
      success: false, 
      error: error.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
    };
  }
};

/**
 * Helper function to generate authorization header
 * @param {string} token - JWT token
 * @returns {Object} - Authorization headers
 */
const getAuthHeaders = (token) => {
  return {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
};

/**
 * Helper function to check if token is expired
 * @param {string} token - JWT token
 * @returns {boolean} - True if expired
 */
const isTokenExpired = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) return true;
    
    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch (error) {
    return true;
  }
};

/**
 * Enhanced middleware to check if user has admin role with additional security
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireAdmin = async (req, res, next) => {
  try {
    // First authenticate the token
    const authResult = await authenticateToken(req, res);
    
    if (!authResult.success) {
      return res.status(401).json({
        error: authResult.error,
        code: authResult.code
      });
    }

    // Check if user has admin role
    if (req.user.role !== 'admin') {
      // Log unauthorized admin access attempt
      console.warn(`Unauthorized admin access attempt by user ${req.user.id} (${req.user.email})`);
      
      return res.status(403).json({
        error: 'Admin access required',
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    // Additional security: Check if admin account is still active
    if (!req.user.isActive) {
      return res.status(403).json({
        error: 'Admin account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Log admin access for audit trail
    console.info(`Admin access granted to ${req.user.email} for ${req.method} ${req.path}`);

    // If using as middleware, call next()
    if (next) {
      next();
    }

    return {
      success: true,
      user: req.user
    };

  } catch (error) {
    console.error('Admin authorization error:', error);
    return res.status(500).json({
      error: 'Authorization failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Enhanced middleware to check if user has valid role with resource access control
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireUser = async (req, res, next) => {
  try {
    // First authenticate the token
    const authResult = await authenticateToken(req, res);
    
    if (!authResult.success) {
      return res.status(401).json({
        error: authResult.error,
        code: authResult.code
      });
    }

    // Allow access for both admin and user roles
    if (req.user.role !== 'admin' && req.user.role !== 'user') {
      return res.status(403).json({
        error: 'Valid user role required',
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    // Additional security: Check if user account is still active
    if (!req.user.isActive) {
      return res.status(403).json({
        error: 'User account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // If using as middleware, call next()
    if (next) {
      next();
    }

    return {
      success: true,
      user: req.user
    };

  } catch (error) {
    console.error('User authorization error:', error);
    return res.status(500).json({
      error: 'Authorization failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Middleware to ensure users can only access their own resources
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @param {string} userIdParam - Parameter name containing user ID (default: 'userId')
 */
const requireOwnershipOrAdmin = (userIdParam = 'userId') => {
  return async (req, res, next) => {
    try {
      // First authenticate the token
      const authResult = await authenticateToken(req, res);
      
      if (!authResult.success) {
        return res.status(401).json({
          error: authResult.error,
          code: authResult.code
        });
      }

      // Admin can access any resource
      if (req.user.role === 'admin') {
        if (next) next();
        return { success: true, user: req.user };
      }

      // Get target user ID from request parameters, body, or query
      const targetUserId = req.params[userIdParam] || req.body[userIdParam] || req.query[userIdParam];
      
      // If no target user ID specified, assume user is accessing their own data
      if (!targetUserId) {
        if (next) next();
        return { success: true, user: req.user };
      }

      // Check if user is trying to access their own data
      if (req.user.id !== targetUserId) {
        console.warn(`User ${req.user.id} attempted to access data for user ${targetUserId}`);
        return res.status(403).json({
          error: 'You can only access your own data',
          code: 'OWNERSHIP_REQUIRED'
        });
      }

      if (next) next();
      return { success: true, user: req.user };

    } catch (error) {
      console.error('Ownership authorization error:', error);
      return res.status(500).json({
        error: 'Authorization failed',
        code: 'AUTH_ERROR'
      });
    }
  };
};

/**
 * Rate limiting middleware for sensitive operations
 * @param {number} maxAttempts - Maximum attempts allowed
 * @param {number} windowMs - Time window in milliseconds
 */
const rateLimitSensitive = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
  const attempts = new Map();
  
  return (req, res, next) => {
    const clientId = req.user?.id || req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old attempts
    if (attempts.has(clientId)) {
      const userAttempts = attempts.get(clientId).filter(time => time > windowStart);
      attempts.set(clientId, userAttempts);
    }
    
    const currentAttempts = attempts.get(clientId) || [];
    
    if (currentAttempts.length >= maxAttempts) {
      return res.status(429).json({
        error: 'Too many attempts. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((currentAttempts[0] + windowMs - now) / 1000)
      });
    }
    
    // Record this attempt
    currentAttempts.push(now);
    attempts.set(clientId, currentAttempts);
    
    next();
  };
};

module.exports = {
  authenticateToken,
  requireRole,
  requireAdmin,
  requireUser,
  requireOwnershipOrAdmin,
  rateLimitSensitive,
  verifyTokenFromRequest,
  getAuthHeaders,
  isTokenExpired
};