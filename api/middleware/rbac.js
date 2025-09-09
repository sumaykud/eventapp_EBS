const { createClient } = require('@supabase/supabase-js');
const { authenticateToken } = require('./auth.js');

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Check if user has admin role
const requireAdmin = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Check if user has admin role in the admin_users table
    const { data: adminUser, error } = await supabase
      .from('admin_users')
      .select('role, permissions')
      .eq('user_id', req.user.id)
      .single();

    if (error || !adminUser) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Add admin info to request for use in other functions
    req.admin = adminUser;
    next();
  } catch (error) {
    console.error('RBAC middleware error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Check if user has specific permission
const requirePermissionCheck = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      // Check if user has admin role and specific permission
      const { data: adminUser, error } = await supabase
        .from('admin_users')
        .select('role, permissions')
        .eq('user_id', req.user.id)
        .single();

      if (error || !adminUser) {
        return res.status(403).json({ error: 'Admin access required' });
      }

      // Check if user has the required permission
      const permissions = adminUser.permissions || [];
      if (!permissions.includes(permission)) {
        return res.status(403).json({ 
          error: `Permission '${permission}' required` 
        });
      }

      req.admin = adminUser;
      next();
    } catch (error) {
      console.error('Permission middleware error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
};

/**
 * Advanced RBAC system with granular permissions
 * Defines what actions each role can perform on different resources
 */
const PERMISSIONS = {
  admin: {
    users: ['create', 'read', 'update', 'delete', 'list', 'activate', 'deactivate'],
    profiles: ['create', 'read', 'update', 'delete', 'list'],
    baptism: ['create', 'read', 'update', 'delete', 'list', 'report'],
    events: ['create', 'read', 'update', 'delete', 'list', 'manage'],
    system: ['backup', 'restore', 'configure', 'audit'],
    reports: ['generate', 'export', 'view_all']
  },
  user: {
    profiles: ['read_own', 'update_own'],
    baptism: ['read_own', 'update_own'],
    events: ['read', 'join', 'leave', 'view_own'],
    reports: ['view_own']
  }
};

/**
 * Resource ownership mapping
 * Defines how to check if a user owns a specific resource
 */
const OWNERSHIP_CHECKS = {
  profiles: async (userId, resourceId) => {
    // For profiles, resourceId should be the user ID being accessed
    // Check if the user is trying to access their own profile
    return userId === resourceId;
  },
  
  baptism: async (userId, resourceId) => {
    // For baptism records, check if the user is the subject
    // resourceId should be the user ID whose baptism record is being accessed
    return userId === resourceId;
  },
  
  events: async (userId, resourceId) => {
    // For events, check if user is the creator or participant
    const { data: eventData } = await supabase
      .from('events')
      .select('created_by')
      .eq('id', resourceId)
      .single();
    
    if (eventData?.created_by === userId) return true;
    
    // Check if user is a participant
    const { data: participantData } = await supabase
      .from('event_participants')
      .select('user_id')
      .eq('event_id', resourceId)
      .eq('user_id', userId)
      .single();
    
    return !!participantData;
  }
};

/**
 * Check if a user has a specific permission
 * @param {string} userRole - User's role
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action being performed
 * @param {string} userId - User ID (for ownership checks)
 * @param {string} resourceId - Resource ID (for ownership checks)
 * @returns {Promise<boolean>} Whether user has permission
 */
const hasPermission = async (userRole, resource, action, userId = null, resourceId = null) => {
  try {
    const rolePermissions = PERMISSIONS[userRole];
    if (!rolePermissions) return false;
    
    const resourcePermissions = rolePermissions[resource];
    if (!resourcePermissions) return false;
    
    // Check if the role has the permission
    if (!resourcePermissions.includes(action)) {
      return false;
    }
    
    // For ownership-based permissions, check ownership if userId and resourceId are provided
    if (action.endsWith('_own')) {
      if (userId && resourceId) {
        const ownershipCheck = OWNERSHIP_CHECKS[resource];
        if (ownershipCheck) {
          return await ownershipCheck(userId, resourceId);
        }
        // If no ownership check function exists, assume ownership is valid
        return true;
      }
      // If no userId/resourceId provided for _own permission, return true (role has the permission)
      return true;
    }
    
    // For non-ownership based permissions, return true
    return true;
  } catch (error) {
    console.error('Permission check error:', error);
    return false;
  }
};

/**
 * Middleware factory for checking specific permissions
 * @param {string} resource - Resource being accessed
 * @param {string} action - Action being performed
 * @param {Object} options - Additional options
 * @returns {Function} Express middleware function
 */
const requirePermission = (resource, action, options = {}) => {
  return async (req, res, next) => {
    try {
      // First authenticate the user
      const authResult = await authenticateToken(req, res);
      
      if (!authResult.success) {
        return res.status(401).json({
          error: authResult.error,
          code: authResult.code
        });
      }
      
      const { user } = authResult;
      
      // Extract resource ID from request
      const resourceId = options.resourceIdParam 
        ? req.params[options.resourceIdParam] 
        : req.params.id || req.body.id || req.query.id;
      
      // Check permission
      const hasAccess = await hasPermission(
        user.role,
        resource,
        action,
        user.id,
        resourceId
      );
      
      if (!hasAccess) {
        // Log unauthorized access attempt
        console.warn(`Access denied: User ${user.id} (${user.email}) attempted ${action} on ${resource}${resourceId ? ` (ID: ${resourceId})` : ''}`);
        
        return res.status(403).json({
          error: `Insufficient permissions for ${action} on ${resource}`,
          code: 'PERMISSION_DENIED',
          required: {
            resource,
            action,
            userRole: user.role
          }
        });
      }
      
      // Log successful access for audit trail
      console.info(`Permission granted: ${user.email} performed ${action} on ${resource}${resourceId ? ` (ID: ${resourceId})` : ''}`);
      
      // Add permission context to request
      req.permission = {
        resource,
        action,
        resourceId,
        granted: true
      };
      
      next();
      
    } catch (error) {
      console.error('Permission middleware error:', error);
      return res.status(500).json({
        error: 'Permission check failed',
        code: 'PERMISSION_ERROR'
      });
    }
  };
};

/**
 * Middleware for dynamic permission checking based on request context
 * @param {Function} permissionResolver - Function to resolve resource and action from request
 * @returns {Function} Express middleware function
 */
const requireDynamicPermission = (permissionResolver) => {
  return async (req, res, next) => {
    try {
      // First authenticate the user
      const authResult = await authenticateToken(req, res);
      
      if (!authResult.success) {
        return res.status(401).json({
          error: authResult.error,
          code: authResult.code
        });
      }
      
      const { user } = authResult;
      
      // Resolve permission requirements from request
      const { resource, action, resourceId } = await permissionResolver(req);
      
      // Check permission
      const hasAccess = await hasPermission(
        user.role,
        resource,
        action,
        user.id,
        resourceId
      );
      
      if (!hasAccess) {
        console.warn(`Dynamic access denied: User ${user.id} attempted ${action} on ${resource}`);
        
        return res.status(403).json({
          error: `Insufficient permissions for ${action} on ${resource}`,
          code: 'PERMISSION_DENIED'
        });
      }
      
      req.permission = { resource, action, resourceId, granted: true };
      next();
      
    } catch (error) {
      console.error('Dynamic permission middleware error:', error);
      return res.status(500).json({
        error: 'Permission check failed',
        code: 'PERMISSION_ERROR'
      });
    }
  };
};

/**
 * Middleware to check multiple permissions (user must have ALL)
 * @param {Array} permissionChecks - Array of {resource, action} objects
 * @returns {Function} Express middleware function
 */
const requireAllPermissions = (permissionChecks) => {
  return async (req, res, next) => {
    try {
      const authResult = await authenticateToken(req, res);
      
      if (!authResult.success) {
        return res.status(401).json({
          error: authResult.error,
          code: authResult.code
        });
      }
      
      const { user } = authResult;
      
      // Check all permissions
      for (const { resource, action, resourceIdParam } of permissionChecks) {
        const resourceId = resourceIdParam 
          ? req.params[resourceIdParam] 
          : req.params.id;
          
        const hasAccess = await hasPermission(
          user.role,
          resource,
          action,
          user.id,
          resourceId
        );
        
        if (!hasAccess) {
          return res.status(403).json({
            error: `Missing required permission: ${action} on ${resource}`,
            code: 'PERMISSION_DENIED'
          });
        }
      }
      
      req.permissions = permissionChecks.map(check => ({ ...check, granted: true }));
      next();
      
    } catch (error) {
      console.error('Multiple permissions middleware error:', error);
      return res.status(500).json({
        error: 'Permission check failed',
        code: 'PERMISSION_ERROR'
      });
    }
  };
};

/**
 * Middleware to check if user has ANY of the specified permissions
 * @param {Array} permissionChecks - Array of {resource, action} objects
 * @returns {Function} Express middleware function
 */
const requireAnyPermission = (permissionChecks) => {
  return async (req, res, next) => {
    try {
      const authResult = await authenticateToken(req, res);
      
      if (!authResult.success) {
        return res.status(401).json({
          error: authResult.error,
          code: authResult.code
        });
      }
      
      const { user } = authResult;
      
      // Check if user has any of the permissions
      let hasAnyAccess = false;
      let grantedPermission = null;
      
      for (const { resource, action, resourceIdParam } of permissionChecks) {
        const resourceId = resourceIdParam 
          ? req.params[resourceIdParam] 
          : req.params.id;
          
        const hasAccess = await hasPermission(
          user.role,
          resource,
          action,
          user.id,
          resourceId
        );
        
        if (hasAccess) {
          hasAnyAccess = true;
          grantedPermission = { resource, action, resourceId };
          break;
        }
      }
      
      if (!hasAnyAccess) {
        return res.status(403).json({
          error: 'Insufficient permissions for this operation',
          code: 'PERMISSION_DENIED',
          required: permissionChecks
        });
      }
      
      req.permission = { ...grantedPermission, granted: true };
      next();
      
    } catch (error) {
      console.error('Any permission middleware error:', error);
      return res.status(500).json({
        error: 'Permission check failed',
        code: 'PERMISSION_ERROR'
      });
    }
  };
};

/**
 * Get all permissions for a user role
 * @param {string} role - User role
 * @returns {Object} All permissions for the role
 */
const getRolePermissions = (role) => {
  return PERMISSIONS[role] || {};
};

/**
 * Check if a role exists
 * @param {string} role - Role to check
 * @returns {boolean} Whether role exists
 */
const isValidRole = (role) => {
  return Object.keys(PERMISSIONS).includes(role);
};

module.exports = {
  hasPermission,
  requirePermission,
  requireDynamicPermission,
  requireAllPermissions,
  requireAnyPermission,
  getRolePermissions,
  isValidRole,
  PERMISSIONS,
  requireAdmin,
  requirePermissionCheck
};