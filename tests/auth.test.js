import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

// Load test environment variables
require('dotenv').config({ path: '.env.test' });

// Import modules to test
let validatePassword, hashPassword, comparePassword, trackPasswordAttempt, resetPasswordAttempts;
let hasPermission, requirePermission, isValidRole;
let authenticateToken, requireAdmin, requireUser;

// Mock Supabase
vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn()
}));

const mockSupabase = {
  from: vi.fn(() => ({
    select: vi.fn(() => ({
      eq: vi.fn(() => ({
        single: vi.fn(() => ({ data: null, error: null })),
        is: vi.fn(() => ({
          single: vi.fn(() => ({ data: null, error: null }))
        }))
      })),
      insert: vi.fn(() => ({
        select: vi.fn(() => ({
          single: vi.fn(() => ({ data: null, error: null }))
        }))
      })),
      update: vi.fn(() => ({
        eq: vi.fn(() => ({
          select: vi.fn(() => ({
            single: vi.fn(() => ({ data: null, error: null }))
          }))
        }))
      }))
    }))
  }))
};

// Set up the mock before each test
beforeEach(async () => {
  console.error('🔍 BeforeEach - Starting setup');
  vi.clearAllMocks();
  createClient.mockReturnValue(mockSupabase);
  
  // Dynamic imports to avoid module loading issues
  try {
    console.error('🔍 BeforeEach - Importing modules');
    const passwordSecurity = await import('../api/utils/password-security.js');
    validatePassword = passwordSecurity.validatePassword;
    hashPassword = passwordSecurity.hashPassword;
    comparePassword = passwordSecurity.comparePassword;
    trackPasswordAttempt = passwordSecurity.trackPasswordAttempt;
    resetPasswordAttempts = passwordSecurity.resetPasswordAttempts;
    
    const rbac = await import('../api/middleware/rbac.js');
    hasPermission = rbac.hasPermission;
    requirePermission = rbac.requirePermission;
    isValidRole = rbac.isValidRole;
    
    const auth = await import('../api/middleware/auth.js');
    authenticateToken = auth.authenticateToken;
    requireAdmin = auth.requireAdmin;
    requireUser = auth.requireUser;
    console.error('🔍 BeforeEach - All modules imported successfully');
    console.error('🔍 BeforeEach - authenticateToken type:', typeof authenticateToken);
  } catch (error) {
    console.error('🔍 BeforeEach - Module import failed:', error.message);
    console.error('🔍 BeforeEach - Full error:', error);
  }
});

// Test data
const testUsers = {
  admin: {
    id: 'admin-123',
    email: 'admin@test.com',
    name: 'Admin User',
    role: 'admin',
    is_active: true,
    password_hash: '$2b$12$test.hash.admin'
  },
  user: {
    id: 'user-123',
    email: 'user@test.com',
    name: 'Regular User',
    role: 'user',
    is_active: true,
    password_hash: '$2b$12$test.hash.user'
  },
  inactive: {
    id: 'inactive-123',
    email: 'inactive@test.com',
    name: 'Inactive User',
    role: 'user',
    is_active: false,
    password_hash: '$2b$12$test.hash.inactive'
  }
};

const validJWT = jwt.sign(
  { 
    userId: testUsers.admin.id, 
    email: testUsers.admin.email, 
    role: testUsers.admin.role,
    sessionId: 'session-123',
    tokenType: 'access'
  }, 
  process.env.JWT_SECRET || 'test-secret',
  { expiresIn: '1h' }
);

describe('Password Security Tests', () => {
  describe('validatePassword', () => {
    it('should validate strong passwords', () => {
      const result = validatePassword('StrongPass123!');
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.strengthScore).toBeGreaterThan(60);
    });

    it('should reject weak passwords', () => {
      const result = validatePassword('weak');
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should reject common passwords', () => {
      const result = validatePassword('password123');
      expect(result.isValid).toBe(false);
      expect(result.errors.some(error => error.includes('common'))).toBe(true);
    });

    it('should warn about passwords containing user info', () => {
      const result = validatePassword('JohnDoe123!', { name: 'John Doe', email: 'john@test.com' });
      expect(result.warnings.some(warning => warning.includes('name'))).toBe(true);
    });

    it('should require minimum length', () => {
      const result = validatePassword('Sh0rt!');
      expect(result.isValid).toBe(false);
      expect(result.errors.some(error => error.includes('8 characters'))).toBe(true);
    });

    it('should require character variety', () => {
      const tests = [
        { password: 'alllowercase123!', missing: 'uppercase' },
        { password: 'ALLUPPERCASE123!', missing: 'lowercase' },
        { password: 'NoNumbers!', missing: 'number' },
        { password: 'NoSpecialChars123', missing: 'special' }
      ];

      tests.forEach(({ password, missing }) => {
        const result = validatePassword(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.some(error => error.toLowerCase().includes(missing))).toBe(true);
      });
    });
  });

  describe('hashPassword and comparePassword', () => {
    it('should hash passwords securely', async () => {
      const password = 'TestPassword123!';
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.startsWith('$2b$')).toBe(true);
    });

    it('should verify correct passwords', async () => {
      const password = 'TestPassword123!';
      const hash = await hashPassword(password);
      const isValid = await comparePassword(password, hash);
      
      expect(isValid).toBe(true);
    });

    it('should reject incorrect passwords', async () => {
      const password = 'TestPassword123!';
      const wrongPassword = 'WrongPassword123!';
      const hash = await hashPassword(password);
      const isValid = await comparePassword(wrongPassword, hash);
      
      expect(isValid).toBe(false);
    });

    it('should reject weak passwords during hashing', async () => {
      await expect(hashPassword('weak')).rejects.toThrow();
    });
  });

  describe('trackPasswordAttempt', () => {
    beforeEach(() => {
      resetPasswordAttempts('test@example.com');
    });

    it('should track failed attempts', () => {
      const result1 = trackPasswordAttempt('test@example.com');
      expect(result1.isLocked).toBe(false);
      expect(result1.attemptsRemaining).toBe(4);

      const result2 = trackPasswordAttempt('test@example.com');
      expect(result2.attemptsRemaining).toBe(3);
    });

    it('should lock account after max attempts', () => {
      // Make 5 failed attempts
      for (let i = 0; i < 5; i++) {
        trackPasswordAttempt('test@example.com');
      }
      
      const result = trackPasswordAttempt('test@example.com');
      expect(result.isLocked).toBe(true);
      expect(result.attemptsRemaining).toBe(0);
    });

    it('should reset attempts on successful login', () => {
      trackPasswordAttempt('test@example.com');
      trackPasswordAttempt('test@example.com');
      
      resetPasswordAttempts('test@example.com');
      
      const result = trackPasswordAttempt('test@example.com');
      expect(result.attemptsRemaining).toBe(4); // Back to first attempt
    });
  });
});

describe('RBAC System Tests', () => {
  describe('hasPermission', () => {
    it('should grant admin permissions', async () => {
      const hasAccess = await hasPermission('admin', 'users', 'create');
      expect(hasAccess).toBe(true);
    });

    it('should grant user permissions for own resources', async () => {
      // Mock ownership check
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            single: vi.fn(() => ({ data: { id: 'user-123' } }))
          }))
        }))
      });

      const hasAccess = await hasPermission('user', 'profiles', 'read_own', 'user-123', 'user-123');
      expect(hasAccess).toBe(true);
    });

    it('should deny user permissions for other resources', async () => {
      // Mock ownership check failure
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            single: vi.fn(() => ({ data: null }))
          }))
        }))
      });

      const hasAccess = await hasPermission('user', 'profiles', 'read_own', 'user-123', 'other-user-456');
      expect(hasAccess).toBe(false);
    });

    it('should deny invalid role permissions', async () => {
      const hasAccess = await hasPermission('invalid-role', 'users', 'create');
      expect(hasAccess).toBe(false);
    });

    it('should deny user admin permissions', async () => {
      const hasAccess = await hasPermission('user', 'users', 'delete');
      expect(hasAccess).toBe(false);
    });
  });

  describe('isValidRole', () => {
    it('should validate admin role', () => {
      expect(isValidRole('admin')).toBe(true);
    });

    it('should validate user role', () => {
      expect(isValidRole('user')).toBe(true);
    });

    it('should reject invalid roles', () => {
      expect(isValidRole('invalid')).toBe(false);
      expect(isValidRole('moderator')).toBe(false);
      expect(isValidRole('')).toBe(false);
    });
  });
});

describe('Authentication Middleware Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('authenticateToken', () => {
    it('should authenticate valid tokens', async () => {
      console.error('🔍 Debug - Starting test: should authenticate valid tokens');
      console.log('🔍 Debug - testUsers.admin:', JSON.stringify(testUsers.admin, null, 2));
      
      // Use the same JWT secret that should be loaded in the auth module
      const JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-key-for-testing-only-do-not-use-in-production';
      console.log('🔍 Debug - JWT_SECRET:', JWT_SECRET);
      
      // Create a valid JWT token
      const token = jwt.sign(
        { 
          userId: testUsers.admin.id, 
          email: testUsers.admin.email,
          role: testUsers.admin.role,
          tokenType: 'access'
        }, 
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      console.log('🔍 Debug - Generated token:', token);
      console.error('🔍 authenticateToken function:', typeof authenticateToken);
      console.error('🔍 authenticateToken is:', authenticateToken ? 'defined' : 'undefined');

      // Mock Supabase user lookup
      mockSupabase.from.mockReturnValue({
        select: vi.fn().mockReturnValue({
          eq: vi.fn().mockReturnValue({
            is: vi.fn().mockReturnValue({
              single: vi.fn().mockResolvedValue({ data: testUsers.admin, error: null })
            })
          })
        })
      });
      console.log('🔍 Debug - Mock setup complete');

      const req = {
        headers: { authorization: `Bearer ${token}` }
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => res),
        json: vi.fn(() => res)
      };
      const next = vi.fn();
      
      console.log('🔍 Debug - About to call authenticateToken');
      console.log('🔍 Debug - req.headers.authorization:', req.headers.authorization);
      
      // Call authenticateToken middleware
      await authenticateToken(req, res, next);
      
      // Check that next was called (successful authentication)
      expect(next).toHaveBeenCalled();
      // Check that user was set on request
      expect(req.user).toBeDefined();
      expect(req.user.id).toBe(testUsers.admin.id);
      // Check that no error response was sent
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
    });

    it('should reject missing tokens', async () => {
      const req = { headers: {} };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => res),
        json: vi.fn(() => res)
      };

      await authenticateToken(req, res);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({ 
        error: 'Access token required'
      });
    });

    it('should reject invalid tokens', async () => {
      const req = {
        headers: { authorization: 'Bearer invalid-token' }
      };
      const res = {
          setHeader: vi.fn(),
          status: vi.fn(() => res),
          json: vi.fn(() => res)
        };

      await authenticateToken(req, res);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    });

    it('should reject tokens for inactive users', async () => {
      // Create JWT for inactive user without sessionId
      const inactiveUserJWT = jwt.sign(
        { 
          userId: testUsers.inactive.id, 
          email: testUsers.inactive.email, 
          role: testUsers.inactive.role,
          tokenType: 'access'
        }, 
        process.env.JWT_SECRET || 'test-secret',
        { expiresIn: '1h' }
      );

      // Mock inactive user lookup
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            is: vi.fn(() => ({
              single: vi.fn(() => ({ data: testUsers.inactive, error: null }))
            }))
          }))
        }))
      });

      const req = {
        headers: { authorization: `Bearer ${inactiveUserJWT}` }
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => res),
        json: vi.fn(() => res)
      };

      await authenticateToken(req, res);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid token' });
    });
  });

  describe('requireAdmin', () => {
    it('should allow admin access', async () => {
      // Mock successful authentication
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            is: vi.fn(() => ({
              single: vi.fn(() => ({ data: testUsers.admin, error: null }))
            }))
          }))
        }))
      });

      const req = {
        headers: { authorization: `Bearer ${validJWT}` },
        user: testUsers.admin,
        method: 'GET',
        path: '/admin/users'
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => ({ json: vi.fn() }))
      };
      const next = vi.fn();

      await requireAdmin(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('should deny non-admin access', async () => {
      // Mock user authentication
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            is: vi.fn(() => ({
              single: vi.fn(() => ({ data: testUsers.user, error: null }))
            }))
          }))
        }))
      });

      const userJWT = jwt.sign(
        { 
          userId: testUsers.user.id, 
          email: testUsers.user.email, 
          role: testUsers.user.role,
          tokenType: 'access'
        }, 
        process.env.JWT_SECRET || 'test-secret'
      );

      const req = {
        headers: { authorization: `Bearer ${userJWT}` },
        user: testUsers.user
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => ({ json: vi.fn() }))
      };
      const next = vi.fn();

      await requireAdmin(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe('requireUser', () => {
    it('should allow user access', async () => {
      // Mock user authentication
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            is: vi.fn(() => ({
              single: vi.fn(() => ({ data: testUsers.user, error: null }))
            }))
          }))
        }))
      });

      const userJWT = jwt.sign(
        { 
          userId: testUsers.user.id, 
          email: testUsers.user.email, 
          role: testUsers.user.role,
          tokenType: 'access'
        }, 
        process.env.JWT_SECRET || 'test-secret'
      );

      const req = {
        headers: { authorization: `Bearer ${userJWT}` },
        user: testUsers.user
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => res),
        json: vi.fn(() => res)
      };
      const next = vi.fn();

      await requireUser(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('should allow admin access', async () => {
      // Mock admin authentication
      mockSupabase.from.mockReturnValue({
        select: vi.fn(() => ({
          eq: vi.fn(() => ({
            is: vi.fn(() => ({
              single: vi.fn(() => ({ data: testUsers.admin, error: null }))
            }))
          }))
        }))
      });

      const req = {
        headers: { authorization: `Bearer ${validJWT}` },
        user: testUsers.admin
      };
      const res = {
        setHeader: vi.fn(),
        status: vi.fn(() => res),
        json: vi.fn(() => res)
      };
      const next = vi.fn();

      await requireUser(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });
});

describe('Integration Tests', () => {
  describe('Complete Authentication Flow', () => {
    it('should handle complete registration flow', async () => {
      const userData = {
        name: 'Test User',
        email: 'test@example.com',
        phone: '+1234567890',
        password: 'SecurePassword123!',
        role: 'user'
      };

      // Test password validation
      const passwordValidation = validatePassword(userData.password, {
        email: userData.email,
        name: userData.name
      });
      expect(passwordValidation.isValid).toBe(true);

      // Test password hashing
      const hashedPassword = await hashPassword(userData.password);
      expect(hashedPassword).toBeDefined();
      expect(hashedPassword).not.toBe(userData.password);

      // Test password verification
      const isValidPassword = await comparePassword(userData.password, hashedPassword);
      expect(isValidPassword).toBe(true);
    });

    it('should handle complete login flow with lockout', async () => {
      const email = 'test@example.com';
      const password = 'SecurePassword123!';
      const wrongPassword = 'WrongPassword123!';

      // Reset attempts
      resetPasswordAttempts(email);

      // Test multiple failed attempts
      for (let i = 0; i < 4; i++) {
        const attempt = trackPasswordAttempt(email);
        expect(attempt.isLocked).toBe(false);
      }

      // Fifth attempt should lock
      const lockAttempt = trackPasswordAttempt(email);
      expect(lockAttempt.isLocked).toBe(true);

      // Successful login should reset
      resetPasswordAttempts(email);
      const resetAttempt = trackPasswordAttempt(email);
      expect(resetAttempt.attemptsRemaining).toBe(4);
    });
  });

  describe('RBAC Integration', () => {
    it('should enforce role-based access control', async () => {
      // Admin should have full access
      expect(await hasPermission('admin', 'users', 'create')).toBe(true);
      expect(await hasPermission('admin', 'users', 'delete')).toBe(true);
      expect(await hasPermission('admin', 'baptism', 'report')).toBe(true);

      // User should have limited access
      expect(await hasPermission('user', 'users', 'create')).toBe(false);
      expect(await hasPermission('user', 'users', 'delete')).toBe(false);
      expect(await hasPermission('user', 'profiles', 'read_own')).toBe(true);
    });
  });
});

// Test utilities
export const createTestUser = (overrides = {}) => {
  return {
    id: 'test-' + Math.random().toString(36).substr(2, 9),
    email: 'test@example.com',
    name: 'Test User',
    role: 'user',
    is_active: true,
    ...overrides
  };
};

export const createTestJWT = (user, options = {}) => {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
      sessionId: 'test-session',
      tokenType: 'access',
      ...options
    },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '1h' }
  );
};

export const mockAuthenticatedRequest = (user) => {
  const token = createTestJWT(user);
  return {
    headers: {
      authorization: `Bearer ${token}`
    },
    user: user
  };
};