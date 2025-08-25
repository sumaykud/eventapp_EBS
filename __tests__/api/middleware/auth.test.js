import jwt from 'jsonwebtoken';
import { jest } from '@jest/globals';
import { authenticateToken, requireRole, verifyTokenFromRequest, getAuthHeaders, isTokenExpired } from '../../../api/middleware/auth.js';

// Mock Supabase client
const mockSupabaseClient = {
  from: jest.fn(() => ({
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn()
  }))
};

// Mock the Supabase module
jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabaseClient)
}));

describe('Auth Middleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = global.testUtils.createMockRequest();
    mockRes = global.testUtils.createMockResponse();
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('authenticateToken', () => {
    it('should authenticate valid token and set user in request', async () => {
      const token = global.testUtils.generateTestToken();
      mockReq.headers.authorization = `Bearer ${token}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'test-user-id',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockReq.user).toEqual(
        expect.objectContaining({
          id: 'test-user-id',
          email: 'test@example.com',
          role: 'user'
        })
      );
      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should return 401 for missing authorization header', async () => {
      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'No token provided'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 for invalid token format', async () => {
      mockReq.headers.authorization = 'InvalidFormat token';

      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid token format'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 for expired token', async () => {
      const expiredToken = jwt.sign(
        { userId: 'test-user-id', email: 'test@example.com' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' } // Expired token
      );
      mockReq.headers.authorization = `Bearer ${expiredToken}`;

      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid or expired token'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 when user not found in database', async () => {
      const token = global.testUtils.generateTestToken();
      mockReq.headers.authorization = `Bearer ${token}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: null,
        error: null
      });

      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'User not found'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 500 for database errors', async () => {
      const token = global.testUtils.generateTestToken();
      mockReq.headers.authorization = `Bearer ${token}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: null,
        error: { message: 'Database connection failed' }
      });

      await authenticateToken(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Authentication failed'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('requireRole', () => {
    beforeEach(() => {
      mockReq.user = global.testUtils.createTestUser();
    });

    it('should allow access for user with required role', () => {
      mockReq.user.role = 'admin';
      const middleware = requireRole('admin');

      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should allow access for user with higher role (admin accessing user route)', () => {
      mockReq.user.role = 'admin';
      const middleware = requireRole('user');

      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should deny access for user with insufficient role', () => {
      mockReq.user.role = 'user';
      const middleware = requireRole('admin');

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Insufficient permissions'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should deny access when user is not set in request', () => {
      delete mockReq.user;
      const middleware = requireRole('user');

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Insufficient permissions'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe('verifyTokenFromRequest', () => {
    it('should return decoded token for valid authorization header', () => {
      const token = global.testUtils.generateTestToken();
      mockReq.headers.authorization = `Bearer ${token}`;

      const result = verifyTokenFromRequest(mockReq);

      expect(result.success).toBe(true);
      expect(result.decoded).toEqual(
        expect.objectContaining({
          userId: 'test-user-id',
          email: 'test@example.com'
        })
      );
    });

    it('should return error for missing authorization header', () => {
      const result = verifyTokenFromRequest(mockReq);

      expect(result.success).toBe(false);
      expect(result.error).toBe('No token provided');
    });

    it('should return error for invalid token format', () => {
      mockReq.headers.authorization = 'InvalidFormat token';

      const result = verifyTokenFromRequest(mockReq);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid token format');
    });

    it('should return error for invalid token', () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      const result = verifyTokenFromRequest(mockReq);

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid or expired token');
    });
  });

  describe('getAuthHeaders', () => {
    it('should return authorization header with Bearer token', () => {
      const token = 'test-token-123';
      const headers = getAuthHeaders(token);

      expect(headers).toEqual({
        'Authorization': 'Bearer test-token-123',
        'Content-Type': 'application/json'
      });
    });

    it('should return headers without authorization when no token provided', () => {
      const headers = getAuthHeaders();

      expect(headers).toEqual({
        'Content-Type': 'application/json'
      });
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for valid non-expired token', () => {
      const token = global.testUtils.generateTestToken();
      const result = isTokenExpired(token);

      expect(result).toBe(false);
    });

    it('should return true for expired token', () => {
      const expiredToken = jwt.sign(
        { userId: 'test-user-id' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' }
      );
      const result = isTokenExpired(expiredToken);

      expect(result).toBe(true);
    });

    it('should return true for invalid token', () => {
      const result = isTokenExpired('invalid-token');

      expect(result).toBe(true);
    });

    it('should return true for malformed token', () => {
      const result = isTokenExpired('not.a.token');

      expect(result).toBe(true);
    });
  });
});