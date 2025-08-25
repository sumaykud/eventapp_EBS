import request from 'supertest';
import jwt from 'jsonwebtoken';
import { jest } from '@jest/globals';

// Mock Supabase client
const mockSupabaseClient = {
  from: jest.fn(() => ({
    select: jest.fn().mockReturnThis(),
    insert: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    single: jest.fn(),
    maybeSingle: jest.fn()
  }))
};

// Mock the Supabase module
jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabaseClient)
}));

// Import the handler after mocking
import handler from '../../api/protected-example.js';

describe('Protected Routes Integration Tests', () => {
  let mockReq, mockRes;
  let validToken, adminToken;

  beforeEach(() => {
    mockReq = global.testUtils.createMockRequest();
    mockRes = global.testUtils.createMockResponse();
    
    // Generate test tokens
    validToken = global.testUtils.generateTestToken({
      userId: 'user-123',
      email: 'user@example.com',
      role: 'user'
    });
    
    adminToken = global.testUtils.generateTestToken({
      userId: 'admin-123',
      email: 'admin@example.com',
      role: 'admin'
    });
    
    jest.clearAllMocks();
  });

  describe('GET /api/protected-example - Get User Profile', () => {
    beforeEach(() => {
      mockReq.method = 'GET';
    });

    it('should return user profile for authenticated user', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user',
          created_at: '2024-01-01T00:00:00Z'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Profile retrieved successfully',
          user: expect.objectContaining({
            id: 'user-123',
            email: 'user@example.com',
            name: 'Test User'
          })
        })
      );
    });

    it('should return 401 for unauthenticated request', async () => {
      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'No token provided'
      });
    });

    it('should return 401 for invalid token', async () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid or expired token'
      });
    });
  });

  describe('PUT /api/protected-example - Update User Profile', () => {
    beforeEach(() => {
      mockReq.method = 'PUT';
      mockReq.body = {
        name: 'Updated Name',
        email: 'updated@example.com'
      };
    });

    it('should update user profile for authenticated user', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      // Mock authentication check
      mockSupabaseClient.from().select().eq().maybeSingle
        .mockResolvedValueOnce({
          data: {
            id: 'user-123',
            email: 'user@example.com',
            name: 'Test User',
            role: 'user'
          },
          error: null
        })
        // Mock update operation
        .mockResolvedValueOnce({
          data: {
            id: 'user-123',
            email: 'updated@example.com',
            name: 'Updated Name',
            role: 'user',
            updated_at: '2024-01-02T00:00:00Z'
          },
          error: null
        });

      mockSupabaseClient.from().update().eq().select().single.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'updated@example.com',
          name: 'Updated Name',
          role: 'user',
          updated_at: '2024-01-02T00:00:00Z'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Profile updated successfully',
          user: expect.objectContaining({
            id: 'user-123',
            name: 'Updated Name',
            email: 'updated@example.com'
          })
        })
      );
    });

    it('should return 400 for invalid update data', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      mockReq.body = {}; // Empty body
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'No valid fields provided for update'
      });
    });
  });

  describe('DELETE /api/protected-example - Delete User Profile', () => {
    beforeEach(() => {
      mockReq.method = 'DELETE';
    });

    it('should delete user profile for authenticated user', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      mockSupabaseClient.from().delete().eq().mockResolvedValue({
        data: null,
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: 'Profile deleted successfully'
      });
    });

    it('should return 500 for database deletion error', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      mockSupabaseClient.from().delete().eq().mockResolvedValue({
        data: null,
        error: { message: 'Deletion failed' }
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Failed to delete profile'
      });
    });
  });

  describe('GET /api/protected-example?admin=true - Admin Only Route', () => {
    beforeEach(() => {
      mockReq.method = 'GET';
      mockReq.query = { admin: 'true' };
    });

    it('should allow access for admin user', async () => {
      mockReq.headers.authorization = `Bearer ${adminToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'admin-123',
          email: 'admin@example.com',
          name: 'Admin User',
          role: 'admin'
        },
        error: null
      });

      mockSupabaseClient.from().select().mockResolvedValue({
        data: [
          { id: 'user-1', email: 'user1@example.com', role: 'user' },
          { id: 'user-2', email: 'user2@example.com', role: 'user' }
        ],
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Admin data retrieved successfully',
          users: expect.arrayContaining([
            expect.objectContaining({ id: 'user-1' }),
            expect.objectContaining({ id: 'user-2' })
          ])
        })
      );
    });

    it('should deny access for regular user', async () => {
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Insufficient permissions'
      });
    });
  });

  describe('Unsupported HTTP Methods', () => {
    it('should return 405 for PATCH requests', async () => {
      mockReq.method = 'PATCH';
      mockReq.headers.authorization = `Bearer ${validToken}`;

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(405);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Method not allowed'
      });
    });
  });

  describe('CORS Headers', () => {
    it('should set CORS headers for all requests', async () => {
      mockReq.method = 'GET';
      mockReq.headers.authorization = `Bearer ${validToken}`;
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'user@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Origin', '*');
      expect(mockRes.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      expect(mockRes.setHeader).toHaveBeenCalledWith('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    });

    it('should handle OPTIONS preflight requests', async () => {
      mockReq.method = 'OPTIONS';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.end).toHaveBeenCalled();
    });
  });
});