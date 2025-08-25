import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
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
import handler from '../../api/authentication.js';

describe('Authentication API', () => {
  let mockReq, mockRes;

  beforeEach(() => {
    mockReq = global.testUtils.createMockRequest();
    mockRes = global.testUtils.createMockResponse();
    jest.clearAllMocks();
  });

  describe('POST /api/authentication - Register', () => {
    beforeEach(() => {
      mockReq.method = 'POST';
      mockReq.body = {
        email: 'test@example.com',
        password: 'password123',
        name: 'Test User'
      };
    });

    it('should register a new user successfully', async () => {
      // Mock Supabase responses
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: null,
        error: null
      });
      
      mockSupabaseClient.from().insert().select().single.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'test@example.com',
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'User registered successfully',
          user: expect.objectContaining({
            id: 'user-123',
            email: 'test@example.com'
          }),
          token: expect.any(String)
        })
      );
    });

    it('should return error if user already exists', async () => {
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: { id: 'existing-user', email: 'test@example.com' },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'User already exists with this email'
      });
    });

    it('should return error for invalid email format', async () => {
      mockReq.body.email = 'invalid-email';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid email format'
      });
    });

    it('should return error for weak password', async () => {
      mockReq.body.password = '123';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    });
  });

  describe('POST /api/authentication - Login', () => {
    beforeEach(() => {
      mockReq.method = 'POST';
      mockReq.body = {
        email: 'test@example.com',
        password: 'password123'
      };
    });

    it('should login user successfully with valid credentials', async () => {
      const hashedPassword = await bcrypt.hash('password123', 10);
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'test@example.com',
          password: hashedPassword,
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Login successful',
          user: expect.objectContaining({
            id: 'user-123',
            email: 'test@example.com'
          }),
          token: expect.any(String)
        })
      );
    });

    it('should return error for non-existent user', async () => {
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: null,
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid email or password'
      });
    });

    it('should return error for incorrect password', async () => {
      const hashedPassword = await bcrypt.hash('differentpassword', 10);
      
      mockSupabaseClient.from().select().eq().maybeSingle.mockResolvedValue({
        data: {
          id: 'user-123',
          email: 'test@example.com',
          password: hashedPassword,
          name: 'Test User',
          role: 'user'
        },
        error: null
      });

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid email or password'
      });
    });
  });

  describe('POST /api/authentication - Verify Token', () => {
    beforeEach(() => {
      mockReq.method = 'POST';
      mockReq.body = { action: 'verify' };
    });

    it('should verify valid token successfully', async () => {
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

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'Token is valid',
          user: expect.objectContaining({
            id: 'test-user-id',
            email: 'test@example.com'
          })
        })
      );
    });

    it('should return error for missing token', async () => {
      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'No token provided'
      });
    });

    it('should return error for invalid token', async () => {
      mockReq.headers.authorization = 'Bearer invalid-token';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Invalid or expired token'
      });
    });
  });

  describe('Unsupported HTTP Methods', () => {
    it('should return 405 for GET requests', async () => {
      mockReq.method = 'GET';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(405);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Method not allowed'
      });
    });

    it('should return 405 for PUT requests', async () => {
      mockReq.method = 'PUT';

      await handler(mockReq, mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(405);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: 'Method not allowed'
      });
    });
  });
});