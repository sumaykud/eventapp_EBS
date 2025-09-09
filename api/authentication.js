// Load environment variables first
require('dotenv').config({
  path: process.env.NODE_ENV === 'production' 
    ? '.env.production' 
    : process.env.NODE_ENV === 'test'
    ? '.env.test'
    : '.env'
});

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const { 
  validatePassword, 
  hashPassword: secureHashPassword, 
  comparePassword: secureComparePassword,
  trackPasswordAttempt,
  resetPasswordAttempts
} = require('./utils/password-security.js');

// Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// JWT configuration from environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || JWT_SECRET + '_refresh';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m'; // Shorter access token
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;

// Rate limiting configuration
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_LOGIN_ATTEMPTS = 5;
const MAX_REGISTRATION_ATTEMPTS = 3;

// In-memory rate limiting store (use Redis in production)
const rateLimitStore = new Map();

// Helper function to generate JWT access token
const generateToken = (userId, email, role = 'user', sessionId = null) => {
  const payload = { 
    userId, 
    email, 
    role,
    sessionId,
    tokenType: 'access',
    iat: Math.floor(Date.now() / 1000)
  };
  
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Helper function to generate JWT refresh token
const generateRefreshToken = (userId, email, role = 'user', sessionId = null) => {
  const payload = { 
    userId, 
    email, 
    role,
    sessionId,
    tokenType: 'refresh',
    iat: Math.floor(Date.now() / 1000)
  };
  
  return jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: JWT_REFRESH_EXPIRES_IN });
};

// Helper function to verify JWT access token
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.tokenType !== 'access') {
      return null;
    }
    return decoded;
  } catch (error) {
    return null;
  }
};

// Helper function to verify JWT refresh token
const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
    if (decoded.tokenType !== 'refresh') {
      return null;
    }
    return decoded;
  } catch (error) {
    return null;
  }
};

// Rate limiting helper
const checkRateLimit = (identifier, maxAttempts) => {
  const now = Date.now();
  const key = `${identifier}_${Math.floor(now / RATE_LIMIT_WINDOW)}`;
  
  const attempts = rateLimitStore.get(key) || 0;
  if (attempts >= maxAttempts) {
    return false;
  }
  
  rateLimitStore.set(key, attempts + 1);
  
  // Clean up old entries
  for (const [storeKey] of rateLimitStore) {
    const keyTime = parseInt(storeKey.split('_').pop()) * RATE_LIMIT_WINDOW;
    if (now - keyTime > RATE_LIMIT_WINDOW) {
      rateLimitStore.delete(storeKey);
    }
  }
  
  return true;
};

// Create user session
const createUserSession = async (userId, userAgent, ipAddress) => {
  try {
    const sessionId = `session_${userId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const { data: session, error } = await supabase
      .from('user_sessions')
      .insert({
        id: sessionId,
        user_id: userId,
        user_agent: userAgent,
        ip_address: ipAddress,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
        is_active: true
      })
      .select('id')
      .single();
    
    if (error) {
      console.error('Session creation error:', error);
      return null;
    }
    
    return session.id;
  } catch (error) {
    console.error('Create session error:', error);
    return null;
  }
};

// Validate user session
const validateUserSession = async (sessionId, userId) => {
  try {
    const { data: session, error } = await supabase
      .from('user_sessions')
      .select('id, expires_at, is_active')
      .eq('id', sessionId)
      .eq('user_id', userId)
      .eq('is_active', true)
      .single();
    
    if (error || !session) {
      return false;
    }
    
    // Check if session is expired
    if (new Date(session.expires_at) < new Date()) {
      // Deactivate expired session
      await supabase
        .from('user_sessions')
        .update({ is_active: false })
        .eq('id', sessionId);
      return false;
    }
    
    return true;
  } catch (error) {
    console.error('Session validation error:', error);
    return false;
  }
};

// Invalidate user session
const invalidateUserSession = async (sessionId) => {
  try {
    await supabase
      .from('user_sessions')
      .update({ 
        is_active: false,
        updated_at: new Date().toISOString()
      })
      .eq('id', sessionId);
    return true;
  } catch (error) {
    console.error('Session invalidation error:', error);
    return false;
  }
};

// Enhanced password validation with complexity requirements
const validatePasswordComplexity = (password, userInfo = {}) => {
  return validatePassword(password, userInfo);
};

// Use enhanced password utilities
const hashPassword = secureHashPassword;
const comparePassword = secureComparePassword;

async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { action } = req.query;

  try {
    switch (action) {
      case 'register':
        return await handleRegistration(req, res);
      case 'login':
        return await handleLogin(req, res);
      case 'verify':
        return await handleTokenVerification(req, res);
      case 'refresh':
        return await handleTokenRefresh(req, res);
      case 'logout':
        return await handleLogout(req, res);
      default:
        return res.status(400).json({ error: 'Invalid action specified' });
    }
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// Handle user registration
async function handleRegistration(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password, name, phone, role = 'user' } = req.body;
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  // Rate limiting check
  if (!checkRateLimit(`reg_${clientIP}`, MAX_REGISTRATION_ATTEMPTS)) {
    return res.status(429).json({ 
      error: 'Too many registration attempts. Please try again later.',
      retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000 / 60) // minutes
    });
  }

  // Validate required fields
  if (!email || !password || !name) {
    return res.status(400).json({ 
      error: 'Missing required fields: email, password, name' 
    });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  // Enhanced password validation with user context
  const passwordValidation = validatePasswordComplexity(password, { email, name });
  if (!passwordValidation.isValid) {
    return res.status(400).json({
      error: 'Password does not meet security requirements',
      details: passwordValidation.errors,
      warnings: passwordValidation.warnings,
      strength: passwordValidation.strength
    });
  }
  
  // Validate role
  if (role && !['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  try {
    // Check if user already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existingUser) {
      return res.status(409).json({ error: 'User already exists with this email' });
    }

    // Hash the password
    const hashedPassword = await hashPassword(password);

    // Create new user
    const { data: newUser, error } = await supabase
      .from('users')
      .insert([
        {
          email: email.toLowerCase(),
          password_hash: hashedPassword,
          name,
          phone,
          role,
          is_active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      ])
      .select('id, email, name, phone, role, is_active, created_at')
      .single();

    if (error) {
      console.error('Supabase registration error:', error);
      return res.status(500).json({ error: 'Failed to create user account' });
    }

    // Create user session
    const sessionId = await createUserSession(newUser.id, userAgent, clientIP);
    
    // Generate JWT tokens
    const accessToken = generateToken(newUser.id, newUser.email, newUser.role, sessionId);
    const refreshToken = generateRefreshToken(newUser.id, newUser.email, newUser.role, sessionId);

    return res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        phone: newUser.phone,
        role: newUser.role,
        isActive: newUser.is_active,
        createdAt: newUser.created_at
      },
      accessToken,
      refreshToken,
      expiresIn: JWT_EXPIRES_IN,
      refreshExpiresIn: JWT_REFRESH_EXPIRES_IN
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Registration failed' });
  }
}

// Handle user login
async function handleLogin(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password } = req.body;
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  // Rate limiting check
  if (!checkRateLimit(`login_${clientIP}`, MAX_LOGIN_ATTEMPTS)) {
    return res.status(429).json({ 
      error: 'Too many login attempts. Please try again later.',
      retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000 / 60) // minutes
    });
  }

  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({ 
      error: 'Missing required fields: email, password' 
    });
  }

  try {
    // Find user by email
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, password_hash, name, phone, role, is_active')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated' });
    }

    // Check for account lockout
    const attemptResult = trackPasswordAttempt(email);
    if (attemptResult.isLocked) {
      return res.status(429).json({
        error: 'Account temporarily locked due to too many failed attempts',
        code: 'ACCOUNT_LOCKED',
        retryAfter: attemptResult.remainingLockout
      });
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({
        error: 'Invalid email or password',
        attemptsRemaining: attemptResult.attemptsRemaining
      });
    }

    // Reset password attempts on successful login
    resetPasswordAttempts(email);

    // Update last login timestamp
    await supabase
      .from('users')
      .update({ 
        last_login: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id);

    // Create user session
    const sessionId = await createUserSession(user.id, userAgent, clientIP);
    
    // Generate JWT tokens
    const accessToken = generateToken(user.id, user.email, user.role, sessionId);
    const refreshToken = generateRefreshToken(user.id, user.email, user.role, sessionId);

    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        role: user.role,
        isActive: user.is_active
      },
      accessToken,
      refreshToken,
      expiresIn: JWT_EXPIRES_IN,
      refreshExpiresIn: JWT_REFRESH_EXPIRES_IN
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Login failed' });
  }
}

// Handle token verification
async function handleTokenVerification(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Optionally verify user still exists and is active
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, role, is_active')
      .eq('id', decoded.userId)
      .single();

    if (error || !user || !user.is_active) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }

    return res.status(200).json({
      message: 'Token is valid',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isActive: user.is_active
      },
      tokenData: {
        userId: decoded.userId,
        email: decoded.email,
        role: decoded.role,
        iat: decoded.iat,
        exp: decoded.exp
      }
    });

  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ error: 'Token verification failed' });
  }
}

// Handle token refresh
async function handleTokenRefresh(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { refreshToken } = req.body;
  const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }

  try {
    // Verify the refresh token
    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    // Validate session if sessionId exists
    if (decoded.sessionId) {
      const isValidSession = await validateUserSession(decoded.sessionId, decoded.userId);
      if (!isValidSession) {
        return res.status(403).json({ error: 'Session expired or invalid' });
      }
    }

    // Check if user still exists and is active
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, name, role, is_active')
      .eq('id', decoded.userId)
      .single();

    if (error || !user || !user.is_active) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }

    // Create new session if needed
    let sessionId = decoded.sessionId;
    if (!sessionId) {
      sessionId = await createUserSession(user.id, userAgent, clientIP);
    }

    // Generate new tokens
    const newAccessToken = generateToken(user.id, user.email, user.role, sessionId);
    const newRefreshToken = generateRefreshToken(user.id, user.email, user.role, sessionId);

    return res.status(200).json({
      message: 'Tokens refreshed successfully',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        isActive: user.is_active
      },
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: JWT_EXPIRES_IN,
      refreshExpiresIn: JWT_REFRESH_EXPIRES_IN
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    return res.status(500).json({ error: 'Token refresh failed' });
  }
}

// Handle user logout
async function handleLogout(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(200).json({ message: 'Logout successful' });
  }

  try {
    // Decode token to get session info (don't verify as it might be expired)
    const decoded = jwt.decode(token);
    
    if (decoded && decoded.sessionId) {
      // Invalidate the session
      await invalidateUserSession(decoded.sessionId);
    }

    return res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    // Still return success as logout should always work
    return res.status(200).json({ message: 'Logout successful' });
  }
}

// Main route handler functions for server.js
const registerUser = async (userData) => {
  return new Promise((resolve, reject) => {
    const mockReq = {
      method: 'POST',
      body: userData
    };
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          if (code >= 400) {
            reject(new Error(data.error || 'Registration failed'));
          } else {
            resolve(data.data || data);
          }
        }
      }),
      json: (data) => resolve(data.data || data)
    };
    handleRegistration(mockReq, mockRes);
  });
};

const loginUser = async (credentials, metadata = {}) => {
  return new Promise((resolve, reject) => {
    const mockReq = {
      method: 'POST',
      body: credentials,
      get: (header) => metadata.userAgent || '',
      ip: metadata.ipAddress || '127.0.0.1',
      connection: { remoteAddress: metadata.ipAddress || '127.0.0.1' }
    };
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          if (code >= 400) {
            reject(new Error(data.error || 'Login failed'));
          } else {
            resolve(data.data || data);
          }
        }
      }),
      json: (data) => resolve(data.data || data)
    };
    handleLogin(mockReq, mockRes);
  });
};

const refreshToken = async (tokenData) => {
  return new Promise((resolve, reject) => {
    const mockReq = {
      method: 'POST',
      body: tokenData
    };
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          if (code >= 400) {
            reject(new Error(data.error || 'Token refresh failed'));
          } else {
            resolve(data.data || data);
          }
        }
      }),
      json: (data) => resolve(data.data || data)
    };
    handleTokenRefresh(mockReq, mockRes);
  });
};

const logoutUser = async (sessionId) => {
  return new Promise((resolve, reject) => {
    const mockReq = {
      method: 'POST',
      user: { sessionId }
    };
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          if (code >= 400) {
            reject(new Error(data.error || 'Logout failed'));
          } else {
            resolve(data);
          }
        }
      }),
      json: (data) => resolve(data)
    };
    handleLogout(mockReq, mockRes);
  });
};

const validateSession = async (token) => {
  return new Promise((resolve, reject) => {
    const mockReq = {
      method: 'POST',
      headers: { authorization: `Bearer ${token}` }
    };
    const mockRes = {
      status: (code) => ({
        json: (data) => {
          if (code >= 400) {
            reject(new Error(data.error || 'Session validation failed'));
          } else {
            resolve(data.data || data);
          }
        }
      }),
      json: (data) => resolve(data.data || data)
    };
    handleTokenVerification(mockReq, mockRes);
  });
};

// Middleware functions
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    // Validate session if sessionId exists
    if (decoded.sessionId) {
      const sessionValid = await validateUserSession(decoded.sessionId, decoded.userId);
      if (!sessionValid) {
        return res.status(403).json({ error: 'Session expired or invalid' });
      }
    }

    // Check if user is active
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.userId)
      .is('deleted_at', null)
      .single();

    if (error || !user || !user.is_active) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

const requireAdmin = async (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const requireUser = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Export helper functions for use in other API routes
module.exports = { 
  handler,
  registerUser,
  loginUser,
  refreshToken,
  logoutUser,
  validateSession,
  authenticateToken,
  requireAdmin,
  requireUser,
  verifyToken, 
  verifyRefreshToken,
  generateToken, 
  generateRefreshToken,
  hashPassword, 
  comparePassword,
  validateUserSession,
  invalidateUserSession,
  createUserSession
};