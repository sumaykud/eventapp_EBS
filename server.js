/**
 * Production Server for Event Joining App
 * 
 * This is the main server file that integrates all components:
 * - Authentication system with JWT and RBAC
 * - Security middleware and headers
 * - Rate limiting and password security
 * - API endpoints for admin, user profiles, and baptism management
 * - Health checks and monitoring
 * - Error handling and logging
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

// Load environment configuration
dotenv.config({
  path: process.env.NODE_ENV === 'production' 
    ? '.env.production' 
    : process.env.NODE_ENV === 'test'
    ? '.env.test'
    : '.env'
});

// Import our modules
const { authenticateToken, requireAdmin, requireUser } = require('./api/authentication');
const { hasPermission, requirePermission } = require('./api/middleware/rbac');
const adminRoutes = require('./api/admin-users.js');
const userRoutes = require('./api/user-profile.js');
const baptismRoutes = require('./api/baptism-management.js');

// Production configuration
const { productionConfig } = require('./deployment/production.config');

class ProductionServer {
  constructor() {
    this.app = express();
    this.server = null;
    this.isShuttingDown = false;
    
    // Initialize server
    this.setupMiddleware();
    this.setupRoutes();
    this.setupErrorHandling();
    this.setupGracefulShutdown();
  }

  setupMiddleware() {
    // Security headers
    this.app.use(helmet(productionConfig.security.helmet));
    
    // Compression
    if (productionConfig.server.compression) {
      this.app.use(compression());
    }
    
    // CORS configuration
    this.app.use(cors(productionConfig.server.cors));
    
    // Body parsing
    this.app.use(express.json({ 
      limit: productionConfig.server.maxRequestSize,
      strict: true
    }));
    this.app.use(express.urlencoded({ 
      extended: true, 
      limit: productionConfig.server.maxRequestSize 
    }));
    
    // Request timeout
    this.app.use((req, res, next) => {
      req.setTimeout(productionConfig.server.requestTimeout, () => {
        res.status(408).json({ 
          error: 'Request timeout',
          message: 'Request took too long to process'
        });
      });
      next();
    });
    
    // General rate limiting
    const generalLimiter = rateLimit(productionConfig.security.rateLimit);
    this.app.use(generalLimiter);
    
    // Authentication rate limiting
    const authLimiter = rateLimit(productionConfig.security.authRateLimit);
    this.app.use('/api/auth', authLimiter);
    
    // Request logging
    this.app.use((req, res, next) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = {
          timestamp: new Date().toISOString(),
          method: req.method,
          url: req.url,
          status: res.statusCode,
          duration: `${duration}ms`,
          userAgent: req.get('User-Agent'),
          ip: req.ip || req.connection.remoteAddress
        };
        
        if (process.env.NODE_ENV === 'production') {
          console.log(JSON.stringify(logData));
        } else {
          console.log(`${req.method} ${req.url} - ${res.statusCode} - ${duration}ms`);
        }
      });
      
      next();
    });
    
    // Add request ID for tracing
    this.app.use((req, res, next) => {
      req.id = Math.random().toString(36).substr(2, 9);
      res.setHeader('X-Request-ID', req.id);
      next();
    });
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', async (req, res) => {
      try {
        const health = {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          version: process.env.npm_package_version || '1.0.0',
          environment: process.env.NODE_ENV,
          requestId: req.id
        };
        
        // Test database connection
        const { createClient } = require('@supabase/supabase-js');
        const supabase = createClient(
          process.env.SUPABASE_URL,
          process.env.SUPABASE_ANON_KEY
        );
        
        const { error } = await supabase
          .from('users')
          .select('count')
          .limit(1);
        
        if (error) {
          health.database = 'unhealthy';
          health.status = 'degraded';
        } else {
          health.database = 'healthy';
        }
        
        const statusCode = health.status === 'healthy' ? 200 : 503;
        res.status(statusCode).json(health);
        
      } catch (error) {
        res.status(503).json({
          status: 'unhealthy',
          error: error.message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      }
    });
    
    // Metrics endpoint (basic)
    this.app.get('/metrics', (req, res) => {
      const metrics = {
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV,
        requestId: req.id
      };
      
      res.json(metrics);
    });
    
    // API routes
    this.app.use('/api/auth', this.createAuthRoutes());
    this.app.use('/api/admin', authenticateToken, requireAdmin, adminRoutes);
    this.app.use('/api/user', authenticateToken, requireUser, userRoutes);
    this.app.use('/api/baptism', authenticateToken, requirePermission('baptism', 'update'), baptismRoutes);
    
    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        name: 'Event Joining App API',
        version: process.env.npm_package_version || '1.0.0',
        environment: process.env.NODE_ENV,
        status: 'running',
        timestamp: new Date().toISOString(),
        endpoints: {
          health: '/health',
          metrics: '/metrics',
          auth: '/api/auth',
          admin: '/api/admin',
          user: '/api/user',
          baptism: '/api/baptism'
        }
      });
    });
    
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.originalUrl} not found`,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    });
  }
  
  createAuthRoutes() {
    const router = express.Router();
    const { registerUser, loginUser, refreshToken, logoutUser, validateSession } = require('./api/authentication');
    
    // Registration
    router.post('/register', async (req, res) => {
      try {
        const result = await registerUser(req.body);
        res.status(201).json({
          success: true,
          message: 'User registered successfully',
          data: result,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      }
    });
    
    // Login
    router.post('/login', async (req, res) => {
      try {
        const result = await loginUser(req.body, {
          userAgent: req.get('User-Agent'),
          ipAddress: req.ip || req.connection.remoteAddress
        });
        
        res.json({
          success: true,
          message: 'Login successful',
          data: result,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      } catch (error) {
        res.status(401).json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      }
    });
    
    // Refresh token
    router.post('/refresh', async (req, res) => {
      try {
        const result = await refreshToken(req.body.refreshToken);
        res.json({
          success: true,
          data: result,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      } catch (error) {
        res.status(401).json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      }
    });
    
    // Logout
    router.post('/logout', authenticateToken, async (req, res) => {
      try {
        await logoutUser(req.user.sessionId);
        res.json({
          success: true,
          message: 'Logout successful',
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      } catch (error) {
        res.status(400).json({
          success: false,
          error: error.message,
          timestamp: new Date().toISOString(),
          requestId: req.id
        });
      }
    });
    
    // Validate session
    router.get('/validate', authenticateToken, (req, res) => {
      res.json({
        success: true,
        valid: true,
        user: {
          id: req.user.userId,
          email: req.user.email,
          role: req.user.role
        },
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    });
    
    return router;
  }

  setupErrorHandling() {
    // Global error handler
    this.app.use((error, req, res, next) => {
      // Log error
      console.error('Unhandled error:', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
      
      // Don't expose stack traces in production
      const isDevelopment = process.env.NODE_ENV !== 'production';
      
      res.status(error.status || 500).json({
        success: false,
        error: 'Internal Server Error',
        message: isDevelopment ? error.message : 'Something went wrong',
        ...(isDevelopment && { stack: error.stack }),
        timestamp: new Date().toISOString(),
        requestId: req.id
      });
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      this.gracefulShutdown('SIGTERM');
    });
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
      this.gracefulShutdown('SIGTERM');
    });
  }

  setupGracefulShutdown() {
    // Handle shutdown signals
    process.on('SIGTERM', () => this.gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => this.gracefulShutdown('SIGINT'));
  }

  gracefulShutdown(signal) {
    if (this.isShuttingDown) {
      return;
    }
    
    this.isShuttingDown = true;
    console.log(`Received ${signal}. Starting graceful shutdown...`);
    
    // Stop accepting new connections
    if (this.server) {
      this.server.close((err) => {
        if (err) {
          console.error('Error during server shutdown:', err);
          process.exit(1);
        }
        
        console.log('Server closed successfully');
        process.exit(0);
      });
      
      // Force shutdown after timeout
      setTimeout(() => {
        console.error('Forced shutdown due to timeout');
        process.exit(1);
      }, 10000);
    } else {
      process.exit(0);
    }
  }

  start() {
    const port = process.env.PORT || 3000;
    const host = process.env.HOST || '0.0.0.0';
    
    this.server = this.app.listen(port, host, () => {
      console.log(`🚀 Event Joining App server running on ${host}:${port}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV}`);
      console.log(`🔍 Health check: http://${host}:${port}/health`);
      console.log(`📈 Metrics: http://${host}:${port}/metrics`);
      console.log(`🔐 API endpoints: http://${host}:${port}/api`);
      
      if (process.env.NODE_ENV === 'production') {
        console.log('✅ Production server started successfully');
      }
    });
    
    // Handle server errors
    this.server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use`);
      } else {
        console.error('Server error:', error);
      }
      process.exit(1);
    });
    
    return this.server;
  }
}

// Start server if this file is run directly
if (require.main === module) {
  const server = new ProductionServer();
  server.start();
}

module.exports = ProductionServer;