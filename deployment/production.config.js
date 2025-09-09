// Production deployment configuration for Event Joining App
// This file contains production-ready settings for security, performance, and monitoring

const productionConfig = {
  // Server Configuration
  server: {
    port: process.env.PORT || 3000,
    host: process.env.HOST || '0.0.0.0',
    nodeEnv: 'production',
    
    // Enable compression
    compression: true,
    
    // Request limits
    requestTimeout: 30000, // 30 seconds
    maxRequestSize: '10mb',
    
    // CORS settings
    cors: {
      origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
    }
  },

  // Security Configuration
  security: {
    // JWT Settings
    jwt: {
      secret: process.env.JWT_SECRET,
      refreshSecret: process.env.JWT_REFRESH_SECRET,
      accessTokenExpiry: '15m',
      refreshTokenExpiry: '7d',
      issuer: 'event-joining-app',
      audience: 'event-joining-users'
    },

    // Rate Limiting
    rateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false
    },

    // Authentication Rate Limiting
    authRateLimit: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 auth requests per windowMs
      skipSuccessfulRequests: true
    },

    // Security Headers
    helmet: {
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"]
        }
      },
      crossOriginEmbedderPolicy: false,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    },

    // Password Security
    password: {
      saltRounds: 12,
      minLength: 8,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      maxAttempts: 5,
      lockoutDuration: 15 * 60 * 1000 // 15 minutes
    }
  },

  // Database Configuration
  database: {
    supabase: {
      url: process.env.SUPABASE_URL,
      anonKey: process.env.SUPABASE_ANON_KEY,
      serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
      
      // Connection pool settings
      db: {
        schema: 'public',
        poolSize: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000
      }
    }
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: 'json',
    
    // Log rotation
    file: {
      filename: 'logs/app-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '14d',
      compress: true
    },
    
    // Error logging
    error: {
      filename: 'logs/error-%DATE%.log',
      level: 'error'
    },
    
    // Audit logging
    audit: {
      filename: 'logs/audit-%DATE%.log',
      events: ['login', 'logout', 'password_change', 'role_change', 'data_access']
    }
  },

  // Monitoring Configuration
  monitoring: {
    // Health check endpoint
    healthCheck: {
      path: '/health',
      checks: {
        database: true,
        memory: true,
        disk: true
      }
    },
    
    // Metrics collection
    metrics: {
      enabled: true,
      path: '/metrics',
      collectDefaultMetrics: true,
      requestDuration: true,
      requestRate: true,
      errorRate: true
    }
  },

  // Session Configuration
  session: {
    maxConcurrentSessions: 5,
    sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
    cleanupInterval: 60 * 60 * 1000, // 1 hour
    
    // Session storage
    store: {
      type: 'memory', // In production, consider Redis
      options: {
        checkPeriod: 86400000 // 24 hours
      }
    }
  },

  // Cache Configuration
  cache: {
    // Response caching
    response: {
      enabled: true,
      ttl: 300, // 5 minutes
      maxSize: 100 // MB
    },
    
    // Static file caching
    static: {
      maxAge: 86400000, // 24 hours
      etag: true,
      lastModified: true
    }
  },

  // Error Handling
  errorHandling: {
    // Hide stack traces in production
    showStackTrace: false,
    
    // Log all errors
    logErrors: true,
    
    // Custom error pages
    customErrorPages: {
      404: 'errors/404.html',
      500: 'errors/500.html'
    }
  },

  // API Configuration
  api: {
    // API versioning
    version: 'v1',
    prefix: '/api',
    
    // Request validation
    validation: {
      stripUnknown: true,
      abortEarly: false
    },
    
    // Response formatting
    response: {
      includeTimestamp: true,
      includeRequestId: true
    }
  }
};

// Environment validation
const requiredEnvVars = [
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY'
];

const validateEnvironment = () => {
  const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  // Validate JWT secrets are strong enough
  if (process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
  
  if (process.env.JWT_REFRESH_SECRET.length < 32) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }
};

// Security recommendations
const securityChecklist = {
  environment: [
    'Set NODE_ENV=production',
    'Use strong JWT secrets (32+ characters)',
    'Configure HTTPS in reverse proxy',
    'Set up proper CORS origins',
    'Enable security headers',
    'Configure rate limiting'
  ],
  
  database: [
    'Use connection pooling',
    'Enable SSL connections',
    'Implement proper backup strategy',
    'Set up monitoring and alerts',
    'Use least privilege access'
  ],
  
  deployment: [
    'Use process manager (PM2, systemd)',
    'Set up log rotation',
    'Configure health checks',
    'Implement graceful shutdowns',
    'Set up monitoring and alerting'
  ],
  
  maintenance: [
    'Regular security updates',
    'Monitor for vulnerabilities',
    'Backup and recovery testing',
    'Performance monitoring',
    'Log analysis and alerting'
  ]
};

module.exports = {
  productionConfig,
  validateEnvironment,
  securityChecklist
};