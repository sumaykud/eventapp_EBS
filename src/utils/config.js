/**
 * Configuration Management
 * Centralized configuration for environment variables, constants, and app settings
 */

// Environment variables with fallbacks
const config = {
  // Environment
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Server Configuration
  PORT: process.env.PORT || 3000,
  API_BASE_URL: process.env.VITE_API_BASE_URL || 'http://localhost:3000',
  
  // Supabase Configuration
  supabase: {
    url: process.env.VITE_SUPABASE_URL,
    anonKey: process.env.VITE_SUPABASE_ANON_KEY,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  },
  
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  
  // Security Configuration
  security: {
    bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
    corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100, // requests per window
  },
  
  // File Upload Configuration
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
    allowedMimeTypes: [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf',
      'text/plain',
    ],
    uploadPath: process.env.UPLOAD_PATH || 'uploads/',
  },
  
  // Database Configuration
  database: {
    connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 30000,
    queryTimeout: parseInt(process.env.DB_QUERY_TIMEOUT) || 10000,
    maxRetries: parseInt(process.env.DB_MAX_RETRIES) || 3,
  },
  
  // Email Configuration (for future use)
  email: {
    from: process.env.EMAIL_FROM || 'noreply@eventapp.com',
    smtpHost: process.env.SMTP_HOST,
    smtpPort: parseInt(process.env.SMTP_PORT) || 587,
    smtpUser: process.env.SMTP_USER,
    smtpPass: process.env.SMTP_PASS,
  },
  
  // Application Constants
  app: {
    name: 'Event Joining App',
    version: '1.0.0',
    description: 'A platform for creating and joining events',
    supportEmail: 'support@eventapp.com',
  },
  
  // Feature Flags
  features: {
    enableEmailVerification: process.env.ENABLE_EMAIL_VERIFICATION === 'true',
    enableSocialLogin: process.env.ENABLE_SOCIAL_LOGIN === 'true',
    enableFileUploads: process.env.ENABLE_FILE_UPLOADS !== 'false',
    enableNotifications: process.env.ENABLE_NOTIFICATIONS !== 'false',
  },
};

/**
 * Validate required environment variables
 * @returns {Object} Validation result with isValid flag and missing variables
 */
export const validateConfig = () => {
  const requiredVars = [
    'VITE_SUPABASE_URL',
    'VITE_SUPABASE_ANON_KEY',
    'JWT_SECRET',
  ];
  
  const missing = requiredVars.filter(varName => {
    const keys = varName.split('.');
    let value = process.env;
    
    for (const key of keys) {
      value = value?.[key];
    }
    
    return !value;
  });
  
  return {
    isValid: missing.length === 0,
    missing,
    message: missing.length > 0 
      ? `Missing required environment variables: ${missing.join(', ')}` 
      : 'All required environment variables are present'
  };
};

/**
 * Get configuration value by path
 * @param {string} path - Dot notation path (e.g., 'supabase.url')
 * @param {*} defaultValue - Default value if path not found
 * @returns {*} Configuration value
 */
export const getConfig = (path, defaultValue = null) => {
  const keys = path.split('.');
  let value = config;
  
  for (const key of keys) {
    value = value?.[key];
    if (value === undefined) {
      return defaultValue;
    }
  }
  
  return value;
};

/**
 * Check if running in development mode
 * @returns {boolean}
 */
export const isDevelopment = () => config.NODE_ENV === 'development';

/**
 * Check if running in production mode
 * @returns {boolean}
 */
export const isProduction = () => config.NODE_ENV === 'production';

/**
 * Check if running in test mode
 * @returns {boolean}
 */
export const isTest = () => config.NODE_ENV === 'test';

/**
 * Get CORS configuration
 * @returns {Object} CORS configuration object
 */
export const getCorsConfig = () => ({
  origin: config.security.corsOrigin,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
});

/**
 * Get rate limiting configuration
 * @returns {Object} Rate limiting configuration
 */
export const getRateLimitConfig = () => ({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMax,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: Math.ceil(config.security.rateLimitWindowMs / 1000),
  },
});

/**
 * Initialize configuration and validate environment
 * Should be called at application startup
 */
export const initializeConfig = () => {
  const validation = validateConfig();
  
  if (!validation.isValid) {
    console.error('❌ Configuration Error:', validation.message);
    if (isProduction()) {
      process.exit(1);
    }
  } else {
    console.log('✅ Configuration validated successfully');
  }
  
  // Log configuration in development
  if (isDevelopment()) {
    console.log('🔧 Configuration loaded:', {
      environment: config.NODE_ENV,
      supabaseUrl: config.supabase.url ? '✅ Set' : '❌ Missing',
      jwtSecret: config.jwt.secret ? '✅ Set' : '❌ Missing',
      features: config.features,
    });
  }
  
  return config;
};

export default config;