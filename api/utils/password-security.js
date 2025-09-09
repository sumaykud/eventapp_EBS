const bcrypt = require('bcryptjs');
const crypto = require('crypto');

/**
 * Enhanced password security utilities
 * Provides comprehensive password validation, hashing, and security features
 */

// Password security configuration
const PASSWORD_CONFIG = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  maxConsecutiveChars: 3,
  preventCommonPasswords: true,
  saltRounds: 12,
  maxAttempts: 5,
  lockoutDuration: 15 * 60 * 1000, // 15 minutes
};

// Common passwords to reject (subset for demonstration)
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'qwerty', 'abc123',
  'password123', 'admin', 'letmein', 'welcome', 'monkey',
  '1234567890', 'password1', '123123', 'qwerty123',
  'admin123', 'root', 'toor', 'pass', 'test', 'guest'
]);

// Password attempt tracking
const passwordAttempts = new Map();

/**
 * Comprehensive password validation
 * @param {string} password - Password to validate
 * @param {Object} userInfo - User information for context-aware validation
 * @returns {Object} Validation result with success status and errors
 */
const validatePassword = (password, userInfo = {}) => {
  const errors = [];
  const warnings = [];
  
  try {
    // Basic length validation
    if (!password || typeof password !== 'string') {
      errors.push('Password is required and must be a string');
      return { isValid: false, errors, warnings };
    }
    
    if (password.length < PASSWORD_CONFIG.minLength) {
      errors.push(`Password must be at least ${PASSWORD_CONFIG.minLength} characters long`);
    }
    
    if (password.length > PASSWORD_CONFIG.maxLength) {
      errors.push(`Password must not exceed ${PASSWORD_CONFIG.maxLength} characters`);
    }
    
    // Character type requirements
    if (PASSWORD_CONFIG.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (PASSWORD_CONFIG.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (PASSWORD_CONFIG.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (PASSWORD_CONFIG.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*()_+-=[]{};\':"|\\,.<>/?)');
    }
    
    // Advanced security checks
    
    // Check for consecutive characters
    let consecutiveCount = 1;
    for (let i = 1; i < password.length; i++) {
      if (password[i] === password[i - 1]) {
        consecutiveCount++;
        if (consecutiveCount > PASSWORD_CONFIG.maxConsecutiveChars) {
          errors.push(`Password cannot have more than ${PASSWORD_CONFIG.maxConsecutiveChars} consecutive identical characters`);
          break;
        }
      } else {
        consecutiveCount = 1;
      }
    }
    
    // Check for sequential characters (123, abc, etc.)
    const hasSequential = /(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password);
    if (hasSequential) {
      warnings.push('Password contains sequential characters which may be less secure');
    }
    
    // Check against common passwords
    if (PASSWORD_CONFIG.preventCommonPasswords && COMMON_PASSWORDS.has(password.toLowerCase())) {
      errors.push('Password is too common. Please choose a more unique password');
    }
    
    // Context-aware validation (if user info provided)
    if (userInfo.email) {
      const emailLocal = userInfo.email.split('@')[0].toLowerCase();
      if (password.toLowerCase().includes(emailLocal)) {
        warnings.push('Password should not contain parts of your email address');
      }
    }
    
    if (userInfo.name) {
      const nameParts = userInfo.name.toLowerCase().split(' ');
      for (const part of nameParts) {
        if (part.length > 2 && password.toLowerCase().includes(part)) {
          warnings.push('Password should not contain parts of your name');
        }
      }
    }
    
    if (userInfo.phone) {
      const phoneDigits = userInfo.phone.replace(/\D/g, '');
      if (phoneDigits.length >= 4 && password.includes(phoneDigits.slice(-4))) {
        warnings.push('Password should not contain parts of your phone number');
      }
    }
    
    // Calculate password strength score
    const strengthScore = calculatePasswordStrength(password);
    if (strengthScore < 60) {
      warnings.push('Password strength is below recommended level');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      strengthScore,
      strength: getStrengthLabel(strengthScore)
    };
    
  } catch (error) {
    console.error('Password validation error:', error);
    return {
      isValid: false,
      errors: ['Password validation failed'],
      warnings: []
    };
  }
};

/**
 * Calculate password strength score (0-100)
 * @param {string} password - Password to analyze
 * @returns {number} Strength score
 */
const calculatePasswordStrength = (password) => {
  let score = 0;
  
  // Length scoring
  if (password.length >= 8) score += 20;
  if (password.length >= 12) score += 10;
  if (password.length >= 16) score += 10;
  
  // Character variety scoring
  if (/[a-z]/.test(password)) score += 10;
  if (/[A-Z]/.test(password)) score += 10;
  if (/\d/.test(password)) score += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score += 15;
  
  // Complexity bonus
  const uniqueChars = new Set(password).size;
  if (uniqueChars >= password.length * 0.7) score += 10;
  
  // Pattern penalties
  if (/(..).*\1/.test(password)) score -= 10; // Repeated patterns
  if (/^\d+$/.test(password)) score -= 20; // All numbers
  if (/^[a-zA-Z]+$/.test(password)) score -= 10; // All letters
  
  return Math.max(0, Math.min(100, score));
};

/**
 * Get strength label from score
 * @param {number} score - Strength score
 * @returns {string} Strength label
 */
const getStrengthLabel = (score) => {
  if (score >= 80) return 'Very Strong';
  if (score >= 60) return 'Strong';
  if (score >= 40) return 'Moderate';
  if (score >= 20) return 'Weak';
  return 'Very Weak';
};

/**
 * Enhanced password hashing with salt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Hashed password
 */
const hashPassword = async (password) => {
  try {
    // Validate password before hashing
    const validation = validatePassword(password);
    if (!validation.isValid) {
      throw new Error(`Password validation failed: ${validation.errors.join(', ')}`);
    }
    
    // Generate salt and hash
    const salt = await bcrypt.genSalt(PASSWORD_CONFIG.saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    return hashedPassword;
  } catch (error) {
    console.error('Password hashing error:', error);
    throw new Error('Failed to hash password');
  }
};

/**
 * Compare password with hash
 * @param {string} password - Plain text password
 * @param {string} hashedPassword - Hashed password
 * @returns {Promise<boolean>} Whether passwords match
 */
const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (error) {
    console.error('Password comparison error:', error);
    return false;
  }
};

/**
 * Track failed password attempts with lockout mechanism
 * @param {string} identifier - User identifier (email, ID, etc.)
 * @returns {Object} Attempt tracking result
 */
const trackPasswordAttempt = (identifier) => {
  const now = Date.now();
  const attempts = passwordAttempts.get(identifier) || { count: 0, firstAttempt: now, lockedUntil: null };
  
  // Check if currently locked out
  if (attempts.lockedUntil && now < attempts.lockedUntil) {
    return {
      isLocked: true,
      remainingLockout: Math.ceil((attempts.lockedUntil - now) / 1000),
      attemptsRemaining: 0
    };
  }
  
  // Reset if lockout period has passed
  if (attempts.lockedUntil && now >= attempts.lockedUntil) {
    attempts.count = 0;
    attempts.firstAttempt = now;
    attempts.lockedUntil = null;
  }
  
  // Increment attempt count
  attempts.count++;
  
  // Check if should be locked out
  if (attempts.count >= PASSWORD_CONFIG.maxAttempts) {
    attempts.lockedUntil = now + PASSWORD_CONFIG.lockoutDuration;
    passwordAttempts.set(identifier, attempts);
    
    return {
      isLocked: true,
      remainingLockout: Math.ceil(PASSWORD_CONFIG.lockoutDuration / 1000),
      attemptsRemaining: 0
    };
  }
  
  passwordAttempts.set(identifier, attempts);
  
  return {
    isLocked: false,
    remainingLockout: 0,
    attemptsRemaining: PASSWORD_CONFIG.maxAttempts - attempts.count
  };
};

/**
 * Reset password attempts for successful login
 * @param {string} identifier - User identifier
 */
const resetPasswordAttempts = (identifier) => {
  passwordAttempts.delete(identifier);
};

/**
 * Generate secure random password
 * @param {number} length - Password length (default: 16)
 * @param {Object} options - Generation options
 * @returns {string} Generated password
 */
const generateSecurePassword = (length = 16, options = {}) => {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSpecialChars = true,
    excludeSimilar = true // Exclude similar looking characters (0, O, l, 1, etc.)
  } = options;
  
  let charset = '';
  
  if (includeUppercase) {
    charset += excludeSimilar ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  }
  
  if (includeLowercase) {
    charset += excludeSimilar ? 'abcdefghijkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  }
  
  if (includeNumbers) {
    charset += excludeSimilar ? '23456789' : '0123456789';
  }
  
  if (includeSpecialChars) {
    charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  }
  
  if (!charset) {
    throw new Error('At least one character type must be included');
  }
  
  let password = '';
  const randomBytes = crypto.randomBytes(length * 2); // Extra bytes for filtering
  
  for (let i = 0, j = 0; i < length && j < randomBytes.length; j++) {
    const randomIndex = randomBytes[j] % charset.length;
    password += charset[randomIndex];
    i++;
  }
  
  return password;
};

/**
 * Check if password needs to be updated (based on age, security requirements, etc.)
 * @param {Date} lastPasswordChange - Date of last password change
 * @param {string} currentPassword - Current password hash
 * @returns {Object} Update recommendation
 */
const checkPasswordUpdateNeeded = (lastPasswordChange, currentPassword) => {
  const now = new Date();
  const daysSinceChange = Math.floor((now - new Date(lastPasswordChange)) / (1000 * 60 * 60 * 24));
  
  const recommendations = [];
  let priority = 'low';
  
  // Age-based recommendations
  if (daysSinceChange > 365) {
    recommendations.push('Password is over 1 year old');
    priority = 'high';
  } else if (daysSinceChange > 180) {
    recommendations.push('Password is over 6 months old');
    priority = 'medium';
  } else if (daysSinceChange > 90) {
    recommendations.push('Consider updating password (over 3 months old)');
    priority = 'low';
  }
  
  // Security-based recommendations
  if (currentPassword && currentPassword.startsWith('$2a$')) {
    const rounds = parseInt(currentPassword.split('$')[2]);
    if (rounds < 10) {
      recommendations.push('Password hash uses outdated security parameters');
      priority = 'high';
    }
  }
  
  return {
    needsUpdate: recommendations.length > 0,
    priority,
    recommendations,
    daysSinceChange
  };
};

module.exports = {
  validatePassword,
  calculatePasswordStrength,
  getStrengthLabel,
  hashPassword,
  comparePassword,
  trackPasswordAttempt,
  resetPasswordAttempts,
  generateSecurePassword,
  checkPasswordUpdateNeeded,
  PASSWORD_CONFIG
};