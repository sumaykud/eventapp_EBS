/**
 * Security utility functions for input validation and sanitization
 */

/**
 * Sanitize input to prevent XSS and injection attacks
 * @param {string} input - The input string to sanitize
 * @returns {string} - Sanitized input
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  return input
    .replace(/[<>"'&]/g, function(match) {
      const escapeMap = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;'
      };
      return escapeMap[match];
    })
    .trim();
}

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} - True if valid email format
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return false;
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.toLowerCase());
}

/**
 * Validate phone number format
 * @param {string} phone - Phone number to validate
 * @returns {boolean} - True if valid phone format
 */
function validatePhone(phone) {
  if (!phone || typeof phone !== 'string') {
    return false;
  }
  
  // Remove all non-digit characters
  const cleanPhone = phone.replace(/\D/g, '');
  
  // Check if it's a valid length (10-15 digits)
  return cleanPhone.length >= 10 && cleanPhone.length <= 15;
}

/**
 * Validate password complexity
 * @param {string} password - Password to validate
 * @returns {object} - Validation result with success and errors
 */
function validatePasswordComplexity(password) {
  const errors = [];
  
  if (!password || typeof password !== 'string') {
    return { success: false, errors: ['Password is required'] };
  }
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    success: errors.length === 0,
    errors
  };
}

/**
 * Validate name format
 * @param {string} name - Name to validate
 * @returns {boolean} - True if valid name format
 */
function validateName(name) {
  if (!name || typeof name !== 'string') {
    return false;
  }
  
  // Allow letters, spaces, hyphens, and apostrophes
  const nameRegex = /^[a-zA-Z\s\-']+$/;
  return nameRegex.test(name.trim()) && name.trim().length >= 2;
}

module.exports = {
  sanitizeInput,
  validateEmail,
  validatePhone,
  validatePasswordComplexity,
  validateName
};