import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

// Set test environment
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-for-testing-only';
process.env.SUPABASE_URL = 'https://test.supabase.co';
process.env.SUPABASE_ANON_KEY = 'test-anon-key';

// Global test setup
beforeAll(async () => {
  console.log('🧪 Starting test suite...');
});

afterAll(async () => {
  console.log('✅ Test suite completed');
});

// Reset mocks before each test
beforeEach(() => {
  // Clear any cached modules
  if (typeof vi !== 'undefined') {
    vi.clearAllMocks();
  }
});

afterEach(() => {
  // Clean up after each test
  if (typeof vi !== 'undefined') {
    vi.restoreAllMocks();
  }
});

// Global error handler for unhandled promises
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Suppress console.log during tests unless explicitly needed
if (process.env.SUPPRESS_TEST_LOGS !== 'false') {
  global.console = {
    ...console,
    log: () => {},
    info: () => {},
    warn: () => {},
    // Keep error for debugging
    error: console.error
  };
}