import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Test environment
    environment: 'node',
    
    // Setup files
    setupFiles: ['./tests/setup.js'],
    
    // Global test configuration
    globals: true,
    
    // Test file patterns
    include: [
      'tests/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
      'api/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'
    ],
    
    // Exclude patterns
    exclude: [
      'node_modules',
      'dist',
      '.next',
      'coverage'
    ],
    
    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'tests/',
        'coverage/',
        '**/*.config.js',
        '**/*.config.ts',
        '**/types.ts',
        '**/constants.js'
      ],
      thresholds: {
        global: {
          branches: 70,
          functions: 70,
          lines: 70,
          statements: 70
        }
      }
    },
    
    // Test timeout
    testTimeout: 10000,
    
    // Hook timeout
    hookTimeout: 10000,
    
    // Reporter configuration
    reporter: ['verbose', 'json'],
    
    // Retry failed tests
    retry: 1,
    
    // Run tests in sequence for database operations
    sequence: {
      concurrent: false
    },
    
    // Mock configuration
    deps: {
      inline: ['@supabase/supabase-js']
    }
  },
  
  // Resolve configuration
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './'),
      '@api': path.resolve(__dirname, './api'),
      '@tests': path.resolve(__dirname, './tests')
    }
  },
  
  // Define configuration
  define: {
    'process.env.NODE_ENV': '"test"'
  }
});