// Debug script to test authenticateToken function
import { config } from 'dotenv';
config({ path: '.env.test' });

console.log('🔍 Environment variables:');
console.log('  - JWT_SECRET:', process.env.JWT_SECRET ? 'SET' : 'NOT SET');
console.log('  - SUPABASE_URL:', process.env.SUPABASE_URL ? 'SET' : 'NOT SET');
console.log('  - SUPABASE_SERVICE_ROLE_KEY:', process.env.SUPABASE_SERVICE_ROLE_KEY ? 'SET' : 'NOT SET');

async function testAuth() {
  try {
    console.log('🔍 Starting debug test...');
    
    // Import the auth module
    console.log('🔍 Attempting to import auth module...');
    const auth = await import('./api/middleware/auth.js');
    console.log('🔍 Auth module imported successfully!');
    console.log('🔍 Exported functions:', Object.keys(auth));
    console.log('🔍 authenticateToken type:', typeof auth.authenticateToken);
    
    if (!auth.authenticateToken) {
      console.error('❌ authenticateToken is not exported!');
      return;
    }
    
    console.log('✅ authenticateToken function is available');
    
  } catch (error) {
    console.error('❌ Error in debug test:', error.message);
    console.error('Full error:', error);
  }
}

testAuth();