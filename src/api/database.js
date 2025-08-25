/**
 * Database Connection and Utilities
 * Supabase client setup and database operation helpers
 */

import { createClient } from '@supabase/supabase-js';
import config, { getConfig, isDevelopment, isTest } from '../utils/config.js';

// Supabase clients
let supabaseClient = null;
let supabaseServiceClient = null;

/**
 * Initialize Supabase client for public operations
 * @returns {Object} Supabase client instance
 */
export const initializeSupabase = () => {
  if (!supabaseClient) {
    const supabaseUrl = getConfig('supabase.url');
    const supabaseAnonKey = getConfig('supabase.anonKey');
    
    if (!supabaseUrl || !supabaseAnonKey) {
      throw new Error('Supabase URL and Anon Key are required');
    }
    
    supabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
      db: {
        schema: 'public',
      },
      global: {
        headers: {
          'X-Client-Info': `${config.app.name}/${config.app.version}`,
        },
      },
    });
    
    if (isDevelopment()) {
      console.log('✅ Supabase client initialized');
    }
  }
  
  return supabaseClient;
};

/**
 * Initialize Supabase service client for admin operations
 * @returns {Object} Supabase service client instance
 */
export const initializeSupabaseService = () => {
  if (!supabaseServiceClient) {
    const supabaseUrl = getConfig('supabase.url');
    const serviceRoleKey = getConfig('supabase.serviceRoleKey');
    
    if (!supabaseUrl || !serviceRoleKey) {
      throw new Error('Supabase URL and Service Role Key are required for admin operations');
    }
    
    supabaseServiceClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
      db: {
        schema: 'public',
      },
      global: {
        headers: {
          'X-Client-Info': `${config.app.name}/${config.app.version}-service`,
        },
      },
    });
    
    if (isDevelopment()) {
      console.log('✅ Supabase service client initialized');
    }
  }
  
  return supabaseServiceClient;
};

/**
 * Get Supabase client instance
 * @returns {Object} Supabase client
 */
export const getSupabaseClient = () => {
  if (!supabaseClient) {
    return initializeSupabase();
  }
  return supabaseClient;
};

/**
 * Get Supabase service client instance
 * @returns {Object} Supabase service client
 */
export const getSupabaseServiceClient = () => {
  if (!supabaseServiceClient) {
    return initializeSupabaseService();
  }
  return supabaseServiceClient;
};

/**
 * Database connection health check
 * @returns {Promise<Object>} Health check result
 */
export const checkDatabaseHealth = async () => {
  try {
    const client = getSupabaseClient();
    const startTime = Date.now();
    
    // Simple query to test connection
    const { data, error } = await client
      .from('users')
      .select('count')
      .limit(1);
    
    const responseTime = Date.now() - startTime;
    
    if (error && error.code !== 'PGRST116') { // PGRST116 is "relation does not exist"
      throw error;
    }
    
    return {
      status: 'healthy',
      responseTime,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString(),
    };
  }
};

/**
 * Execute database query with error handling and retries
 * @param {Function} queryFn - Function that returns a Supabase query
 * @param {Object} options - Query options
 * @returns {Promise<Object>} Query result
 */
export const executeQuery = async (queryFn, options = {}) => {
  const {
    maxRetries = getConfig('database.maxRetries', 3),
    timeout = getConfig('database.queryTimeout', 10000),
    useServiceClient = false,
  } = options;
  
  const client = useServiceClient ? getSupabaseServiceClient() : getSupabaseClient();
  
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Create timeout promise
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Query timeout')), timeout);
      });
      
      // Execute query with timeout
      const queryPromise = queryFn(client);
      const result = await Promise.race([queryPromise, timeoutPromise]);
      
      if (result.error) {
        throw new Error(result.error.message || 'Database query failed');
      }
      
      return {
        success: true,
        data: result.data,
        count: result.count,
        status: result.status,
        statusText: result.statusText,
      };
    } catch (error) {
      lastError = error;
      
      if (isDevelopment()) {
        console.warn(`Query attempt ${attempt} failed:`, error.message);
      }
      
      // Don't retry on certain errors
      if (error.message.includes('JWT') || error.message.includes('unauthorized')) {
        break;
      }
      
      // Wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
      }
    }
  }
  
  return {
    success: false,
    error: lastError.message,
    attempts: maxRetries,
  };
};

/**
 * Database transaction wrapper
 * @param {Function} transactionFn - Function containing transaction operations
 * @param {Object} options - Transaction options
 * @returns {Promise<Object>} Transaction result
 */
export const executeTransaction = async (transactionFn, options = {}) => {
  const { useServiceClient = false } = options;
  const client = useServiceClient ? getSupabaseServiceClient() : getSupabaseClient();
  
  try {
    // Note: Supabase doesn't have explicit transaction support in the client
    // This is a wrapper for future enhancement or when using direct SQL
    const result = await transactionFn(client);
    
    return {
      success: true,
      data: result,
    };
  } catch (error) {
    if (isDevelopment()) {
      console.error('Transaction failed:', error);
    }
    
    return {
      success: false,
      error: error.message,
    };
  }
};

/**
 * Batch insert helper
 * @param {string} table - Table name
 * @param {Array} records - Array of records to insert
 * @param {Object} options - Insert options
 * @returns {Promise<Object>} Insert result
 */
export const batchInsert = async (table, records, options = {}) => {
  const {
    batchSize = 100,
    useServiceClient = false,
    onConflict = null,
  } = options;
  
  if (!Array.isArray(records) || records.length === 0) {
    return { success: true, data: [], inserted: 0 };
  }
  
  const client = useServiceClient ? getSupabaseServiceClient() : getSupabaseClient();
  const results = [];
  let totalInserted = 0;
  
  // Process in batches
  for (let i = 0; i < records.length; i += batchSize) {
    const batch = records.slice(i, i + batchSize);
    
    try {
      let query = client.from(table).insert(batch);
      
      if (onConflict) {
        query = query.onConflict(onConflict);
      }
      
      const { data, error } = await query.select();
      
      if (error) {
        throw error;
      }
      
      results.push(...(data || []));
      totalInserted += data?.length || 0;
    } catch (error) {
      if (isDevelopment()) {
        console.error(`Batch insert failed for batch ${Math.floor(i / batchSize) + 1}:`, error);
      }
      
      return {
        success: false,
        error: error.message,
        inserted: totalInserted,
        failedAt: Math.floor(i / batchSize) + 1,
      };
    }
  }
  
  return {
    success: true,
    data: results,
    inserted: totalInserted,
  };
};

/**
 * Initialize database connections
 * Should be called at application startup
 */
export const initializeDatabase = async () => {
  try {
    // Initialize clients
    initializeSupabase();
    
    // Only initialize service client if service role key is available
    if (getConfig('supabase.serviceRoleKey')) {
      initializeSupabaseService();
    }
    
    // Perform health check
    if (!isTest()) {
      const health = await checkDatabaseHealth();
      
      if (health.status === 'healthy') {
        console.log(`✅ Database connection healthy (${health.responseTime}ms)`);
      } else {
        console.warn('⚠️ Database health check failed:', health.error);
      }
    }
    
    return true;
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    
    if (!isDevelopment()) {
      throw error;
    }
    
    return false;
  }
};

// Export default client getter for convenience
export default getSupabaseClient;