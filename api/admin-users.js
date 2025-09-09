const { createClient } = require('@supabase/supabase-js');
const { verifyTokenFromRequest, requireRole } = require('./middleware/auth.js');
const { hashPassword } = require('./authentication.js');

// Initialize Supabase client with service role key for admin operations
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseServiceKey);

module.exports = async function handler(req, res) {
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

  // Verify authentication token
  const authResult = await verifyTokenFromRequest(req);
  if (!authResult.success) {
    return res.status(401).json({ 
      error: authResult.error || 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }

  const user = authResult.user;

  // Check if user has admin role
  if (user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED'
    });
  }

  try {
    switch (req.method) {
      case 'GET':
        return await handleGetUsers(req, res);
      case 'POST':
        return await handleCreateUser(req, res);
      case 'PUT':
        return await handleUpdateUser(req, res);
      case 'DELETE':
        return await handleDeleteUser(req, res);
      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Admin users API error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Get all users with pagination and filtering
 * Query params: page, limit, role, is_baptized, search
 */
async function handleGetUsers(req, res) {
  try {
    const { 
      page = 1, 
      limit = 20, 
      role, 
      is_baptized, 
      search 
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('users')
      .select(`
        id, email, name, phone, role, photo, 
        ebs_join_date, is_baptized, baptism_date,
        is_active, email_verified, last_login,
        created_at, updated_at
      `, { count: 'exact' })
      .is('deleted_at', null)
      .range(offset, offset + parseInt(limit) - 1)
      .order('created_at', { ascending: false });

    // Apply filters
    if (role) {
      query = query.eq('role', role);
    }
    
    if (is_baptized !== undefined) {
      query = query.eq('is_baptized', is_baptized === 'true');
    }
    
    if (search) {
      query = query.or(`name.ilike.%${search}%,email.ilike.%${search}%`);
    }

    const { data: users, error, count } = await query;

    if (error) {
      console.error('Error fetching users:', error);
      return res.status(500).json({ error: 'Failed to fetch users' });
    }

    return res.status(200).json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        totalPages: Math.ceil(count / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
}

/**
 * Create a new user (Admin only)
 */
async function handleCreateUser(req, res) {
  try {
    const {
      email,
      password,
      name,
      phone,
      role = 'user',
      photo,
      ebs_join_date,
      is_baptized = false,
      baptism_date
    } = req.body;

    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({ 
        error: 'Email, password, and name are required' 
      });
    }

    if (!['user', 'admin'].includes(role)) {
      return res.status(400).json({ 
        error: 'Invalid role. Must be user or admin' 
      });
    }

    // Validate baptism date if baptized
    if (is_baptized && !baptism_date) {
      return res.status(400).json({ 
        error: 'Baptism date is required when user is baptized' 
      });
    }

    // Hash password
    const password_hash = await hashPassword(password);

    // Create user
    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        email,
        password_hash,
        name,
        phone,
        role,
        photo,
        ebs_join_date,
        is_baptized,
        baptism_date: is_baptized ? baptism_date : null,
        is_active: true,
        email_verified: true // Admin created users are auto-verified
      })
      .select(`
        id, email, name, phone, role, photo,
        ebs_join_date, is_baptized, baptism_date,
        is_active, email_verified, created_at
      `)
      .single();

    if (error) {
      if (error.code === '23505') { // Unique constraint violation
        return res.status(409).json({ error: 'Email already exists' });
      }
      console.error('Error creating user:', error);
      return res.status(500).json({ error: 'Failed to create user' });
    }

    return res.status(201).json({ 
      message: 'User created successfully',
      user: newUser 
    });
  } catch (error) {
    console.error('Create user error:', error);
    return res.status(500).json({ error: 'Failed to create user' });
  }
}

/**
 * Update user information (Admin only)
 */
async function handleUpdateUser(req, res) {
  try {
    const { userId } = req.query;
    const {
      name,
      phone,
      role,
      photo,
      ebs_join_date,
      is_baptized,
      baptism_date,
      is_active
    } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Validate role if provided
    if (role && !['user', 'admin'].includes(role)) {
      return res.status(400).json({ 
        error: 'Invalid role. Must be user or admin' 
      });
    }

    // Validate baptism date if baptized
    if (is_baptized && !baptism_date) {
      return res.status(400).json({ 
        error: 'Baptism date is required when user is baptized' 
      });
    }

    // Build update object with only provided fields
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (name !== undefined) updateData.name = name;
    if (phone !== undefined) updateData.phone = phone;
    if (role !== undefined) updateData.role = role;
    if (photo !== undefined) updateData.photo = photo;
    if (ebs_join_date !== undefined) updateData.ebs_join_date = ebs_join_date;
    if (is_baptized !== undefined) {
      updateData.is_baptized = is_baptized;
      updateData.baptism_date = is_baptized ? baptism_date : null;
    }
    if (is_active !== undefined) updateData.is_active = is_active;

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', userId)
      .is('deleted_at', null)
      .select(`
        id, email, name, phone, role, photo,
        ebs_join_date, is_baptized, baptism_date,
        is_active, email_verified, updated_at
      `)
      .single();

    if (error) {
      console.error('Error updating user:', error);
      return res.status(500).json({ error: 'Failed to update user' });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ 
      message: 'User updated successfully',
      user: updatedUser 
    });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({ error: 'Failed to update user' });
  }
}

/**
 * Soft delete user (Admin only)
 */
async function handleDeleteUser(req, res) {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    // Soft delete by setting deleted_at timestamp
    const { data: deletedUser, error } = await supabase
      .from('users')
      .update({ 
        deleted_at: new Date().toISOString(),
        is_active: false,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId)
      .is('deleted_at', null)
      .select('id, email, name')
      .single();

    if (error) {
      console.error('Error deleting user:', error);
      return res.status(500).json({ error: 'Failed to delete user' });
    }

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ 
      message: 'User deleted successfully',
      user: deletedUser 
    });
  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({ error: 'Failed to delete user' });
  }
}