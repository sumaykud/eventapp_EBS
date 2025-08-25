import { createClient } from '@supabase/supabase-js';
import { verifyTokenFromRequest, requireRole } from './middleware/auth.js';

const supabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.VITE_SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
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

  try {
    switch (req.method) {
      case 'GET':
        return await handleGetUserProfile(req, res, user);
      case 'PUT':
        return await handleUpdateUserProfile(req, res, user);
      case 'DELETE':
        return await handleDeleteUserAccount(req, res, user);
      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Protected route error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

// GET: Get user profile (any authenticated user)
async function handleGetUserProfile(req, res, user) {
  try {
    const { data: userProfile, error } = await supabase
      .from('users')
      .select('id, email, name, phone, role, is_active, created_at, last_login')
      .eq('id', user.id)
      .single();

    if (error) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    return res.status(200).json({
      message: 'User profile retrieved successfully',
      user: {
        id: userProfile.id,
        email: userProfile.email,
        name: userProfile.name,
        phone: userProfile.phone,
        role: userProfile.role,
        isActive: userProfile.is_active,
        createdAt: userProfile.created_at,
        lastLogin: userProfile.last_login
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({ error: 'Failed to retrieve user profile' });
  }
}

// PUT: Update user profile (user can update their own profile)
async function handleUpdateUserProfile(req, res, user) {
  const { name, phone } = req.body;
  const { userId } = req.query;

  // Users can only update their own profile unless they're admin
  if (userId && userId !== user.id && user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'You can only update your own profile',
      code: 'INSUFFICIENT_PERMISSIONS'
    });
  }

  const targetUserId = userId || user.id;

  try {
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (name) updateData.name = name;
    if (phone) updateData.phone = phone;

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', targetUserId)
      .select('id, email, name, phone, role, updated_at')
      .single();

    if (error) {
      return res.status(500).json({ error: 'Failed to update user profile' });
    }

    return res.status(200).json({
      message: 'User profile updated successfully',
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        name: updatedUser.name,
        phone: updatedUser.phone,
        role: updatedUser.role,
        updatedAt: updatedUser.updated_at
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    return res.status(500).json({ error: 'Failed to update user profile' });
  }
}

// DELETE: Delete user account (admin only or user's own account)
async function handleDeleteUserAccount(req, res, user) {
  const { userId } = req.query;

  // Users can only delete their own account unless they're admin
  if (userId && userId !== user.id && user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Insufficient permissions to delete this account',
      code: 'INSUFFICIENT_PERMISSIONS'
    });
  }

  const targetUserId = userId || user.id;

  try {
    // Soft delete: mark as inactive instead of hard delete
    const { data: deletedUser, error } = await supabase
      .from('users')
      .update({ 
        is_active: false,
        deleted_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      })
      .eq('id', targetUserId)
      .select('id, email, name')
      .single();

    if (error) {
      return res.status(500).json({ error: 'Failed to delete user account' });
    }

    return res.status(200).json({
      message: 'User account deleted successfully',
      deletedUser: {
        id: deletedUser.id,
        email: deletedUser.email,
        name: deletedUser.name
      }
    });
  } catch (error) {
    console.error('Delete account error:', error);
    return res.status(500).json({ error: 'Failed to delete user account' });
  }
}

// Example of admin-only route
export async function adminOnlyHandler(req, res) {
  // Verify authentication
  const authResult = await verifyTokenFromRequest(req);
  if (!authResult.success) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Check admin role
  if (authResult.user.role !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required',
      code: 'ADMIN_REQUIRED'
    });
  }

  // Admin-only logic here
  return res.status(200).json({ 
    message: 'Admin access granted',
    user: authResult.user
  });
}