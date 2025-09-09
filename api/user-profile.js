const { createClient } = require('@supabase/supabase-js');
const { verifyTokenFromRequest } = require('./middleware/auth.js');
const { hashPassword, comparePassword } = require('./authentication.js');

// Initialize Supabase client
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

  try {
    switch (req.method) {
      case 'GET':
        return await handleGetProfile(req, res, user);
      case 'PUT':
        return await handleUpdateProfile(req, res, user);
      case 'PATCH':
        return await handleUpdatePassword(req, res, user);
      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('User profile API error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Get user's own profile
 */
async function handleGetProfile(req, res, user) {
  try {
    const { data: userProfile, error } = await supabase
      .from('users')
      .select(`
        id, email, name, phone, role, photo,
        ebs_join_date, is_baptized, baptism_date,
        is_active, email_verified, last_login,
        created_at, updated_at
      `)
      .eq('id', user.id)
      .is('deleted_at', null)
      .single();

    if (error) {
      console.error('Error fetching user profile:', error);
      return res.status(500).json({ error: 'Failed to fetch profile' });
    }

    if (!userProfile) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    return res.status(200).json({ profile: userProfile });
  } catch (error) {
    console.error('Get profile error:', error);
    return res.status(500).json({ error: 'Failed to fetch profile' });
  }
}

/**
 * Update user's own profile
 * Users can update: name, phone, photo, ebs_join_date, is_baptized, baptism_date
 * Users cannot update: email, role, is_active, email_verified
 */
async function handleUpdateProfile(req, res, user) {
  try {
    const {
      name,
      phone,
      photo,
      ebs_join_date,
      is_baptized,
      baptism_date
    } = req.body;

    // Validate baptism date if baptized
    if (is_baptized && !baptism_date) {
      return res.status(400).json({ 
        error: 'Baptism date is required when marking as baptized' 
      });
    }

    // Build update object with only allowed fields
    const updateData = {
      updated_at: new Date().toISOString()
    };

    if (name !== undefined) updateData.name = name;
    if (phone !== undefined) updateData.phone = phone;
    if (photo !== undefined) updateData.photo = photo;
    if (ebs_join_date !== undefined) updateData.ebs_join_date = ebs_join_date;
    if (is_baptized !== undefined) {
      updateData.is_baptized = is_baptized;
      updateData.baptism_date = is_baptized ? baptism_date : null;
    }

    const { data: updatedProfile, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', user.id)
      .is('deleted_at', null)
      .select(`
        id, email, name, phone, role, photo,
        ebs_join_date, is_baptized, baptism_date,
        is_active, email_verified, updated_at
      `)
      .single();

    if (error) {
      console.error('Error updating profile:', error);
      return res.status(500).json({ error: 'Failed to update profile' });
    }

    if (!updatedProfile) {
      return res.status(404).json({ error: 'Profile not found' });
    }

    return res.status(200).json({ 
      message: 'Profile updated successfully',
      profile: updatedProfile 
    });
  } catch (error) {
    console.error('Update profile error:', error);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
}

/**
 * Update user's password
 */
async function handleUpdatePassword(req, res, user) {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        error: 'Current password and new password are required' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        error: 'New password must be at least 8 characters long' 
      });
    }

    // Get current user data to verify password
    const { data: userData, error: fetchError } = await supabase
      .from('users')
      .select('password_hash')
      .eq('id', user.id)
      .is('deleted_at', null)
      .single();

    if (fetchError || !userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isCurrentPasswordValid = await comparePassword(
      currentPassword, 
      userData.password_hash
    );

    if (!isCurrentPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newPasswordHash = await hashPassword(newPassword);

    // Update password
    const { error: updateError } = await supabase
      .from('users')
      .update({ 
        password_hash: newPasswordHash,
        updated_at: new Date().toISOString()
      })
      .eq('id', user.id)
      .is('deleted_at', null);

    if (updateError) {
      console.error('Error updating password:', updateError);
      return res.status(500).json({ error: 'Failed to update password' });
    }

    return res.status(200).json({ 
      message: 'Password updated successfully' 
    });
  } catch (error) {
    console.error('Update password error:', error);
    return res.status(500).json({ error: 'Failed to update password' });
  }
}

/**
 * Get baptism statistics (for admin dashboard)
 */
module.exports.getBaptismStats = async function getBaptismStats(req, res) {
  try {
    // Verify admin access
    const authResult = await verifyTokenFromRequest(req);
    if (!authResult.success || authResult.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { data: stats, error } = await supabase
      .from('users')
      .select('is_baptized, ebs_join_date')
      .is('deleted_at', null);

    if (error) {
      console.error('Error fetching baptism stats:', error);
      return res.status(500).json({ error: 'Failed to fetch statistics' });
    }

    const totalUsers = stats.length;
    const baptizedUsers = stats.filter(user => user.is_baptized).length;
    const ebsMembers = stats.filter(user => user.ebs_join_date).length;
    const unbaptizedUsers = totalUsers - baptizedUsers;

    return res.status(200).json({
      statistics: {
        totalUsers,
        baptizedUsers,
        unbaptizedUsers,
        ebsMembers,
        baptismRate: totalUsers > 0 ? (baptizedUsers / totalUsers * 100).toFixed(2) : 0
      }
    });
  } catch (error) {
    console.error('Get baptism stats error:', error);
    return res.status(500).json({ error: 'Failed to fetch statistics' });
  }
}