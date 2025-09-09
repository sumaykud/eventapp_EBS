const { createClient } = require('@supabase/supabase-js');
const { verifyTokenFromRequest, requireRole } = require('./middleware/auth.js');
const { sanitizeInput, validateEmail, validatePhone } = require('../utils/security.js');

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
        return await handleGetBaptismData(req, res, user);
      case 'POST':
        return await handleUpdateBaptismStatus(req, res, user);
      case 'PUT':
        return await handleUpdateEBSMembership(req, res, user);
      default:
        return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Baptism management API error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Get baptism and EBS data
 * - Regular users can only see their own data
 * - Admins can see all users' data with filtering
 */
async function handleGetBaptismData(req, res, user) {
  try {
    const { userId, filter, page = 1, limit = 20 } = req.query;
    const isAdmin = user.role === 'admin';

    let query = supabase
      .from('users')
      .select(`
        id, name, email, phone,
        ebs_join_date, is_baptized, baptism_date,
        created_at
      `)
      .is('deleted_at', null);

    // If not admin, only show own data
    if (!isAdmin) {
      query = query.eq('id', user.id);
    } else {
      // Admin can filter and paginate
      if (userId) {
        query = query.eq('id', userId);
      }

      // Apply filters for admin
      if (filter === 'baptized') {
        query = query.eq('is_baptized', true);
      } else if (filter === 'unbaptized') {
        query = query.eq('is_baptized', false);
      } else if (filter === 'ebs_members') {
        query = query.not('ebs_join_date', 'is', null);
      }

      // Pagination for admin
      const offset = (parseInt(page) - 1) * parseInt(limit);
      query = query.range(offset, offset + parseInt(limit) - 1);
    }

    query = query.order('created_at', { ascending: false });

    const { data: baptismData, error, count } = await query;

    if (error) {
      console.error('Error fetching baptism data:', error);
      return res.status(500).json({ error: 'Failed to fetch baptism data' });
    }

    const response = { data: baptismData };

    // Add pagination info for admin
    if (isAdmin && !userId) {
      response.pagination = {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        totalPages: Math.ceil(count / parseInt(limit))
      };
    }

    return res.status(200).json(response);
  } catch (error) {
    console.error('Get baptism data error:', error);
    return res.status(500).json({ error: 'Failed to fetch baptism data' });
  }
}

/**
 * Update baptism status
 * - Regular users can update their own baptism status
 * - Admins can update any user's baptism status
 */
async function handleUpdateBaptismStatus(req, res, user) {
  try {
    const { userId, is_baptized, baptism_date } = req.body;
    const isAdmin = user.role === 'admin';
    const targetUserId = isAdmin && userId ? userId : user.id;

    // Validation
    if (is_baptized === undefined) {
      return res.status(400).json({ 
        error: 'Baptism status (is_baptized) is required' 
      });
    }

    if (is_baptized && !baptism_date) {
      return res.status(400).json({ 
        error: 'Baptism date is required when marking as baptized' 
      });
    }

    // Validate date format
    if (baptism_date && isNaN(Date.parse(baptism_date))) {
      return res.status(400).json({ 
        error: 'Invalid baptism date format' 
      });
    }

    // Check if user exists (for admin operations)
    if (isAdmin && userId) {
      const { data: targetUser, error: userError } = await supabase
        .from('users')
        .select('id, name')
        .eq('id', userId)
        .is('deleted_at', null)
        .single();

      if (userError || !targetUser) {
        return res.status(404).json({ error: 'Target user not found' });
      }
    }

    // Update baptism status
    const updateData = {
      is_baptized,
      baptism_date: is_baptized ? baptism_date : null,
      updated_at: new Date().toISOString()
    };

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', targetUserId)
      .is('deleted_at', null)
      .select(`
        id, name, email,
        is_baptized, baptism_date,
        updated_at
      `)
      .single();

    if (error) {
      console.error('Error updating baptism status:', error);
      return res.status(500).json({ error: 'Failed to update baptism status' });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ 
      message: 'Baptism status updated successfully',
      user: updatedUser 
    });
  } catch (error) {
    console.error('Update baptism status error:', error);
    return res.status(500).json({ error: 'Failed to update baptism status' });
  }
}

/**
 * Update EBS membership information
 * - Regular users can update their own EBS join date
 * - Admins can update any user's EBS membership
 */
async function handleUpdateEBSMembership(req, res, user) {
  try {
    const { userId, ebs_join_date } = req.body;
    const isAdmin = user.role === 'admin';
    const targetUserId = isAdmin && userId ? userId : user.id;

    // Validate date format if provided
    if (ebs_join_date && isNaN(Date.parse(ebs_join_date))) {
      return res.status(400).json({ 
        error: 'Invalid EBS join date format' 
      });
    }

    // Check if user exists (for admin operations)
    if (isAdmin && userId) {
      const { data: targetUser, error: userError } = await supabase
        .from('users')
        .select('id, name')
        .eq('id', userId)
        .is('deleted_at', null)
        .single();

      if (userError || !targetUser) {
        return res.status(404).json({ error: 'Target user not found' });
      }
    }

    // Update EBS membership
    const updateData = {
      ebs_join_date,
      updated_at: new Date().toISOString()
    };

    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', targetUserId)
      .is('deleted_at', null)
      .select(`
        id, name, email,
        ebs_join_date,
        updated_at
      `)
      .single();

    if (error) {
      console.error('Error updating EBS membership:', error);
      return res.status(500).json({ error: 'Failed to update EBS membership' });
    }

    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ 
      message: 'EBS membership updated successfully',
      user: updatedUser 
    });
  } catch (error) {
    console.error('Update EBS membership error:', error);
    return res.status(500).json({ error: 'Failed to update EBS membership' });
  }
}

/**
 * Get baptism statistics and reports (Admin only)
 */
async function getBaptismReports(req, res) {
  try {
    // Verify admin access
    const authResult = await verifyTokenFromRequest(req);
    if (!authResult.success || authResult.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { year, month } = req.query;

    // Base query for all active users
    let query = supabase
      .from('users')
      .select(`
        id, name, email,
        ebs_join_date, is_baptized, baptism_date,
        created_at
      `)
      .is('deleted_at', null);

    // Filter by year/month if provided
    if (year) {
      const startDate = `${year}-01-01`;
      const endDate = `${year}-12-31`;
      
      if (month) {
        const monthStart = `${year}-${month.padStart(2, '0')}-01`;
        const nextMonth = parseInt(month) === 12 ? 1 : parseInt(month) + 1;
        const nextYear = parseInt(month) === 12 ? parseInt(year) + 1 : parseInt(year);
        const monthEnd = `${nextYear}-${nextMonth.toString().padStart(2, '0')}-01`;
        
        query = query.gte('baptism_date', monthStart).lt('baptism_date', monthEnd);
      } else {
        query = query.gte('baptism_date', startDate).lte('baptism_date', endDate);
      }
    }

    const { data: users, error } = await query;

    if (error) {
      console.error('Error fetching baptism reports:', error);
      return res.status(500).json({ error: 'Failed to fetch reports' });
    }

    // Calculate statistics
    const totalUsers = users.length;
    const baptizedUsers = users.filter(user => user.is_baptized).length;
    const unbaptizedUsers = totalUsers - baptizedUsers;
    const ebsMembers = users.filter(user => user.ebs_join_date).length;
    
    // Group baptisms by month (if year filter is applied)
    const baptismsByMonth = {};
    if (year) {
      users.filter(user => user.baptism_date).forEach(user => {
        const month = new Date(user.baptism_date).getMonth() + 1;
        baptismsByMonth[month] = (baptismsByMonth[month] || 0) + 1;
      });
    }

    return res.status(200).json({
      statistics: {
        totalUsers,
        baptizedUsers,
        unbaptizedUsers,
        ebsMembers,
        baptismRate: totalUsers > 0 ? (baptizedUsers / totalUsers * 100).toFixed(2) : 0
      },
      baptismsByMonth: year ? baptismsByMonth : null,
      users: users.map(user => ({
        id: user.id,
        name: user.name,
        email: user.email,
        ebs_join_date: user.ebs_join_date,
        is_baptized: user.is_baptized,
        baptism_date: user.baptism_date,
        created_at: user.created_at
      }))
    });
  } catch (error) {
    console.error('Get baptism reports error:', error);
    return res.status(500).json({ error: 'Failed to fetch reports' });
  }
}