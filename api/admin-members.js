import { createClient } from '@supabase/supabase-js';
import { authenticateToken, requireAdmin } from './middleware/auth.js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
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

  // Authenticate and require admin role
  await authenticateToken(req, res, async () => {
    await requireAdmin(req, res, async () => {
      try {
        if (req.method === 'GET') {
          await handleGetMembers(req, res);
        } else if (req.method === 'PATCH') {
          await handleUpdateMemberStatus(req, res);
        } else {
          return res.status(405).json({ error: 'Method not allowed' });
        }
      } catch (error) {
        console.error('Admin members API error:', error);
        return res.status(500).json({ 
          error: 'Internal server error',
          message: 'Something went wrong while processing your request'
        });
      }
    });
  });
}

// Get members with filtering and pagination
async function handleGetMembers(req, res) {
  const { 
    page = 1, 
    limit = 20, 
    status, 
    search, 
    sortBy = 'created_at', 
    sortOrder = 'desc' 
  } = req.query;

  const offset = (parseInt(page) - 1) * parseInt(limit);
  
  try {
    let query = supabase
      .from('registrations')
      .select(`
        id,
        name,
        age,
        email,
        phone,
        reason,
        status,
        created_at,
        updated_at
      `);

    // Apply filters
    if (status && status !== 'all') {
      query = query.eq('status', status);
    }

    if (search) {
      query = query.or(`name.ilike.%${search}%,email.ilike.%${search}%`);
    }

    // Apply sorting
    const validSortFields = ['name', 'email', 'age', 'status', 'created_at', 'updated_at'];
    const validSortOrders = ['asc', 'desc'];
    
    if (validSortFields.includes(sortBy) && validSortOrders.includes(sortOrder)) {
      query = query.order(sortBy, { ascending: sortOrder === 'asc' });
    } else {
      query = query.order('created_at', { ascending: false });
    }

    // Apply pagination
    query = query.range(offset, offset + parseInt(limit) - 1);

    const { data: members, error, count } = await query;

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to fetch members' });
    }

    // Get total count for pagination
    const { count: totalCount, error: countError } = await supabase
      .from('registrations')
      .select('*', { count: 'exact', head: true })
      .eq(status && status !== 'all' ? 'status' : 'id', status && status !== 'all' ? status : members[0]?.id || '');

    const totalPages = Math.ceil((totalCount || members.length) / parseInt(limit));

    return res.status(200).json({
      success: true,
      data: members,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalCount: totalCount || members.length,
        limit: parseInt(limit),
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      },
      filters: {
        status: status || 'all',
        search: search || '',
        sortBy,
        sortOrder
      }
    });

  } catch (error) {
    console.error('Get members error:', error);
    return res.status(500).json({ error: 'Failed to fetch members' });
  }
}

// Update member status (approve/reject)
async function handleUpdateMemberStatus(req, res) {
  const { id, status, notes } = req.body;

  if (!id || !status) {
    return res.status(400).json({ 
      error: 'Missing required fields: id and status' 
    });
  }

  const validStatuses = ['pending', 'approved', 'rejected', 'cancelled'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ 
      error: 'Invalid status. Must be one of: ' + validStatuses.join(', ') 
    });
  }

  try {
    const updateData = {
      status,
      updated_at: new Date().toISOString()
    };

    if (notes) {
      updateData.admin_notes = notes;
    }

    const { data, error } = await supabase
      .from('registrations')
      .update(updateData)
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to update member status' });
    }

    if (!data) {
      return res.status(404).json({ error: 'Member not found' });
    }

    return res.status(200).json({
      success: true,
      message: `Member status updated to ${status}`,
      data: {
        id: data.id,
        name: data.name,
        email: data.email,
        status: data.status,
        updated_at: data.updated_at
      }
    });

  } catch (error) {
    console.error('Update member status error:', error);
    return res.status(500).json({ error: 'Failed to update member status' });
  }
}