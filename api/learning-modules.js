import { createClient } from '@supabase/supabase-js';
import { authenticateToken } from './middleware/auth.js';

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

  try {
    if (req.method === 'GET') {
      await handleGetModules(req, res);
    } else if (req.method === 'POST') {
      // Require authentication for progress tracking
      await authenticateToken(req, res, async () => {
        await handleUpdateProgress(req, res);
      });
    } else {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('Learning modules API error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: 'Something went wrong while processing your request'
    });
  }
}

// Get learning modules (public access for published modules)
async function handleGetModules(req, res) {
  const { category, difficulty, search } = req.query;
  
  try {
    let query = supabase
      .from('learning_modules')
      .select(`
        id,
        title,
        description,
        content,
        category,
        difficulty,
        duration_minutes,
        is_published,
        created_at,
        updated_at
      `)
      .eq('is_published', true)
      .order('created_at', { ascending: false });

    // Apply filters
    if (category) {
      query = query.eq('category', category);
    }

    if (difficulty) {
      query = query.eq('difficulty', difficulty);
    }

    if (search) {
      query = query.or(`title.ilike.%${search}%,description.ilike.%${search}%`);
    }

    const { data: modules, error } = await query;

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to fetch learning modules' });
    }

    // Get user progress if authenticated
    let userProgress = {};
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        // Simple token validation - in production, use proper JWT verification
        const token = authHeader.substring(7);
        const { data: user } = await supabase.auth.getUser(token);
        
        if (user?.user) {
          const { data: progress } = await supabase
            .from('user_module_progress')
            .select('module_id, progress_percentage, completed_at')
            .eq('user_id', user.user.id);
          
          if (progress) {
            userProgress = progress.reduce((acc, p) => {
              acc[p.module_id] = {
                progress: p.progress_percentage,
                completed: p.completed_at !== null
              };
              return acc;
            }, {});
          }
        }
      } catch (authError) {
        // Continue without user progress if auth fails
        console.log('Auth check failed, continuing without user progress');
      }
    }

    // Add progress information to modules
    const modulesWithProgress = modules.map(module => ({
      ...module,
      userProgress: userProgress[module.id] || { progress: 0, completed: false }
    }));

    return res.status(200).json({
      success: true,
      data: modulesWithProgress,
      filters: {
        category: category || 'all',
        difficulty: difficulty || 'all',
        search: search || ''
      }
    });

  } catch (error) {
    console.error('Get modules error:', error);
    return res.status(500).json({ error: 'Failed to fetch learning modules' });
  }
}

// Update user progress (requires authentication)
async function handleUpdateProgress(req, res) {
  const { moduleId, progressPercentage } = req.body;
  const userId = req.user.id;

  if (!moduleId || progressPercentage === undefined) {
    return res.status(400).json({ 
      error: 'Missing required fields: moduleId and progressPercentage' 
    });
  }

  if (progressPercentage < 0 || progressPercentage > 100) {
    return res.status(400).json({ 
      error: 'Progress percentage must be between 0 and 100' 
    });
  }

  try {
    // Check if module exists and is published
    const { data: module, error: moduleError } = await supabase
      .from('learning_modules')
      .select('id, title')
      .eq('id', moduleId)
      .eq('is_published', true)
      .single();

    if (moduleError || !module) {
      return res.status(404).json({ error: 'Learning module not found' });
    }

    // Upsert progress record
    const progressData = {
      user_id: userId,
      module_id: moduleId,
      progress_percentage: progressPercentage,
      completed_at: progressPercentage >= 100 ? new Date().toISOString() : null,
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('user_module_progress')
      .upsert(progressData, { 
        onConflict: 'user_id,module_id',
        returning: 'minimal'
      });

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to update progress' });
    }

    return res.status(200).json({
      success: true,
      message: progressPercentage >= 100 
        ? `Congratulations! You've completed "${module.title}"` 
        : 'Progress updated successfully',
      data: {
        moduleId,
        progress: progressPercentage,
        completed: progressPercentage >= 100
      }
    });

  } catch (error) {
    console.error('Update progress error:', error);
    return res.status(500).json({ error: 'Failed to update progress' });
  }
}