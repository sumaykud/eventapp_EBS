import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    await handleGetBlogPosts(req, res);
  } catch (error) {
    console.error('Blog API error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: 'Something went wrong while processing your request'
    });
  }
}

// Get blog posts (public access for published posts)
async function handleGetBlogPosts(req, res) {
  const { 
    page = 1, 
    limit = 10, 
    category, 
    search, 
    postId 
  } = req.query;

  try {
    // If requesting a specific post
    if (postId) {
      const { data: post, error } = await supabase
        .from('blog_posts')
        .select(`
          id,
          title,
          content,
          excerpt,
          category,
          tags,
          featured_image_url,
          is_published,
          created_at,
          updated_at
        `)
        .eq('id', postId)
        .eq('is_published', true)
        .single();

      if (error || !post) {
        return res.status(404).json({ error: 'Blog post not found' });
      }

      return res.status(200).json({
        success: true,
        data: post
      });
    }

    // Get list of posts with pagination
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('blog_posts')
      .select(`
        id,
        title,
        excerpt,
        category,
        tags,
        featured_image_url,
        is_published,
        created_at,
        updated_at
      `)
      .eq('is_published', true)
      .order('created_at', { ascending: false });

    // Apply filters
    if (category && category !== 'all') {
      query = query.eq('category', category);
    }

    if (search) {
      query = query.or(`title.ilike.%${search}%,excerpt.ilike.%${search}%,content.ilike.%${search}%`);
    }

    // Apply pagination
    query = query.range(offset, offset + parseInt(limit) - 1);

    const { data: posts, error, count } = await query;

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to fetch blog posts' });
    }

    // Get total count for pagination
    let countQuery = supabase
      .from('blog_posts')
      .select('*', { count: 'exact', head: true })
      .eq('is_published', true);

    if (category && category !== 'all') {
      countQuery = countQuery.eq('category', category);
    }

    if (search) {
      countQuery = countQuery.or(`title.ilike.%${search}%,excerpt.ilike.%${search}%,content.ilike.%${search}%`);
    }

    const { count: totalCount, error: countError } = await countQuery;

    const totalPages = Math.ceil((totalCount || posts.length) / parseInt(limit));

    // Get available categories for filtering
    const { data: categories } = await supabase
      .from('blog_posts')
      .select('category')
      .eq('is_published', true)
      .not('category', 'is', null);

    const uniqueCategories = [...new Set(categories?.map(c => c.category) || [])];

    return res.status(200).json({
      success: true,
      data: posts,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalCount: totalCount || posts.length,
        limit: parseInt(limit),
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      },
      filters: {
        category: category || 'all',
        search: search || '',
        availableCategories: uniqueCategories
      }
    });

  } catch (error) {
    console.error('Get blog posts error:', error);
    return res.status(500).json({ error: 'Failed to fetch blog posts' });
  }
}