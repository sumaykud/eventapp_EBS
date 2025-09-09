const { createClient } = require('@supabase/supabase-js');
const { authenticateToken } = require('./middleware/auth');
const { requireAdmin } = require('./middleware/rbac');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
};

module.exports = async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).json({ message: 'OK' });
  }

  // Set CORS headers
  Object.keys(corsHeaders).forEach(key => {
    res.setHeader(key, corsHeaders[key]);
  });

  try {
    // Authenticate and check admin role
    await authenticateToken(req, res, async () => {
      await requireAdmin(req, res, async () => {
        const { method } = req;
        const { id } = req.query;

        switch (method) {
          case 'GET':
            if (id) {
              await getBlogPost(req, res, id);
            } else {
              await getAllBlogPosts(req, res);
            }
            break;

          case 'POST':
            await createBlogPost(req, res);
            break;

          case 'PUT':
            if (!id) {
              return res.status(400).json({ error: 'Post ID is required for updates' });
            }
            await updateBlogPost(req, res, id);
            break;

          case 'DELETE':
            if (!id) {
              return res.status(400).json({ error: 'Post ID is required for deletion' });
            }
            await deleteBlogPost(req, res, id);
            break;

          default:
            res.status(405).json({ error: 'Method not allowed' });
        }
      });
    });
  } catch (error) {
    console.error('Admin blog API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Get all blog posts (including drafts) with filtering and pagination
async function getAllBlogPosts(req, res) {
  try {
    const {
      page = 1,
      limit = 10,
      status,
      category,
      author,
      search,
      sortBy = 'created_at',
      sortOrder = 'desc'
    } = req.query;

    const offset = (parseInt(page) - 1) * parseInt(limit);

    let query = supabase
      .from('blog_posts')
      .select(`
        *,
        author:users!author_id(id, email, full_name),
        category:blog_categories(id, name, slug)
      `);

    // Apply filters
    if (status) {
      query = query.eq('status', status);
    }

    if (category) {
      query = query.eq('category_id', category);
    }

    if (author) {
      query = query.eq('author_id', author);
    }

    if (search) {
      query = query.or(`title.ilike.%${search}%,content.ilike.%${search}%,excerpt.ilike.%${search}%`);
    }

    // Apply sorting
    query = query.order(sortBy, { ascending: sortOrder === 'asc' });

    // Apply pagination
    query = query.range(offset, offset + parseInt(limit) - 1);

    const { data: posts, error, count } = await query;

    if (error) {
      console.error('Error fetching blog posts:', error);
      return res.status(500).json({ error: 'Failed to fetch blog posts' });
    }

    // Get total count for pagination
    const { count: totalCount } = await supabase
      .from('blog_posts')
      .select('*', { count: 'exact', head: true });

    res.json({
      posts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: totalCount,
        totalPages: Math.ceil(totalCount / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Error in getAllBlogPosts:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Get single blog post by ID
async function getBlogPost(req, res, id) {
  try {
    const { data: post, error } = await supabase
      .from('blog_posts')
      .select(`
        *,
        author:users!author_id(id, email, full_name),
        category:blog_categories(id, name, slug)
      `)
      .eq('id', id)
      .single();

    if (error) {
      console.error('Error fetching blog post:', error);
      return res.status(404).json({ error: 'Blog post not found' });
    }

    res.json({ post });
  } catch (error) {
    console.error('Error in getBlogPost:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Create new blog post
async function createBlogPost(req, res) {
  try {
    const {
      title,
      content,
      excerpt,
      status = 'draft',
      category_id,
      meta_description,
      slug
    } = req.body;

    // Validate required fields
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    // Generate slug if not provided
    let finalSlug = slug;
    if (!finalSlug) {
      finalSlug = title.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-');
    }

    // Check if slug is unique
    const { data: existingPost } = await supabase
      .from('blog_posts')
      .select('id')
      .eq('slug', finalSlug)
      .single();

    if (existingPost) {
      finalSlug = `${finalSlug}-${Date.now()}`;
    }

    const postData = {
      title,
      content,
      excerpt: excerpt || content.substring(0, 200) + '...',
      status,
      category_id,
      meta_description,
      slug: finalSlug,
      author_id: req.user.id,
      published_at: status === 'published' ? new Date().toISOString() : null
    };

    const { data: post, error } = await supabase
      .from('blog_posts')
      .insert([postData])
      .select(`
        *,
        author:users!author_id(id, email, full_name),
        category:blog_categories(id, name, slug)
      `)
      .single();

    if (error) {
      console.error('Error creating blog post:', error);
      return res.status(500).json({ error: 'Failed to create blog post' });
    }

    res.status(201).json({ post, message: 'Blog post created successfully' });
  } catch (error) {
    console.error('Error in createBlogPost:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Update blog post
async function updateBlogPost(req, res, id) {
  try {
    const {
      title,
      content,
      excerpt,
      status,
      category_id,
      meta_description,
      slug
    } = req.body;

    // Check if post exists
    const { data: existingPost, error: fetchError } = await supabase
      .from('blog_posts')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !existingPost) {
      return res.status(404).json({ error: 'Blog post not found' });
    }

    const updateData = {};
    
    if (title !== undefined) updateData.title = title;
    if (content !== undefined) updateData.content = content;
    if (excerpt !== undefined) updateData.excerpt = excerpt;
    if (status !== undefined) {
      updateData.status = status;
      // Set published_at when publishing
      if (status === 'published' && existingPost.status !== 'published') {
        updateData.published_at = new Date().toISOString();
      }
    }
    if (category_id !== undefined) updateData.category_id = category_id;
    if (meta_description !== undefined) updateData.meta_description = meta_description;
    if (slug !== undefined) {
      // Check if new slug is unique
      const { data: slugCheck } = await supabase
        .from('blog_posts')
        .select('id')
        .eq('slug', slug)
        .neq('id', id)
        .single();

      if (slugCheck) {
        return res.status(400).json({ error: 'Slug already exists' });
      }
      updateData.slug = slug;
    }

    const { data: post, error } = await supabase
      .from('blog_posts')
      .update(updateData)
      .eq('id', id)
      .select(`
        *,
        author:users!author_id(id, email, full_name),
        category:blog_categories(id, name, slug)
      `)
      .single();

    if (error) {
      console.error('Error updating blog post:', error);
      return res.status(500).json({ error: 'Failed to update blog post' });
    }

    res.json({ post, message: 'Blog post updated successfully' });
  } catch (error) {
    console.error('Error in updateBlogPost:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Delete blog post
async function deleteBlogPost(req, res, id) {
  try {
    const { error } = await supabase
      .from('blog_posts')
      .delete()
      .eq('id', id);

    if (error) {
      console.error('Error deleting blog post:', error);
      return res.status(500).json({ error: 'Failed to delete blog post' });
    }

    res.json({ message: 'Blog post deleted successfully' });
  } catch (error) {
    console.error('Error in deleteBlogPost:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}