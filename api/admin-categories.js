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
              await getCategory(req, res, id);
            } else {
              await getAllCategories(req, res);
            }
            break;

          case 'POST':
            await createCategory(req, res);
            break;

          case 'PUT':
            if (!id) {
              return res.status(400).json({ error: 'Category ID is required for updates' });
            }
            await updateCategory(req, res, id);
            break;

          case 'DELETE':
            if (!id) {
              return res.status(400).json({ error: 'Category ID is required for deletion' });
            }
            await deleteCategory(req, res, id);
            break;

          default:
            res.status(405).json({ error: 'Method not allowed' });
        }
      });
    });
  } catch (error) {
    console.error('Admin categories API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Get all categories
async function getAllCategories(req, res) {
  try {
    const { data: categories, error } = await supabase
      .from('blog_categories')
      .select('*')
      .order('name');

    if (error) {
      console.error('Error fetching categories:', error);
      return res.status(500).json({ error: 'Failed to fetch categories' });
    }

    res.json({ categories });
  } catch (error) {
    console.error('Error in getAllCategories:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Get single category by ID
async function getCategory(req, res, id) {
  try {
    const { data: category, error } = await supabase
      .from('blog_categories')
      .select('*')
      .eq('id', id)
      .single();

    if (error) {
      console.error('Error fetching category:', error);
      return res.status(404).json({ error: 'Category not found' });
    }

    res.json({ category });
  } catch (error) {
    console.error('Error in getCategory:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Create new category
async function createCategory(req, res) {
  try {
    const { name, description, slug } = req.body;

    // Validate required fields
    if (!name) {
      return res.status(400).json({ error: 'Category name is required' });
    }

    // Generate slug if not provided
    let finalSlug = slug;
    if (!finalSlug) {
      finalSlug = name.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .trim('-');
    }

    // Check if slug is unique
    const { data: existingCategory } = await supabase
      .from('blog_categories')
      .select('id')
      .eq('slug', finalSlug)
      .single();

    if (existingCategory) {
      return res.status(400).json({ error: 'Category slug already exists' });
    }

    const categoryData = {
      name,
      description,
      slug: finalSlug
    };

    const { data: category, error } = await supabase
      .from('blog_categories')
      .insert([categoryData])
      .select('*')
      .single();

    if (error) {
      console.error('Error creating category:', error);
      return res.status(500).json({ error: 'Failed to create category' });
    }

    res.status(201).json({ category, message: 'Category created successfully' });
  } catch (error) {
    console.error('Error in createCategory:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Update category
async function updateCategory(req, res, id) {
  try {
    const { name, description, slug } = req.body;

    // Check if category exists
    const { data: existingCategory, error: fetchError } = await supabase
      .from('blog_categories')
      .select('*')
      .eq('id', id)
      .single();

    if (fetchError || !existingCategory) {
      return res.status(404).json({ error: 'Category not found' });
    }

    const updateData = {};
    
    if (name !== undefined) updateData.name = name;
    if (description !== undefined) updateData.description = description;
    if (slug !== undefined) {
      // Check if new slug is unique
      const { data: slugCheck } = await supabase
        .from('blog_categories')
        .select('id')
        .eq('slug', slug)
        .neq('id', id)
        .single();

      if (slugCheck) {
        return res.status(400).json({ error: 'Slug already exists' });
      }
      updateData.slug = slug;
    }

    const { data: category, error } = await supabase
      .from('blog_categories')
      .update(updateData)
      .eq('id', id)
      .select('*')
      .single();

    if (error) {
      console.error('Error updating category:', error);
      return res.status(500).json({ error: 'Failed to update category' });
    }

    res.json({ category, message: 'Category updated successfully' });
  } catch (error) {
    console.error('Error in updateCategory:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Delete category
async function deleteCategory(req, res, id) {
  try {
    // Check if category has associated blog posts
    const { data: posts, error: postsError } = await supabase
      .from('blog_posts')
      .select('id')
      .eq('category_id', id)
      .limit(1);

    if (postsError) {
      console.error('Error checking category usage:', postsError);
      return res.status(500).json({ error: 'Failed to check category usage' });
    }

    if (posts && posts.length > 0) {
      return res.status(400).json({ 
        error: 'Cannot delete category that has associated blog posts' 
      });
    }

    const { error } = await supabase
      .from('blog_categories')
      .delete()
      .eq('id', id);

    if (error) {
      console.error('Error deleting category:', error);
      return res.status(500).json({ error: 'Failed to delete category' });
    }

    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error('Error in deleteCategory:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}