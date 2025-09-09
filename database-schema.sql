-- Event Joining App Database Schema
-- This file contains the SQL commands to set up the required tables in Supabase

-- Enable Row Level Security (RLS) for all tables
-- Run these commands in your Supabase SQL Editor

-- 1. Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    photo TEXT, -- URL to user's photo
    ebs_join_date DATE, -- Date when user joined EBS (if applicable)
    is_baptized BOOLEAN DEFAULT false, -- Baptism status (No/Yes)
    baptism_date DATE, -- Date of baptism (if baptized)
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- 2. Event registrations table (existing)
CREATE TABLE IF NOT EXISTS registrations (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    age INTEGER NOT NULL CHECK (age > 0 AND age < 150),
    reason TEXT NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    document_url TEXT, -- For file uploads
    admin_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Email verification tokens table
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. User sessions table (optional, for session management)
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_token TEXT UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
CREATE INDEX IF NOT EXISTS idx_users_is_baptized ON users(is_baptized);
CREATE INDEX IF NOT EXISTS idx_users_ebs_join_date ON users(ebs_join_date);
CREATE INDEX IF NOT EXISTS idx_registrations_user_id ON registrations(user_id);
CREATE INDEX IF NOT EXISTS idx_registrations_status ON registrations(status);
CREATE INDEX IF NOT EXISTS idx_registrations_email ON registrations(email);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_token ON email_verification_tokens(token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_registrations_updated_at BEFORE UPDATE ON registrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) Policies

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verification_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;

-- Users table policies
-- Users can read their own data
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT USING (auth.uid() = id);

-- Users can update their own data (except role and is_active)
CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Only service role can insert users (handled by API)
CREATE POLICY "Service role can insert users" ON users
    FOR INSERT WITH CHECK (auth.role() = 'service_role');

-- Admins can view all users
CREATE POLICY "Admins can view all users" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Registrations table policies
-- Users can view their own registrations
CREATE POLICY "Users can view own registrations" ON registrations
    FOR SELECT USING (user_id = auth.uid());

-- Users can insert their own registrations
CREATE POLICY "Users can create registrations" ON registrations
    FOR INSERT WITH CHECK (user_id = auth.uid());

-- Users can update their own registrations (if status is pending)
CREATE POLICY "Users can update own pending registrations" ON registrations
    FOR UPDATE USING (user_id = auth.uid() AND status = 'pending');

-- Admins can view and manage all registrations
CREATE POLICY "Admins can manage all registrations" ON registrations
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Password reset tokens policies
CREATE POLICY "Users can view own password reset tokens" ON password_reset_tokens
    FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service role can manage password reset tokens" ON password_reset_tokens
    FOR ALL WITH CHECK (auth.role() = 'service_role');

-- Email verification tokens policies
CREATE POLICY "Users can view own email verification tokens" ON email_verification_tokens
    FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service role can manage email verification tokens" ON email_verification_tokens
    FOR ALL WITH CHECK (auth.role() = 'service_role');

-- User sessions policies
CREATE POLICY "Users can view own sessions" ON user_sessions
    FOR SELECT USING (user_id = auth.uid());

CREATE POLICY "Service role can manage user sessions" ON user_sessions
    FOR ALL WITH CHECK (auth.role() = 'service_role');

-- Enable RLS on new tables
ALTER TABLE learning_modules ENABLE ROW LEVEL SECURITY;
ALTER TABLE blog_posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_module_progress ENABLE ROW LEVEL SECURITY;

-- Learning modules policies
-- Everyone can view published modules
CREATE POLICY "Anyone can view published learning modules" ON learning_modules
    FOR SELECT USING (is_published = true);

-- Admins can manage all learning modules
CREATE POLICY "Admins can manage learning modules" ON learning_modules
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Blog posts policies
-- Everyone can view published blog posts
CREATE POLICY "Anyone can view published blog posts" ON blog_posts
    FOR SELECT USING (is_published = true);

-- Authors can view their own posts
CREATE POLICY "Authors can view own posts" ON blog_posts
    FOR SELECT USING (author_id = auth.uid());

-- Admins can manage all blog posts
CREATE POLICY "Admins can manage blog posts" ON blog_posts
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM admin_users au 
            WHERE au.user_id = auth.uid()
        )
    );

-- Authors can manage their own posts
CREATE POLICY "Authors can manage own posts" ON blog_posts
    FOR ALL USING (author_id = auth.uid());

-- User module progress policies
-- Users can view and update their own progress
CREATE POLICY "Users can manage own module progress" ON user_module_progress
    FOR ALL USING (user_id = auth.uid());

-- Admins can view all user progress
CREATE POLICY "Admins can view all module progress" ON user_module_progress
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Enable RLS on admin_users
ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;

-- Policy: Only admins can view admin_users
CREATE POLICY "Admins can view admin users" ON admin_users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM admin_users au 
            WHERE au.user_id = auth.uid()
        )
    );

-- Policy: Only super admins can manage admin_users
CREATE POLICY "Super admins can manage admin users" ON admin_users
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM admin_users au 
            WHERE au.user_id = auth.uid() 
            AND au.permissions ? 'manage_admins'
        )
    );

-- Enable RLS on blog_categories
ALTER TABLE blog_categories ENABLE ROW LEVEL SECURITY;

-- Policy: Everyone can view categories
CREATE POLICY "Anyone can view categories" ON blog_categories
    FOR SELECT USING (true);

-- Policy: Only admins can manage categories
CREATE POLICY "Admins can manage categories" ON blog_categories
    FOR ALL USING (
        EXISTS (
            SELECT 1 FROM admin_users au 
            WHERE au.user_id = auth.uid()
        )
    );

-- Insert default admin user (optional)
-- Remember to change the password hash to your actual hashed password
-- This is just an example - you should create admin users through your API
/*
INSERT INTO users (email, password_hash, name, role, is_active, email_verified)
VALUES (
    'admin@example.com',
    '$2a$12$example_hashed_password_here',
    'System Administrator',
    'admin',
    true,
    true
) ON CONFLICT (email) DO NOTHING;
*/

-- Create admin_users table for admin role management
CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'admin',
    permissions JSONB DEFAULT '[]'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Create indexes for admin_users
CREATE INDEX idx_admin_users_user_id ON admin_users(user_id);
CREATE INDEX idx_admin_users_role ON admin_users(role);

-- Add trigger for admin_users updated_at
CREATE TRIGGER update_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create blog_categories table for better category management
CREATE TABLE blog_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    slug VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create trigger for blog_categories updated_at
CREATE TRIGGER update_blog_categories_updated_at
    BEFORE UPDATE ON blog_categories
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create a function to clean up expired tokens (run periodically)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    -- Delete expired password reset tokens
    DELETE FROM password_reset_tokens 
    WHERE expires_at < NOW() OR used = true;
    
    -- Delete expired email verification tokens
    DELETE FROM email_verification_tokens 
    WHERE expires_at < NOW() OR used = true;
    
    -- Delete expired user sessions
    DELETE FROM user_sessions 
    WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- You can set up a cron job or scheduled function to run cleanup_expired_tokens() periodically

-- 6. Learning modules table for MVP
CREATE TABLE IF NOT EXISTS learning_modules (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    content TEXT NOT NULL,
    order_index INTEGER DEFAULT 0,
    is_published BOOLEAN DEFAULT false,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. Blog posts table for MVP
CREATE TABLE IF NOT EXISTS blog_posts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    excerpt TEXT,
    content TEXT NOT NULL,
    featured_image TEXT,
    is_published BOOLEAN DEFAULT false,
    published_at TIMESTAMP WITH TIME ZONE,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    meta_description TEXT,
    category_id UUID REFERENCES blog_categories(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 8. User progress tracking for learning modules
CREATE TABLE IF NOT EXISTS user_module_progress (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    module_id UUID REFERENCES learning_modules(id) ON DELETE CASCADE,
    completed BOOLEAN DEFAULT false,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, module_id)
);

-- Additional indexes for new tables
CREATE INDEX IF NOT EXISTS idx_learning_modules_published ON learning_modules(is_published);
CREATE INDEX IF NOT EXISTS idx_learning_modules_order ON learning_modules(order_index);
CREATE INDEX IF NOT EXISTS idx_blog_posts_published ON blog_posts(is_published);
CREATE INDEX IF NOT EXISTS idx_blog_posts_slug ON blog_posts(slug);
CREATE INDEX IF NOT EXISTS idx_blog_posts_author ON blog_posts(author_id);
CREATE INDEX IF NOT EXISTS idx_blog_posts_published_at ON blog_posts(published_at);
CREATE INDEX IF NOT EXISTS idx_blog_posts_category_id ON blog_posts(category_id);
CREATE INDEX IF NOT EXISTS idx_user_module_progress_user ON user_module_progress(user_id);
CREATE INDEX IF NOT EXISTS idx_user_module_progress_module ON user_module_progress(module_id);

-- Create triggers for updated_at columns on new tables
CREATE TRIGGER update_learning_modules_updated_at BEFORE UPDATE ON learning_modules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_blog_posts_updated_at BEFORE UPDATE ON blog_posts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Storage bucket for file uploads (run in Supabase dashboard)
/*
-- Create storage bucket for registration documents
INSERT INTO storage.buckets (id, name, public)
VALUES ('registration-documents', 'registration-documents', false);

-- Create storage policy for registration documents
CREATE POLICY "Users can upload their own documents" ON storage.objects
    FOR INSERT WITH CHECK (
        bucket_id = 'registration-documents' AND
        auth.uid()::text = (storage.foldername(name))[1]
    );

CREATE POLICY "Users can view their own documents" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'registration-documents' AND
        auth.uid()::text = (storage.foldername(name))[1]
    );

CREATE POLICY "Admins can view all documents" ON storage.objects
    FOR SELECT USING (
        bucket_id = 'registration-documents' AND
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );
*/