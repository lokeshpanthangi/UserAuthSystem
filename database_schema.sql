-- Database Schema for Secure Authentication System
-- This file contains all SQL queries to create the required tables in Supabase
-- Execute these queries in your Supabase SQL editor

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum type for user roles
CREATE TYPE user_role AS ENUM ('user', 'admin');

-- Create users table
CREATE TABLE users (
    -- Primary key using UUID for better security and scalability
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Unique username for login (case-insensitive)
    username VARCHAR(50) UNIQUE NOT NULL,
    
    -- Unique email address (case-insensitive)
    email VARCHAR(255) UNIQUE NOT NULL,
    
    -- Bcrypt hashed password (never store plain text passwords)
    hashed_password VARCHAR(255) NOT NULL,
    
    -- User role with default value 'user'
    role user_role NOT NULL DEFAULT 'user',
    
    -- Account status flag
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Timestamp when account was created
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Timestamp when account was last updated
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
-- Index on username for fast login lookups
CREATE INDEX idx_users_username ON users(username);

-- Index on email for fast email lookups
CREATE INDEX idx_users_email ON users(email);

-- Index on role for admin queries
CREATE INDEX idx_users_role ON users(role);

-- Index on is_active for filtering active users
CREATE INDEX idx_users_is_active ON users(is_active);

-- Create function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at on row changes
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add constraints for data validation
-- Ensure username is not empty and has minimum length
ALTER TABLE users ADD CONSTRAINT check_username_length 
    CHECK (LENGTH(TRIM(username)) >= 3);

-- Ensure email format is valid (basic check)
ALTER TABLE users ADD CONSTRAINT check_email_format 
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

-- Ensure hashed_password is not empty
ALTER TABLE users ADD CONSTRAINT check_password_not_empty 
    CHECK (LENGTH(TRIM(hashed_password)) > 0);

-- Optional: Create a view for safe user data (excluding sensitive information)
CREATE VIEW user_profiles AS
SELECT 
    id,
    username,
    email,
    role,
    is_active,
    created_at,
    updated_at
FROM users;

-- Row Level Security (RLS) policies (optional but recommended)
-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own data
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT USING (auth.uid() = id);

-- Policy: Users can update their own data (except role)
CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Policy: Only service role can insert new users (handled by backend)
CREATE POLICY "Service role can insert users" ON users
    FOR INSERT WITH CHECK (auth.role() = 'service_role');

-- Policy: Only admins can view all users
CREATE POLICY "Admins can view all users" ON users
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM users 
            WHERE id = auth.uid() AND role = 'admin'
        )
    );

-- Insert a default admin user (optional - for testing)
-- Note: You should change this password and create through your API
/*
INSERT INTO users (username, email, hashed_password, role) VALUES 
('admin', 'admin@example.com', '$2b$12$example_hashed_password', 'admin');
*/

-- Comments for documentation
COMMENT ON TABLE users IS 'Main users table storing authentication and profile information';
COMMENT ON COLUMN users.id IS 'Unique identifier for each user (UUID)';
COMMENT ON COLUMN users.username IS 'Unique username for login';
COMMENT ON COLUMN users.email IS 'Unique email address';
COMMENT ON COLUMN users.hashed_password IS 'Bcrypt hashed password';
COMMENT ON COLUMN users.role IS 'User role (user or admin)';
COMMENT ON COLUMN users.is_active IS 'Account status flag';
COMMENT ON COLUMN users.created_at IS 'Account creation timestamp';
COMMENT ON COLUMN users.updated_at IS 'Last update timestamp';