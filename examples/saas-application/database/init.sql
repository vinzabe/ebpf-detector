-- Abejar SaaS Database Initialization
-- This script runs on first database creation

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- The users table will be created by SQLAlchemy migrations
-- This file is for any additional initialization

-- Example: Create indexes for performance
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email);

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'Abejar SaaS database initialized at %', NOW();
END $$;
