-- ─────────────────────────────────────────────────────────────────────────────
-- AC3 Local MySQL Initialization
-- Runs once on first container start (docker-entrypoint-initdb.d)
-- ─────────────────────────────────────────────────────────────────────────────

-- Ensure the database exists with correct charset
CREATE DATABASE IF NOT EXISTS ac3dev
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- Grant full access to the application user
GRANT ALL PRIVILEGES ON ac3dev.* TO 'ac3admin'@'%';
FLUSH PRIVILEGES;

-- Create slow query log directory
-- (MySQL container may not have /var/log/mysql by default)
