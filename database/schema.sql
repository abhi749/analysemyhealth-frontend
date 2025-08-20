-- HealthAI Database Schema for Cloudflare D1
-- This creates the database structure for zero-knowledge health data storage

-- Users table - Basic user information from Google OAuth
CREATE TABLE IF NOT EXISTS users (
    google_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    picture TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- User security table - Hashed security answers for encryption key derivation
-- Note: We never store the actual answers, only secure hashes
CREATE TABLE IF NOT EXISTS user_security (
    user_id TEXT PRIMARY KEY,
    answer_hash_1 TEXT NOT NULL,
    answer_hash_2 TEXT NOT NULL, 
    answer_hash_3 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id) ON DELETE CASCADE
);

-- Documents table - Metadata only, no sensitive health data
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    document_type TEXT NOT NULL CHECK (document_type IN ('lab', 'scan', 'other')),
    r2_key TEXT NOT NULL, -- Key for encrypted file in Cloudflare R2
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id) ON DELETE CASCADE
);

-- Analysis results table - Stores encrypted analysis results
-- All health insights are encrypted before storage
CREATE TABLE IF NOT EXISTS analysis_results (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    document_ids TEXT NOT NULL, -- JSON array of document IDs analyzed
    encrypted_results BLOB NOT NULL, -- Encrypted analysis data
    analysis_date TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id) ON DELETE CASCADE
);

-- User sessions table - For secure session management
CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id) ON DELETE CASCADE
);

-- User preferences table - App settings and preferences
CREATE TABLE IF NOT EXISTS user_preferences (
    user_id TEXT PRIMARY KEY,
    timezone TEXT DEFAULT 'UTC',
    date_format TEXT DEFAULT 'MM/DD/YYYY',
    notification_email BOOLEAN DEFAULT true,
    data_retention_months INTEGER DEFAULT 12,
    export_format TEXT DEFAULT 'json',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id) ON DELETE CASCADE
);

-- Audit log table - Track all access to user data for security
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL, -- 'upload', 'download', 'analyze', 'delete', etc.
    resource_type TEXT NOT NULL, -- 'document', 'analysis', etc.
    resource_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(google_id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at);
CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);

CREATE INDEX IF NOT EXISTS idx_analysis_user_id ON analysis_results(user_id);
CREATE INDEX IF NOT EXISTS idx_analysis_date ON analysis_results(analysis_date);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- Insert default data
INSERT OR IGNORE INTO user_preferences (user_id, created_at, updated_at) 
VALUES ('default', datetime('now'), datetime('now'));

-- View for user dashboard statistics
CREATE VIEW IF NOT EXISTS user_stats AS
SELECT 
    u.google_id,
    u.name,
    u.email,
    COUNT(d.id) as document_count,
    SUM(d.file_size) as total_storage_bytes,
    COUNT(ar.id) as analysis_count,
    MIN(d.created_at) as first_upload,
    MAX(d.created_at) as last_upload
FROM users u
LEFT JOIN documents d ON u.google_id = d.user_id
LEFT JOIN analysis_results ar ON u.google_id = ar.user_id
GROUP BY u.google_id, u.name, u.email;
