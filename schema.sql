-- Create logs table (each log for an IP event)
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event TEXT               -- e.g., "NORMAL" or "SYN"
);

-- Create threats table for storing suspicious activity alerts
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_type TEXT,         -- e.g., "SYN Flood"
    description TEXT
);
