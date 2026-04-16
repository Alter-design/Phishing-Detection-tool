import sqlite3
from datetime import datetime

DB_NAME = "phishing.db"

def init_db():
    """Initialize database with required tables."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Scan results table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL,
            risk_level TEXT,
            rf_prediction TEXT,
            xgb_prediction TEXT,
            rule_score INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Admin users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Statistics table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE UNIQUE,
            total_scans INTEGER DEFAULT 0,
            phishing_detected INTEGER DEFAULT 0,
            legitimate_detected INTEGER DEFAULT 0
        )
    """)
    
    # Insert default admin if not exists
    cursor.execute("SELECT * FROM admins WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            ("admin", "admin123")
        )
    
    # Whitelist table for legitimate sites
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            added_by TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert default whitelist entries if table is empty
    cursor.execute("SELECT COUNT(*) FROM whitelist")
    if cursor.fetchone()[0] == 0:
        default_whitelist = [
            ("google.com", "system"),
            ("youtube.com", "system"),
            ("facebook.com", "system"),
            ("twitter.com", "system"),
            ("instagram.com", "system"),
            ("linkedin.com", "system"),
            ("github.com", "system"),
            ("stackoverflow.com", "system"),
            ("microsoft.com", "system"),
            ("apple.com", "system"),
            ("amazon.com", "system"),
            ("netflix.com", "system"),
            ("wikipedia.org", "system"),
            ("reddit.com", "system"),
            ("yahoo.com", "system"),
            ("bing.com", "system"),
            ("https://www.uptm.edu.my", "system"),
        ]
        cursor.executemany(
            "INSERT INTO whitelist (url, added_by) VALUES (?, ?)",
            default_whitelist
        )
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")


def save_scan(url, prediction, confidence, risk_level, rf_prediction, xgb_prediction, rule_score):
    """Save a scan result to the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scan_results 
        (url, prediction, confidence, risk_level, rf_prediction, xgb_prediction, rule_score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (url, prediction, confidence, risk_level, rf_prediction, xgb_prediction, rule_score))
    
    scan_id = cursor.lastrowid
    
    # Update statistics
    today = datetime.now().date()
    cursor.execute("SELECT * FROM statistics WHERE date = ?", (today,))
    stats = cursor.fetchone()
    
    if stats:
        cursor.execute("""
            UPDATE statistics 
            SET total_scans = total_scans + 1,
                phishing_detected = phishing_detected + ?,
                legitimate_detected = legitimate_detected + ?
            WHERE date = ?
        """, (1 if prediction == "Phishing" else 0, 
              1 if prediction == "Legitimate" else 0, today))
    else:
        cursor.execute("""
            INSERT INTO statistics (date, total_scans, phishing_detected, legitimate_detected)
            VALUES (?, 1, ?, ?)
        """, (today, 
              1 if prediction == "Phishing" else 0,
              1 if prediction == "Legitimate" else 0))
    
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit=100):
    """Get recent scan history."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, url, prediction, CAST(confidence AS REAL), risk_level, scan_date
        FROM scan_results
        ORDER BY scan_date DESC
        LIMIT ?
    """, (limit,))
    
    results = cursor.fetchall()
    conn.close()
    return results


def get_statistics():
    """Get overall statistics."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scan_results")
    total_scans = cursor.fetchone()[0]
    
    # Phishing detected
    cursor.execute("SELECT COUNT(*) FROM scan_results WHERE prediction = 'Phishing'")
    phishing_count = cursor.fetchone()[0]
    
    # Legitimate detected
    cursor.execute("SELECT COUNT(*) FROM scan_results WHERE prediction = 'Legitimate'")
    legitimate_count = cursor.fetchone()[0]
    
    # Recent scans by day (last 7 days)
    cursor.execute("""
        SELECT date, total_scans, phishing_detected, legitimate_detected
        FROM statistics
        ORDER BY date DESC
        LIMIT 7
    """)
    daily_stats = cursor.fetchall()
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'phishing_detected': phishing_count,
        'legitimate_detected': legitimate_count,
        'daily_stats': daily_stats
    }


def verify_admin(username, password):
    """Verify admin credentials."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM admins WHERE username = ? AND password = ?",
        (username, password)
    )
    
    result = cursor.fetchone()
    conn.close()
    return result is not None


def search_scans(query):
    """Search scans by URL."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, url, prediction, CAST(confidence AS REAL), risk_level, scan_date
        FROM scan_results
        WHERE url LIKE ?
        ORDER BY scan_date DESC
        LIMIT 50
    """, (f"%{query}%",))
    
    results = cursor.fetchall()
    conn.close()
    return results


def add_to_whitelist(url, added_by="admin"):
    """Add a URL to the whitelist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Normalize URL - remove http:// or https:// for consistent matching
    normalized_url = url.lower().strip()
    if normalized_url.startswith('http://'):
        normalized_url = normalized_url[7:]
    elif normalized_url.startswith('https://'):
        normalized_url = normalized_url[8:]
    
    # Remove trailing slash
    normalized_url = normalized_url.rstrip('/')
    
    try:
        cursor.execute(
            "INSERT INTO whitelist (url, added_by) VALUES (?, ?)",
            (normalized_url, added_by)
        )
        conn.commit()
        success = True
        error_msg = None
    except sqlite3.IntegrityError:
        success = False
        error_msg = "URL already exists in whitelist"
    finally:
        conn.close()
    
    return success, error_msg


def get_whitelist():
    """Get all whitelist entries."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, url, added_by, added_date
        FROM whitelist
        ORDER BY added_date DESC
    """)
    
    results = cursor.fetchall()
    conn.close()
    return results


def remove_from_whitelist(id):
    """Remove a URL from the whitelist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM whitelist WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return True


def get_whitelist_urls():
    """Get all whitelist URLs as a list (for detector)."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT url FROM whitelist")
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return results


if __name__ == "__main__":
    # Initialize database
    init_db()
    
    # Test functions
    print("\nTesting database functions...")
    
    # Save a test scan
    scan_id = save_scan(
        "http://test-phishing.com/login",
        "Phishing",
        95.5,
        "HIGH",
        "Phishing",
        "Phishing",
        8
    )
    print(f"✓ Saved scan with ID: {scan_id}")
    
    # Get history
    history = get_scan_history()
    print(f"✓ Scan history: {len(history)} records")
    
    # Get statistics
    stats = get_statistics()
    print(f"✓ Statistics: {stats}")
