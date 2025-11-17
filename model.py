import sqlite3
import datetime

def init_database():
    """Initialize the database with sample data"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # Create users table with weak password storage
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create posts table with no ownership enforcement
    c.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            user_id INTEGER,
            is_public BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create uploads table with insecure file references
    c.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            original_name TEXT,
            upload_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Insert vulnerable default data
    try:
        # VULN: Default admin with weak password
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", 
                 ('admin', 'admin123', 'admin@blog.com', 'admin'))
        
        # VULN: Regular user
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                 ('user1', 'password123', 'user1@blog.com'))
        
        # Sample posts with mixed ownership
        c.execute("INSERT INTO posts (title, content, user_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Welcome to our Blog', 'This is the first post!', 1, 1))
        
        c.execute("INSERT INTO posts (title, content, user_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Private Thoughts', 'This should be private...', 2, 0))
        
        c.execute("INSERT INTO posts (title, content, user_id, is_public) VALUES (?, ?, ?, ?)",
                 ('Public Announcement', 'Important news!', 1, 1))
                 
    except sqlite3.IntegrityError:
        # Data already exists
        pass
    
    conn.commit()
    conn.close()

def get_user_by_id(user_id):
    """VULN: No input validation on user_id"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # VULN: Direct string formatting in query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    user = c.execute(query).fetchone()
    
    conn.close()
    return user

def get_all_users():
    """VULN: Exposes password hashes to any caller"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    users = c.execute("SELECT id, username, password, email, role FROM users").fetchall()
    
    conn.close()
    return users

def create_post(title, content, user_id, is_public=True):
    """VULN: No authorization check - any user can create posts as anyone"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # VULN: SQL Injection vulnerability
    query = f"""
        INSERT INTO posts (title, content, user_id, is_public) 
        VALUES ('{title}', '{content}', {user_id}, {1 if is_public else 0})
    """
    c.execute(query)
    
    conn.commit()
    conn.close()
    return c.lastrowid

def get_all_posts():
    """VULN: Returns all posts without privacy checks"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    posts = c.execute("""
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC
    """).fetchall()
    
    conn.close()
    return posts

def delete_post_by_id(post_id):
    """VULN: No ownership verification - any user can delete any post"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # VULN: SQL Injection and no authorization
    query = f"DELETE FROM posts WHERE id = {post_id}"
    c.execute(query)
    
    conn.commit()
    conn.close()
    return c.rowcount > 0

def log_user_action(user_id, action):
    """VULN: Logging function with SQL Injection"""
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    
    # VULN: SQL Injection in logging
    query = f"""
        INSERT INTO user_actions (user_id, action, timestamp) 
        VALUES ({user_id}, '{action}', datetime('now'))
    """
    
    # VULN: Table might not exist - no error handling
    c.execute(query)
    conn.commit()
    conn.close()