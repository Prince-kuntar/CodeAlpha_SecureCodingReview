import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib

def login_user(username, password):
    conn = sqlite3.connect('blog.db')
    
    # VULN: SQL Injection in authentication
    query = f"SELECT * FROM users WHERE username = '{username}'"
    user = conn.execute(query).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        # VULN: Weak JWT secret and long expiration
        token = jwt.encode({
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)  # Too long
        }, 'hardcoded-secret-key', algorithm='HS256')
        
        return token
    return None

def register_user(username, password, email):
    # VULN: Weak password policy
    if len(password) < 4:
        return False, "Password too short"
    
    conn = sqlite3.connect('blog.db')
    
    # VULN: No uniqueness check for username/email
    hashed_pw = generate_password_hash(password, method='md5')  # VULN: Weak hashing
    
    try:
        conn.execute(f"""
            INSERT INTO users (username, password, email, role) 
            VALUES ('{username}', '{hashed_pw}', '{email}', 'user')
        """)
        conn.commit()
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()
    
    return True, "User registered"