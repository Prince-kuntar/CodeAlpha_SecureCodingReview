import os
import sqlite3
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hardcoded-secret-key'
app.config['UPLOAD_FOLDER'] = '/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Database setup
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # VULN: No signature verification
            data = jwt.decode(token, options={"verify_signature": False})
            current_user = data['user_id']
        except:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/posts/<int:post_id>')
@token_required
def get_post(current_user, post_id):
    conn = get_db_connection()
    
    # VULN: SQL Injection + No authorization check
    query = f"SELECT * FROM posts WHERE id = {post_id}"
    post = conn.execute(query).fetchone()
    conn.close()
    
    if post:
        # VULN: IDOR - any user can access any post
        return jsonify(dict(post))
    return jsonify({'error': 'Post not found'}), 404

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        # VULN: Path traversal still possible with encoded paths
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # VULN: Storing file path in DB with user input
        conn = get_db_connection()
        conn.execute(f"INSERT INTO uploads (user_id, filename) VALUES ({current_user}, '{filepath}')")
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'File uploaded successfully', 'path': filepath})

@app.route('/api/admin/users')
@token_required
def admin_users(current_user):
    # VULN: Broken Access Control - no role check
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, password FROM users").fetchall()
    conn.close()
    
    return jsonify([dict(user) for user in users])

@app.route('/api/posts/<int:post_id>/delete', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    conn = get_db_connection()
    
    # VULN: No ownership verification
    conn.execute(f"DELETE FROM posts WHERE id = {post_id}")
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Post deleted'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')