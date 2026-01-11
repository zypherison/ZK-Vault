from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import os
import vault_manager
import crypto_engine
import breach_checker
import json

app = Flask(__name__)
app.secret_key = os.urandom(24)

# FIX: Allow cookies in Cross-Origin Extension requests
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_HTTPONLY=True
)

CORS(app, supports_credentials=True) # Enable CORS for Extension compatibility

# Hardcoded Admin (Demo purposes)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "admin123"

if not os.path.exists(vault_manager.DB_NAME):
    vault_manager.init_db()

@app.after_request
def add_security_headers(response):
    """Injects production-grade security headers."""
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Force HTTPS (HSTS) - Standard for Swiss-style vaults
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    # CSP is critical for ZK-Vault to prevent XSS from stealing the master key
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://api.pwnedpasswords.com https://cdn.jsdelivr.net chrome-extension://*; "
        "worker-src 'self' blob:;"
    )
    return response

@app.before_request
def restrict_admin_access():
    """Globally gates the /admin route to ensure no session bypass."""
    if request.path.startswith('/admin'):
        if not session.get('is_admin') or session.get('user') != ADMIN_USERNAME:
            return redirect(url_for('login'))
    
    # Gate the vault sync API to ensure only logged-in users can access it
    if request.path.startswith('/api/vault') and request.method == 'GET':
        if 'user' not in session:
            return jsonify({"error": "Unauthorized"}), 401

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('vault'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    data = request.json
    username = data.get('username')
    auth_hash = data.get('auth_hash') # Client derived hash
    password = data.get('password') # For plain login like admin
    
    # Check Admin first
    if username == ADMIN_USERNAME and (password == ADMIN_PASSWORD_HASH or auth_hash == ADMIN_PASSWORD_HASH):
        session.clear() # Clear any existing user data
        session['user'] = username
        session['is_admin'] = True
        return jsonify({"status": "success", "redirect": "/admin"})

    user = vault_manager.get_user(username)
    if user:
        if user['auth_hash'] == auth_hash:
            session.clear()
            session['user'] = username
            session['is_admin'] = False
            return jsonify({"status": "success", "redirect": "/vault"})
        else:
            print(f"Login failed for {username}. Provided: {auth_hash[:10]}... Stored: {user['auth_hash'][:10]}...")
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    else:
        # Register flow (Auto-register for demo simplicity if user doesn't exist? 
        # Or explicit register? Prompt says 'User creates vault'.
        # Let's handle registration in a separate call or auto-create if not exists for smoother demo.)
        return jsonify({"status": "error", "message": "User not found. Use /register first."}), 404

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    auth_hash = data.get('auth_hash')
    salt = data.get('salt') # User's salt for their encryption key (needed to derive key again)
    encrypted_blob = data.get('encrypted_blob') # Initial empty vault or populated
    
    if vault_manager.get_user(username):
        return jsonify({"status": "error", "message": "User already exists"}), 400
        
    vault_manager.create_user(username, auth_hash, salt, encrypted_blob)
    session['user'] = username
    return jsonify({"status": "success", "redirect": "/vault"})

@app.route('/vault')
def vault():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('vault.html', username=session['user'])

@app.route('/api/vault', methods=['GET', 'POST'])
def api_vault():
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
        
    username = session['user']
    if request.method == 'GET':
        user = vault_manager.get_user(username)
        return jsonify({
            "encrypted_blob": user['encrypted_blob'],
            "salt": user['salt']
        })
    elif request.method == 'POST':
        data = request.json
        vault_manager.update_vault(
            username, 
            data.get('encrypted_blob'),
            data.get('security_score', 0),
            data.get('pwned_count', 0),
            data.get('item_count', 0),
            data.get('note_count', 0),
            data.get('file_count', 0)
        )
        return jsonify({"status": "success"})

@app.route('/api/user_salt')
def get_user_salt():
    username = request.args.get('username')
    
    # Check for hardcoded admin first
    if username == ADMIN_USERNAME:
        return jsonify({"salt": "admin_salt_placeholder"}) # Admin doesn't strictly need ZK salt but extension expects one
        
    user = vault_manager.get_user(username)
    if user:
        return jsonify({"salt": user['salt']})
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/admin')
def admin():
    # RIGOROUS Check: Must be logged in AND have the is_admin flag explicitly set
    if not session.get('is_admin') or session.get('user') != ADMIN_USERNAME:
        return redirect(url_for('login'))
        
    users = vault_manager.get_all_users_admin()
    
    # Mock system stats
    db_path = vault_manager.DB_NAME
    db_size = f"{os.path.getsize(db_path) / 1024:.1f} KB" if os.path.exists(db_path) else "Cloud/Turso"
    
    stats = {
        "db_size": db_size,
        "total_vaults": len(users),
        "admin_status": "Online",
        "server_load": "0.15, 0.08, 0.02"
    }
    
    return render_template('admin.html', users=users, stats=stats)

@app.route('/api/pwned/<prefix>')
def pwned(prefix):
    # Proxy to HIBP to avoid exposing Client IP if desired, or just to CORS wrapper
    # Prefix usually 5 chars
    if len(prefix) != 5:
        return jsonify({"error": "Invalid prefix"}), 400
    
    result = breach_checker.check_breach_prefix(prefix)
    return result # Returns the raw text specific format from HIBP

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    vault_manager.init_db()
    # Use PORT env for Render/Heroku compatibility
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
