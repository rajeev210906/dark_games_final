from flask import Flask, render_template, request, redirect, g, session, flash, url_for, jsonify
from functools import wraps
import sqlite3
import hashlib
import os
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta
import logging
import json

app = Flask(__name__)
# Production configurations
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=1),  # Reduce session lifetime
    SESSION_REFRESH_EACH_REQUEST=True,
    # Add PythonAnywhere specific settings
    APPLICATION_ROOT='/',
    PREFERRED_URL_SCHEME='https'
)

# Use ProxyFix if behind a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Add logging configuration
logging.basicConfig(
    filename='admin.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DATABASE = 'games.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Add login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def check_session_lifetime():
    if 'admin_logged_in' in session:
        last_activity = datetime.strptime(session['last_activity'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() - last_activity > timedelta(hours=1):  # Session timeout after 1 hour
            session.clear()
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('login'))
        session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please fill all fields', 'error')
            return render_template('login.html')
            
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        user = db.execute('SELECT * FROM admins WHERE username = ? AND password = ?',
                         (username, hashed_password)).fetchone()
        
        if user:
            session.clear()  # Clear any existing session
            session['admin_logged_in'] = True
            session['admin_id'] = user['id']
            session['last_activity'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session.permanent = True  # Use permanent session
            flash('Welcome back!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid credentials', 'error')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# User Homepage Route
@app.route('/')
def home():
    filter_option = request.args.get('filter', 'All')
    db = get_db()
    query = "SELECT * FROM games WHERE visible = 1"
    if filter_option != 'All':
        query += " AND filter = ?"
        games = db.execute(query, (filter_option,)).fetchall()
    else:
        games = db.execute(query).fetchall()
    return render_template('home.html', games=games, filter_option=filter_option)

# Game Details Route
@app.route('/game/<title>')
def game(title):
    db = get_db()
    
    game_details = db.execute("""
        SELECT games.*, 
               CASE WHEN games.ratings_visible = 1 THEN COUNT(DISTINCT r.id) ELSE 0 END as total_ratings,
               CASE WHEN games.ratings_visible = 1 THEN AVG(r.rating) ELSE 0 END as avg_rating
        FROM games 
        LEFT JOIN ratings r ON games.id = r.game_id
        WHERE games.title = ?
        GROUP BY games.id
    """, [title]).fetchone()
    
    if not game_details:
        flash('Game not found', 'error')
        return redirect(url_for('home'))
        
    # Only fetch visible comments
    comments = db.execute("""
        SELECT c.*, r.reply, r.timestamp as reply_timestamp,
               CASE WHEN c.visible = 1 THEN true ELSE false END as visible
        FROM comments c
        LEFT JOIN replies r ON c.id = r.comment_id
        WHERE c.game_id = ?
        ORDER BY c.timestamp DESC
    """, [game_details['id']]).fetchall()
    
    return render_template('game.html', 
                         game=game_details,
                         comments=comments,
                         avg_rating=game_details['avg_rating'] or 0,
                         total_ratings=game_details['total_ratings'])

# Admin Panel Route
@app.route('/admin')
@login_required
def admin():
    db = get_db()
    games = db.execute("SELECT * FROM games ORDER BY id DESC").fetchall()
    return render_template('admin.html', games=games)

@app.route('/admin/action', methods=['POST'])
@login_required
def admin_action():
    action = request.form.get('action')
    game_ids = request.form.getlist('game_ids[]')
    
    if not game_ids:
        flash('No games selected', 'error')
        return redirect(url_for('admin'))
    
    db = get_db()
    message = ''
    
    try:
        if action == 'delete':
            db.execute("DELETE FROM games WHERE id IN (%s)" % ','.join('?'*len(game_ids)), game_ids)
            message = f'{len(game_ids)} games deleted successfully'
        elif action in ['show', 'hide']:
            visibility = 1 if action == 'show' else 0
            db.execute(f"UPDATE games SET visible = ? WHERE id IN ({','.join('?'*len(game_ids))})", 
                      [visibility] + game_ids)
            message = f'{len(game_ids)} games {"shown" if visibility else "hidden"} successfully'
        elif action == 'toggle_visibility':
            for game_id in game_ids:
                current = db.execute("SELECT visible FROM games WHERE id = ?", (game_id,)).fetchone()
                new_visibility = 0 if current['visible'] else 1
                db.execute("UPDATE games SET visible = ? WHERE id = ?", (new_visibility, game_id))
            message = 'Game visibility toggled successfully'
        elif action == 'toggle_ratings':
            game_id = game_ids[0]  # Get single game ID
            current = db.execute("SELECT ratings_visible FROM games WHERE id = ?", (game_id,)).fetchone()
            new_visibility = 0 if current['ratings_visible'] else 1
            db.execute("UPDATE games SET ratings_visible = ? WHERE id = ?", (new_visibility, game_id))
            message = f'Ratings visibility {"enabled" if new_visibility else "disabled"} successfully'
            
        db.commit()
        flash(message, 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin'))

# Add New Game Route
@app.route('/add_game', methods=['GET', 'POST'])
@login_required
def add_game():
    if request.method == 'POST':
        image = request.form['image']
        title = request.form['title']
        text = request.form['text']
        link = request.form['link']
        filter_option = request.form['filter']
        
        db = get_db()
        db.execute("INSERT INTO games (image, title, text, link, filter, visible) VALUES (?, ?, ?, ?, ?, 1)", 
                   (image, title, text, link, filter_option))
        db.commit()
        return redirect('/admin')
    return render_template('add_game.html')

# Search Route
@app.route('/search')
def search():
    query = request.args.get('q', '')
    db = get_db()
    games = db.execute(
        "SELECT * FROM games WHERE visible = 1 AND (title LIKE ? OR text LIKE ?)",
        (f'%{query}%', f'%{query}%')
    ).fetchall()
    return render_template('home.html', games=games)

# Rate Game Route
@app.route('/rate/<int:game_id>', methods=['POST'])
def rate_game(game_id):
    db = get_db()
    game = db.execute("SELECT ratings_visible FROM games WHERE id = ?", [game_id]).fetchone()
    
    if not game or not game['ratings_visible']:
        flash('Rating is not available for this game', 'error')
        return redirect(request.referrer)
        
    rating = request.form.get('rating')
    if not rating or not rating.isdigit() or int(rating) not in range(1, 6):
        flash('Invalid rating', 'error')
        return redirect(request.referrer)
        
    db.execute("INSERT INTO ratings (game_id, rating) VALUES (?, ?)", [game_id, rating])
    db.commit()
    flash('Thank you for rating!', 'success')
    return redirect(request.referrer)

# Add new admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    db = get_db()
    total_games = db.execute("SELECT COUNT(*) as count FROM games").fetchone()['count']
    active_games = db.execute("SELECT COUNT(*) as count FROM games WHERE visible=1").fetchone()['count']
    total_ratings = db.execute("SELECT COUNT(*) as count FROM ratings").fetchone()['count']
    
    # Get recent activities
    activities = db.execute("""
        SELECT * FROM admin_logs 
        ORDER BY timestamp DESC LIMIT 10
    """).fetchall()
    
    return render_template('admin/dashboard.html', 
                         total_games=total_games,
                         active_games=active_games,
                         total_ratings=total_ratings,
                         activities=activities)

@app.route('/admin/logs')
@login_required
def admin_logs():
    with open('admin.log', 'r') as f:
        logs = f.readlines()
    return render_template('admin/logs.html', logs=logs)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if request.method == 'POST':
        db = get_db()
        settings = {
            'site_name': request.form.get('site_name'),
            'maintenance_mode': request.form.get('maintenance_mode') == 'on',
            'max_games_per_page': request.form.get('max_games_per_page'),
            'allowed_categories': request.form.getlist('categories[]')
        }
        
        db.execute("UPDATE site_settings SET value = ? WHERE key = 'settings'", 
                  (json.dumps(settings),))
        db.commit()
        flash('Settings updated successfully', 'success')
        
    return render_template('admin/settings.html')

@app.route('/admin/batch-actions', methods=['POST'])
@login_required
def batch_actions():
    action = request.form.get('action')
    game_ids = request.form.getlist('game_ids[]')
    
    db = get_db()
    if action == 'delete':
        db.execute("DELETE FROM games WHERE id IN (%s)" % ','.join('?'*len(game_ids)), game_ids)
    elif action == 'hide':
        db.execute("UPDATE games SET visible = 0 WHERE id IN (%s)" % ','.join('?'*len(game_ids)), game_ids)
    elif action == 'show':
        db.execute("UPDATE games SET visible = 1 WHERE id IN (%s)" % ','.join('?'*len(game_ids)), game_ids)
    
    db.commit()
    log_admin_action(f"Batch {action} performed on games: {','.join(game_ids)}")
    return redirect(url_for('admin'))

def log_admin_action(action):
    db = get_db()
    db.execute("""
        INSERT INTO admin_logs (admin_id, action, timestamp)
        VALUES (?, ?, ?)
    """, (session['admin_id'], action, datetime.now()))
    db.commit()
    logging.info(f"Admin {session['admin_id']}: {action}")

@app.route('/edit_game/<int:game_id>', methods=['GET', 'POST'])
@login_required
def edit_game(game_id):
    db = get_db()
    if request.method == 'POST':
        image = request.form['image']
        title = request.form['title']
        text = request.form['text']
        link = request.form['link']
        filter_option = request.form['filter']
        
        db.execute("""
            UPDATE games 
            SET image = ?, title = ?, text = ?, link = ?, filter = ? 
            WHERE id = ?
        """, (image, title, text, link, filter_option, game_id))
        db.commit()
        flash('Game updated successfully', 'success')
        return redirect(url_for('admin'))
        
    game = db.execute('SELECT * FROM games WHERE id = ?', (game_id,)).fetchone()
    if game is None:
        flash('Game not found', 'error')
        return redirect(url_for('admin'))
        
    return render_template('edit_game.html', game=game)

# Initialize database tables
def init_db():
    with app.app_context():
        db = get_db()
        
        # Create tables first
        db.execute('''CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image TEXT NOT NULL,
            title TEXT NOT NULL,
            text TEXT NOT NULL,
            link TEXT NOT NULL,
            filter TEXT NOT NULL,
            visible INTEGER DEFAULT 1,
            ratings_visible INTEGER DEFAULT 1,
            comments_enabled INTEGER DEFAULT 1
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER,
            rating INTEGER,
            FOREIGN KEY(game_id) REFERENCES games(id)
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER,
            user_name TEXT NOT NULL,
            comment TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            visible INTEGER DEFAULT 1,
            FOREIGN KEY(game_id) REFERENCES games(id)
        )''')

        db.execute('''CREATE TABLE IF NOT EXISTS replies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id INTEGER,
            admin_id INTEGER,
            reply TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(comment_id) REFERENCES comments(id),
            FOREIGN KEY(admin_id) REFERENCES admins(id)
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            action TEXT,
            timestamp DATETIME,
            FOREIGN KEY(admin_id) REFERENCES admins(id)
        )''')
        
        db.execute('''CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )''')

        # Add default admin account if it doesn't exist
        default_admin = db.execute("SELECT * FROM admins WHERE username = 'admin'").fetchone()
        if not default_admin:
            default_password = hashlib.sha256('admin123'.encode()).hexdigest()
            db.execute("INSERT INTO admins (username, password) VALUES (?, ?)",
                      ('admin', default_password))

        # Initialize default settings if not exists
        if not db.execute("SELECT * FROM site_settings WHERE key='settings'").fetchone():
            default_settings = {
                'site_name': 'Dark Games',
                'maintenance_mode': False,
                'max_games_per_page': 12,
                'allowed_categories': ['Phone', 'Desktop']
            }
            db.execute("INSERT INTO site_settings (key, value) VALUES (?, ?)",
                      ('settings', json.dumps(default_settings)))

        db.commit()

@app.route('/admin/comments')
@login_required
def admin_comments():
    db = get_db()
    comments = db.execute('''
        SELECT comments.*, games.title as game_title 
        FROM comments 
        JOIN games ON comments.game_id = games.id 
        ORDER BY comments.timestamp DESC
    ''').fetchall()
    return render_template('admin/comments.html', comments=comments)

@app.route('/admin/comment/action', methods=['POST'])
@login_required
def comment_action():
    action = request.form['action']
    comment_id = request.form['comment_id']
    db = get_db()
    
    try:
        if action == 'hide':
            db.execute("UPDATE comments SET visible = 0 WHERE id = ?", [comment_id])
            flash('Comment hidden successfully', 'success')
        elif action == 'show':
            db.execute("UPDATE comments SET visible = 1 WHERE id = ?", [comment_id])
            flash('Comment shown successfully', 'success')
        elif action == 'delete':
            db.execute("DELETE FROM comments WHERE id = ?", [comment_id])
            flash('Comment deleted successfully', 'success')
        elif action == 'reply':
            reply_text = request.form['reply']
            db.execute("INSERT INTO replies (comment_id, admin_id, reply) VALUES (?, ?, ?)",
                      [comment_id, session['admin_id'], reply_text])
            flash('Reply added successfully', 'success')
        
        db.commit()
    except Exception as e:
        db.rollback()
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(request.referrer)

@app.route('/admin/ratings')
@login_required
def admin_ratings():
    db = get_db()
    ratings = db.execute('''
        SELECT games.title, games.ratings_visible,
               COUNT(ratings.id) as total_ratings,
               AVG(ratings.rating) as avg_rating
        FROM games
        LEFT JOIN ratings ON games.id = ratings.game_id
        GROUP BY games.id
    ''').fetchall()
    return render_template('admin/ratings.html', ratings=ratings)

# Add these new routes
@app.route('/game/<int:game_id>/comment', methods=['POST'])
def add_comment(game_id):
    if request.method == 'POST':
        user_name = request.form.get('user_name')
        comment_text = request.form.get('comment')
        
        if not user_name or not comment_text:
            flash('Please fill in all fields', 'error')
            return redirect(request.referrer)
            
        db = get_db()
        db.execute("""
            INSERT INTO comments (game_id, user_name, comment, timestamp)
            VALUES (?, ?, ?, datetime('now'))
        """, [game_id, user_name, comment_text])
        db.commit()
        flash('Comment posted successfully!', 'success')
    return redirect(request.referrer)

if __name__ == '__main__':
    init_db()
    # Production settings
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=True)
