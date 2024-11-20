from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
import csv
from io import StringIO

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# Configure app based on environment
if os.getenv('FLASK_ENV') == 'production':
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Set this in production environment
    app.config['DEBUG'] = False
    # Security headers for production
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data:;"
        return response
else:  # development
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['DEBUG'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///timejournal.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.jinja_env.globals.update(min=min)  # Add min function to Jinja environment
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use memory storage for simplicity
)

def limit_login_attempts():
    """Apply rate limiting to login attempts"""
    def decorator(f):
        @wraps(f)
        @limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
        def wrapped(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapped
    return decorator

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    entries = db.relationship('TimeEntry', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

class TimeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    available_time = db.Column(db.Float, nullable=False)  # in hours
    actual_time = db.Column(db.Float, nullable=False)  # in hours
    notes = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*" for c in password):
        return False, "Password must contain at least one special character (!@#$%^&*)"
    return True, ""

def init_db():
    with app.app_context():
        db.create_all()
        # Create admin user if no users exist
        if not User.query.first():
            admin = User(username='admin', is_admin=True)
            admin.set_password('AdminPass123!')
            db.session.add(admin)
            db.session.commit()

# Initialize database when the app starts
init_db()

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limit_login_attempts()
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next_page = request.args.get('next')
            if next_page and url_for('static', filename='') not in next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validate username
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Validate password
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg)
            return redirect(url_for('register'))
        
        # Make the first user an admin
        is_first_user = User.query.count() == 0
        user = User(username=username,
                   password_hash=generate_password_hash(password),
                   is_admin=is_first_user)
        
        db.session.add(user)
        try:
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get date range parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Base query
    query = TimeEntry.query.filter_by(user_id=current_user.id)
    
    # Apply date filters if provided
    if start_date and end_date:
        query = query.filter(
            TimeEntry.date >= datetime.datetime.strptime(start_date, '%Y-%m-%d').date(),
            TimeEntry.date <= datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
        )
    
    # Order entries by date
    query = query.order_by(TimeEntry.date.desc())
    
    # Get paginated entries
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    entries = pagination.items
    
    # Calculate overall utilization for the filtered date range
    all_entries = query.all()  # Get all entries for the filtered range
    if all_entries:
        total_available = sum(entry.available_time for entry in all_entries)
        total_actual = sum(entry.actual_time for entry in all_entries)
        overall_utilization = round((total_actual / total_available) * 100, 2) if total_available > 0 else 0
    else:
        overall_utilization = 0

    # If request wants JSON, return chart data
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Get entries ordered by date ascending for the chart
        chart_entries = query.order_by(TimeEntry.date.asc()).all()
        return jsonify({
            'dates': [entry.date.strftime('%Y-%m-%d') for entry in chart_entries],
            'available_times': [entry.available_time for entry in chart_entries],
            'actual_times': [entry.actual_time for entry in chart_entries]
        })
    
    return render_template('dashboard.html',
                         entries=entries,
                         pagination=pagination,
                         per_page=per_page,
                         overall_utilization=overall_utilization)

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    try:
        date = datetime.datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
        
        # Get time values from form
        available_time = request.form.get('available_time')
        actual_time = request.form.get('actual_time')
        
        # Validate available_time
        try:
            available_time = float(available_time)
            if available_time <= 0:
                flash('Available time must be a positive number')
                return redirect(url_for('dashboard'))
            if available_time > 24:
                flash('Available time cannot be more than 24 hours')
                return redirect(url_for('dashboard'))
        except (ValueError, TypeError):
            flash('Available time must be a valid number')
            return redirect(url_for('dashboard'))
            
        # Validate actual_time
        try:
            actual_time = float(actual_time)
            if actual_time < 0:
                flash('Actual time must be a positive number')
                return redirect(url_for('dashboard'))
            if actual_time > 24:
                flash('Actual time cannot be more than 24 hours')
                return redirect(url_for('dashboard'))
            if actual_time > available_time:
                flash('Actual time cannot exceed available time')
                return redirect(url_for('dashboard'))
        except (ValueError, TypeError):
            flash('Actual time must be a valid number')
            return redirect(url_for('dashboard'))

        # Check total hours for the day
        existing_entries = TimeEntry.query.filter_by(
            user_id=current_user.id,
            date=date
        ).all()
        
        total_available = sum(entry.available_time for entry in existing_entries)
        total_actual = sum(entry.actual_time for entry in existing_entries)
        
        if total_available + available_time > 24:
            flash('Total available time for the day cannot exceed 24 hours')
            return redirect(url_for('dashboard'))
            
        if total_actual + actual_time > 24:
            flash('Total actual time for the day cannot exceed 24 hours')
            return redirect(url_for('dashboard'))
        
        notes = request.form.get('notes')
        
        entry = TimeEntry(
            date=date,
            available_time=available_time,
            actual_time=actual_time,
            notes=notes,
            user_id=current_user.id
        )
        
        db.session.add(entry)
        db.session.commit()
        flash('Time entry added successfully')
        return redirect(url_for('dashboard'))
        
    except ValueError:
        flash('Invalid date format')
        return redirect(url_for('dashboard'))

@app.route('/get_entries')
@login_required
def get_entries():
    # Get date range parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Base query
    query = TimeEntry.query.filter_by(user_id=current_user.id)
    
    # Apply date filters if provided
    if start_date and end_date:
        query = query.filter(
            TimeEntry.date >= datetime.datetime.strptime(start_date, '%Y-%m-%d').date(),
            TimeEntry.date <= datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
        )
    
    # Get entries ordered by date
    entries = query.order_by(TimeEntry.date.asc()).all()
    
    # Aggregate entries by date
    daily_entries = {}
    for entry in entries:
        date_str = entry.date.strftime('%Y-%m-%d')
        if date_str not in daily_entries:
            daily_entries[date_str] = {
                'available_time': 0,
                'actual_time': 0,
                'notes': []
            }
        daily_entries[date_str]['available_time'] += entry.available_time
        daily_entries[date_str]['actual_time'] += entry.actual_time
        if entry.notes:
            daily_entries[date_str]['notes'].append(entry.notes)
    
    # Calculate utilization rates for each day
    entries_data = []
    total_utilization = 0
    
    for i, (date, data) in enumerate(sorted(daily_entries.items()), 1):
        utilization_rate = round((data['actual_time'] / data['available_time']) * 100, 2)
        total_utilization += utilization_rate
        average_utilization = round(total_utilization / i, 2)
        
        entries_data.append({
            'date': date,
            'available_time': data['available_time'],
            'actual_time': data['actual_time'],
            'utilization_rate': utilization_rate,
            'average_utilization': average_utilization,
            'notes': ' | '.join(data['notes']) if data['notes'] else ''
        })
    
    return jsonify(entries_data)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    all_entries = TimeEntry.query.order_by(TimeEntry.date.desc()).all()
    
    # Calculate overall statistics
    total_users = len(users)
    total_entries = len(all_entries)
    admin_users = len([user for user in users if user.is_admin])
    
    # Calculate average utilization per user
    user_stats = []
    for user in users:
        user_entries = TimeEntry.query.filter_by(user_id=user.id).all()
        if user_entries:
            total_available = sum(entry.available_time for entry in user_entries)
            total_actual = sum(entry.actual_time for entry in user_entries)
            utilization = (total_actual / total_available * 100) if total_available > 0 else 0
            entry_count = len(user_entries)
        else:
            utilization = 0
            entry_count = 0
            
        user_stats.append({
            'username': user.username,
            'utilization': round(utilization, 1),
            'entry_count': entry_count,
            'is_admin': user.is_admin,
            'id': user.id  # Add this line to fix the toggle admin functionality
        })
    
    # Calculate daily aggregates for the chart
    def get_admin_chart_data():
        # Get all entries ordered by date
        entries = TimeEntry.query.order_by(TimeEntry.date.desc()).all()
        
        # Create a dictionary to store daily stats
        daily_stats = {}
        
        for entry in entries:
            date_str = entry.date.strftime('%Y-%m-%d')
            if date_str not in daily_stats:
                daily_stats[date_str] = {
                    'total_entries': 0,
                    'total_utilization': 0,
                    'entry_count': 0
                }
            
            daily_stats[date_str]['total_entries'] += 1
            daily_stats[date_str]['total_utilization'] += (entry.actual_time / entry.available_time * 100 if entry.available_time > 0 else 0)
            daily_stats[date_str]['entry_count'] += 1
        
        # Convert to list and calculate averages
        chart_data = []
        for date_str, stats in sorted(daily_stats.items()):
            avg_utilization = stats['total_utilization'] / stats['entry_count'] if stats['entry_count'] > 0 else 0
            chart_data.append({
                'date': date_str,
                'utilization': round(avg_utilization, 1),
                'entries': stats['total_entries']
            })
        
        # Sort by date
        chart_data.sort(key=lambda x: x['date'])
        
        # Calculate overall average utilization
        if entries:
            total_utilization = sum(entry.actual_time / entry.available_time * 100 if entry.available_time > 0 else 0 for entry in entries)
            avg_utilization = round(total_utilization / len(entries), 1)
        else:
            avg_utilization = 0
        
        return chart_data, avg_utilization

    chart_data, avg_utilization = get_admin_chart_data()
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_entries=total_entries,
                         admin_users=admin_users,
                         user_stats=user_stats,
                         chart_data=chart_data,
                         avg_utilization=avg_utilization,
                         users=users)

@app.route('/admin/create_admin', methods=['POST'])
@login_required
@admin_required
def create_admin():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('admin_dashboard'))
    
    user = User(username=username,
                password_hash=generate_password_hash(password),
                is_admin=True)
    db.session.add(user)
    db.session.commit()
    flash(f'Created admin user: {username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect(url_for('admin_dashboard'))
    
    if not validate_password(password)[0]:
        flash('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number')
        return redirect(url_for('admin_dashboard'))
    
    user = User(username=username,
                password_hash=generate_password_hash(password),
                is_admin=False)
    db.session.add(user)
    db.session.commit()
    
    flash(f'Successfully created user: {username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot modify your own admin status')
        return redirect(url_for('admin_dashboard'))
    
    # Check if we're trying to remove admin status
    if user.is_admin:
        # Count total number of admins
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            flash('Cannot remove admin status: This is the last admin account')
            return redirect(url_for('admin_dashboard'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Updated admin status for user: {user.username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account')
        return redirect(url_for('admin_dashboard'))
    
    # Delete all entries associated with the user
    TimeEntry.query.filter_by(user_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    flash(f'Deleted user: {user.username}')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = TimeEntry.query.get_or_404(entry_id)
    
    # Ensure users can only edit their own entries
    if entry.user_id != current_user.id:
        flash('You do not have permission to edit this entry.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            new_date = datetime.datetime.strptime(request.form['date'], '%Y-%m-%d').date()
            new_available_time = float(request.form['available_time'])
            new_actual_time = float(request.form['actual_time'])
            
            # Validate time inputs
            if new_available_time <= 0 or new_available_time > 24:
                flash('Available time must be between 0 and 24 hours')
                return render_template('edit_entry.html', entry=entry)
                
            if new_actual_time < 0 or new_actual_time > 24:
                flash('Actual time must be between 0 and 24 hours')
                return render_template('edit_entry.html', entry=entry)
                
            if new_actual_time > new_available_time:
                flash('Actual time cannot exceed available time')
                return render_template('edit_entry.html', entry=entry)
            
            # Check total hours for the day
            existing_entries = TimeEntry.query.filter_by(
                user_id=current_user.id,
                date=new_date
            ).filter(TimeEntry.id != entry_id).all()
            
            total_available = sum(e.available_time for e in existing_entries)
            total_actual = sum(e.actual_time for e in existing_entries)
            
            if total_available + new_available_time > 24:
                flash('Total available time for the day cannot exceed 24 hours')
                return render_template('edit_entry.html', entry=entry)
                
            if total_actual + new_actual_time > 24:
                flash('Total actual time for the day cannot exceed 24 hours')
                return render_template('edit_entry.html', entry=entry)
            
            # Update entry
            entry.date = new_date
            entry.available_time = new_available_time
            entry.actual_time = new_actual_time
            entry.notes = request.form['notes']
            
            db.session.commit()
            flash('Entry updated successfully!')
            return redirect(url_for('dashboard'))
            
        except (ValueError, TypeError):
            flash('Invalid input values')
            return render_template('edit_entry.html', entry=entry)
    
    return render_template('edit_entry.html', entry=entry)

@app.route('/delete_entry/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entry = TimeEntry.query.get_or_404(entry_id)
    
    # Ensure users can only delete their own entries
    if entry.user_id != current_user.id:
        flash('You do not have permission to delete this entry.')
        return redirect(url_for('dashboard'))
    
    db.session.delete(entry)
    db.session.commit()
    flash('Entry deleted successfully.')
    return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Verify current password
    if not check_password_hash(current_user.password_hash, current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('profile'))
    
    # Verify new password matches confirmation
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('profile'))
    
    # Validate new password
    is_valid, message = validate_password(new_password)
    if not is_valid:
        flash(f'Password validation failed: {message}', 'error')
        return redirect(url_for('profile'))
    
    # Update password
    current_user.set_password(new_password)
    db.session.commit()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    
    # Check if this is the original admin account
    is_original_admin = current_user.id == 1 and current_user.is_admin
    if is_original_admin:
        flash('The original admin account cannot be deleted.', 'error')
        return redirect(url_for('profile'))
    
    # Verify password
    if not check_password_hash(current_user.password_hash, password):
        flash('Incorrect password.', 'error')
        return redirect(url_for('profile'))
    
    # Delete all time entries for this user
    TimeEntry.query.filter_by(user_id=current_user.id).delete()
    
    # Delete the user account
    db.session.delete(current_user)
    db.session.commit()
    
    # Log the user out
    logout_user()
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('login'))

@app.route('/export_entries')
@login_required
def export_entries():
    # Get date range from query parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Query entries
    query = TimeEntry.query.filter_by(user_id=current_user.id).order_by(TimeEntry.date.desc())
    
    if start_date and end_date:
        try:
            start = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
            query = query.filter(TimeEntry.date.between(start, end))
        except ValueError:
            flash('Invalid date format')
            return redirect(url_for('dashboard'))
    
    entries = query.all()
    
    # Create CSV in memory
    si = StringIO()
    cw = csv.writer(si)
    
    # Write headers
    cw.writerow(['Date', 'Available Time (hours)', 'Actual Time (hours)', 'Utilization Rate (%)', 'Notes'])
    
    # Write data
    for entry in entries:
        utilization = (entry.actual_time / entry.available_time * 100) if entry.available_time > 0 else 0
        cw.writerow([
            entry.date.strftime('%Y-%m-%d'),
            entry.available_time,
            entry.actual_time,
            f"{utilization:.1f}",
            entry.notes or ''
        ])
    
    output = si.getvalue()
    si.close()
    
    # Create response
    filename = f"time_entries_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename={filename}'
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
