# Util-Eyes Time Journal Application

A simple web application for tracking and analyzing time utilization. This Flask-based application helps users monitor their productivity by comparing available time against actual time spent on personal projects or other stuff you want to accomplish, providing insights into time management and efficiency.

## Features

### User Management
- User registration and authentication system
- Secure password hashing
- Role-based access control (Admin/Regular users)
- User profile management

### Time Tracking
- Log daily time entries with:
  - Available time allocation
  - Actual time spent
  - Date tracking
  - Detailed notes
- Edit and delete time entries
- Historical data viewing

### Analytics & Dashboard
- Overall time utilization metrics
- Productivity percentage calculations
- Paginated view of time entries
- Date range filtering
- Visual representation of time data

### Admin Features
- User management capabilities
- Admin dashboard for system overview
- Ability to create/modify/delete users
- Toggle admin privileges

## Technical Stack

- **Backend Framework**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login
- **Frontend**: 
  - HTML5
  - Bootstrap 5 for responsive design
  - JavaScript for interactivity
- **Security**: 
  - Password hashing with Werkzeug
  - CSRF protection
  - Session management

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd util-eyes
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python app.py
```

## Configuration

The application uses the following configuration:
- SQLite database (timejournal.db)
- Secret key for session management
- Configurable pagination settings
- Customizable time entry validation rules

## Usage Guide

1. **First Time Setup**:
   - Register an account (first user automatically becomes admin)
   - Login with your credentials

2. **Adding Time Entries**:
   - Navigate to the dashboard
   - Click "Add Entry"
   - Fill in the date, available time, actual time, and optional notes
   - Submit the entry

3. **Managing Entries**:
   - View entries on the dashboard
   - Edit or delete entries as needed
   - Filter entries by date range
   - Monitor your productivity metrics

4. **Admin Functions**:
   - Access admin dashboard
   - Manage user accounts
   - Toggle admin privileges
   - View system-wide statistics

## Development

To run the application in development mode:
```bash
python app.py
```
The application will be available at `http://localhost:5000`

## Production Deployment

For production deployment:
1. Configure your production database
2. Set up proper environment variables
3. Use gunicorn as the WSGI server:
```bash
gunicorn -c gunicorn.conf.py app:app
```

## Security Notes

- All passwords are hashed before storage
- Session management is implemented securely
- Input validation is performed on all forms
- CSRF protection is enabled

## License

[Specify your license here]

## Contributing

[Add contribution guidelines if applicable]
