# Util-Eyes Time Tracking Application

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A simple web application for tracking personal time utilization with authentication and security features.

## Features

- Secure user authentication with password policy enforcement
- Role-based access control (Admin and Regular users)
- Time tracking with utilization rates
- Admin dashboard with data visualization
  * Daily utilization chart
  * Daily entries chart
  * Interactive dual y-axis support
- Rate limiting for login attempts
- Environment-specific configurations
- Database flexibility (SQLite/PostgreSQL support)

## Setup

1. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root:
```
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///timejournal.db  # For SQLite
# For PostgreSQL use: DATABASE_URL=postgresql://user:password@host:port/dbname
```

4. Run the application:
```bash
python3 app.py
```

The application will automatically:
- Initialize the database
- Create required tables
- Create an initial admin user if none exists

## Default Admin Account

On first run, an admin account is created with these credentials:
- Username: admin
- Password: AdminPass123!

## Password Requirements

New user passwords must:
- Be at least 8 characters long
- Contain at least one uppercase letter
- Contain at least one lowercase letter
- Contain at least one number
- Contain at least one special character (!@#$%^&*)

## Database Configuration

### SQLite (Default Development Database)
The application uses SQLite by default for development. The database file (timejournal.db) is created automatically in the instance folder when the application starts.

### PostgreSQL (Production Database)
For production deployments, PostgreSQL is recommended. To migrate from SQLite to PostgreSQL:

1. Ensure PostgreSQL is installed and running
2. Set up PostgreSQL environment variables:
```bash
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password
POSTGRES_HOST=your_host
POSTGRES_PORT=5432
```

3. Run the migration script:
```bash
python3 production_migration.py
```

The migration script will:
- Create a new PostgreSQL database
- Migrate all users and time entries
- Verify data integrity
- Generate detailed migration logs

## Deployment

### Fly.io Deployment
The application is configured for deployment on Fly.io:

1. Install the Fly.io CLI
2. Configure PostgreSQL database
3. Deploy the application:
```bash
fly deploy
```

Environment variables are configured in `fly.toml` and through Fly.io secrets.

## Development

### Testing
Run the test suite:
```bash
pytest test_app.py -v
```

## Security Features

- Password hashing using Werkzeug's security functions
- Rate limiting on login attempts
- Security headers for production environment
- CSRF protection
- Role-based access control
- Input validation and sanitization

## Environment Configuration

The application supports different configurations for development and production environments:
- Development: Debug mode enabled, detailed error messages
- Production: Security headers enabled, minimal error information exposed

## Project Structure

```
util-eyes/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── test_app.py        # Test suite
├── .env               # Environment configuration
├── production_migration.py  # PostgreSQL migration script
└── timejournal.db     # SQLite database (auto-generated)
```

## Future Enhancements

- Multi-factor authentication
- Password recovery
- Advanced time tracking analytics
- External authentication providers
- More comprehensive logging
