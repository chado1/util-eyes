import unittest
from app import app, db, User, TimeEntry
from datetime import datetime, date
from werkzeug.security import generate_password_hash
import json
import os

class TestUtilEyes(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        with app.app_context():
            db.drop_all()  # Drop all tables first
            db.create_all()
            
            # Create test admin user
            admin = User(
                username='admin',
                password_hash=generate_password_hash('AdminPass123!'),
                is_admin=True
            )
            db.session.add(admin)
            
            # Create test regular user
            user = User(
                username='testuser',
                password_hash=generate_password_hash('TestPass123!'),
                is_admin=False
            )
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()
        # Remove test database file
        if os.path.exists('test.db'):
            os.remove('test.db')

    def test_index_redirect(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)

    def test_login_success(self):
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'dashboard', response.data)

    def test_login_failure(self):
        response = self.client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        self.assertIn(b'Invalid username or password', response.data)

    def test_register_success(self):
        response = self.client.post('/register', data={
            'username': 'newuser',
            'password': 'NewPass123!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'dashboard', response.data)

    def test_register_weak_password(self):
        response = self.client.post('/register', data={
            'username': 'newuser',
            'password': 'weak'
        }, follow_redirects=True)
        self.assertIn(b'Password must be at least 8 characters long', response.data)

    def test_add_time_entry(self):
        # Login first
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        # Add time entry
        response = self.client.post('/add_entry', data={
            'date': '2024-02-20',
            'available_time': '8',
            'actual_time': '6',
            'notes': 'Test entry'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify entry was added
        with app.app_context():
            entry = TimeEntry.query.filter_by(user_id=2).first()  # testuser's ID is 2
            self.assertIsNotNone(entry)
            self.assertEqual(entry.available_time, 8.0)
            self.assertEqual(entry.actual_time, 6.0)
            self.assertEqual(entry.notes, 'Test entry')

    def test_edit_time_entry(self):
        # Login and create entry first
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        with app.app_context():
            entry = TimeEntry(
                date=date(2024, 2, 20),
                available_time=8.0,
                actual_time=6.0,
                notes='Original entry',
                user_id=2  # testuser's ID
            )
            db.session.add(entry)
            db.session.commit()
            entry_id = entry.id

        # Edit the entry
        response = self.client.post(f'/edit_entry/{entry_id}', data={
            'date': '2024-02-20',
            'available_time': '7',
            'actual_time': '5',
            'notes': 'Updated entry'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify entry was updated
        with app.app_context():
            updated_entry = TimeEntry.query.get(entry_id)
            self.assertEqual(updated_entry.available_time, 7.0)
            self.assertEqual(updated_entry.actual_time, 5.0)
            self.assertEqual(updated_entry.notes, 'Updated entry')

    def test_delete_time_entry(self):
        # Login and create entry first
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        with app.app_context():
            entry = TimeEntry(
                date=date(2024, 2, 20),
                available_time=8.0,
                actual_time=6.0,
                notes='Entry to delete',
                user_id=2  # testuser's ID
            )
            db.session.add(entry)
            db.session.commit()
            entry_id = entry.id

        # Delete the entry
        response = self.client.post(f'/delete_entry/{entry_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify entry was deleted
        with app.app_context():
            deleted_entry = TimeEntry.query.get(entry_id)
            self.assertIsNone(deleted_entry)

    def test_admin_dashboard_access(self):
        # Login as admin
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        })
        
        response = self.client.get('/admin')
        self.assertEqual(response.status_code, 200)

    def test_admin_create_user(self):
        # Login as admin
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'AdminPass123!'
        })
        
        response = self.client.post('/admin/create_user', data={
            'username': 'newuser2',
            'password': 'NewPass123!'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify user was created
        with app.app_context():
            new_user = User.query.filter_by(username='newuser2').first()
            self.assertIsNotNone(new_user)
            self.assertFalse(new_user.is_admin)

    def test_non_admin_dashboard_access(self):
        # Login as regular user
        self.client.post('/login', data={
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        response = self.client.get('/admin')
        self.assertEqual(response.status_code, 302)  # Should redirect
        self.assertIn('dashboard', response.location)

if __name__ == '__main__':
    unittest.main()
