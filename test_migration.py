import os
import sqlite3
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime

def create_postgres_db():
    # Connect to default postgres database first
    conn = psycopg2.connect(
        dbname='postgres',
        user='postgres',
        password='',
        host='localhost'
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    
    # Create new database
    try:
        cur.execute('DROP DATABASE IF EXISTS util_eyes_test')
        cur.execute('CREATE DATABASE util_eyes_test')
        print("Created test database successfully!")
    except Exception as e:
        print(f"Error creating database: {e}")
    finally:
        cur.close()
        conn.close()

def setup_postgres_schema(conn):
    cur = conn.cursor()
    
    # Create tables
    cur.execute('''
        CREATE TABLE IF NOT EXISTS "user" (
            id SERIAL PRIMARY KEY,
            username VARCHAR(80) UNIQUE NOT NULL,
            password_hash VARCHAR(120) NOT NULL,
            is_admin BOOLEAN
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS time_entry (
            id SERIAL PRIMARY KEY,
            date DATE NOT NULL,
            available_time FLOAT NOT NULL,
            actual_time FLOAT NOT NULL,
            notes TEXT,
            user_id INTEGER NOT NULL REFERENCES "user"(id),
            created_at TIMESTAMP
        )
    ''')
    
    conn.commit()
    cur.close()

def migrate_data():
    # Connect to SQLite
    sqlite_conn = sqlite3.connect('instance/timejournal.db')
    sqlite_cur = sqlite_conn.cursor()
    
    # Connect to PostgreSQL
    pg_conn = psycopg2.connect(
        dbname='util_eyes_test',
        user='postgres',
        password='',
        host='localhost'
    )
    setup_postgres_schema(pg_conn)
    pg_cur = pg_conn.cursor()
    
    try:
        # Migrate users
        sqlite_cur.execute('SELECT id, username, password_hash, is_admin FROM "user"')
        users = sqlite_cur.fetchall()
        
        for user in users:
            # Convert SQLite integer to PostgreSQL boolean
            user_data = list(user)
            user_data[3] = bool(user_data[3]) if user_data[3] is not None else False
            
            pg_cur.execute('''
                INSERT INTO "user" (id, username, password_hash, is_admin)
                VALUES (%s, %s, %s, %s)
            ''', user_data)
        
        print(f"Migrated {len(users)} users")
        
        # Migrate time entries
        sqlite_cur.execute('''
            SELECT id, date, available_time, actual_time, notes, user_id, created_at 
            FROM time_entry
        ''')
        entries = sqlite_cur.fetchall()
        
        for entry in entries:
            pg_cur.execute('''
                INSERT INTO time_entry (id, date, available_time, actual_time, notes, user_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', entry)
        
        print(f"Migrated {len(entries)} time entries")
        
        # Commit the transaction
        pg_conn.commit()
        print("Migration completed successfully!")
        
    except Exception as e:
        pg_conn.rollback()
        print(f"Error during migration: {e}")
    
    finally:
        sqlite_cur.close()
        sqlite_conn.close()
        pg_cur.close()
        pg_conn.close()

def verify_migration():
    # Connect to both databases
    sqlite_conn = sqlite3.connect('instance/timejournal.db')
    sqlite_cur = sqlite_conn.cursor()
    
    pg_conn = psycopg2.connect(
        dbname='util_eyes_test',
        user='postgres',
        password='',
        host='localhost'
    )
    pg_cur = pg_conn.cursor()
    
    try:
        # Check user counts
        sqlite_cur.execute('SELECT COUNT(*) FROM "user"')
        sqlite_user_count = sqlite_cur.fetchone()[0]
        
        pg_cur.execute('SELECT COUNT(*) FROM "user"')
        pg_user_count = pg_cur.fetchone()[0]
        
        print(f"\nVerification Results:")
        print(f"Users: SQLite={sqlite_user_count}, PostgreSQL={pg_user_count}")
        
        # Check time entry counts
        sqlite_cur.execute('SELECT COUNT(*) FROM time_entry')
        sqlite_entry_count = sqlite_cur.fetchone()[0]
        
        pg_cur.execute('SELECT COUNT(*) FROM time_entry')
        pg_entry_count = pg_cur.fetchone()[0]
        
        print(f"Time Entries: SQLite={sqlite_entry_count}, PostgreSQL={pg_entry_count}")
        
        # Sample some data for manual verification
        pg_cur.execute('SELECT username, is_admin FROM "user" LIMIT 3')
        sample_users = pg_cur.fetchall()
        print("\nSample migrated users:")
        for user in sample_users:
            print(f"Username: {user[0]}, Is Admin: {user[1]}")
        
    finally:
        sqlite_cur.close()
        sqlite_conn.close()
        pg_cur.close()
        pg_conn.close()

if __name__ == '__main__':
    print("Starting test migration process...")
    create_postgres_db()
    migrate_data()
    verify_migration()
