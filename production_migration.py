import os
import sqlite3
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), f'migration_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_postgres_connection(dbname='postgres'):
    """Get a connection to PostgreSQL with error handling"""
    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=os.getenv('POSTGRES_USER', 'postgres'),
            password=os.getenv('POSTGRES_PASSWORD', ''),
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            port=os.getenv('POSTGRES_PORT', '5432')
        )
        return conn
    except Exception as e:
        logging.error(f"Failed to connect to PostgreSQL: {e}")
        raise

def setup_postgres_schema(conn):
    """Create the PostgreSQL schema"""
    cur = conn.cursor()
    try:
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
        logging.info("PostgreSQL schema created successfully")
    except Exception as e:
        conn.rollback()
        logging.error(f"Failed to create schema: {e}")
        raise
    finally:
        cur.close()

def migrate_data(sqlite_path, pg_conn):
    """Migrate data from SQLite to PostgreSQL"""
    try:
        sqlite_conn = sqlite3.connect(sqlite_path)
        sqlite_cur = sqlite_conn.cursor()
        pg_cur = pg_conn.cursor()

        # Migrate users
        sqlite_cur.execute('SELECT id, username, password_hash, is_admin FROM "user"')
        users = sqlite_cur.fetchall()
        
        for user in users:
            try:
                user_data = list(user)
                user_data[3] = bool(user_data[3]) if user_data[3] is not None else False
                
                pg_cur.execute('''
                    INSERT INTO "user" (id, username, password_hash, is_admin)
                    VALUES (%s, %s, %s, %s)
                ''', user_data)
                logging.info(f"Migrated user: {user_data[1]}")
            except Exception as e:
                logging.error(f"Failed to migrate user {user_data[1]}: {e}")
                raise

        # Migrate time entries
        sqlite_cur.execute('''
            SELECT id, date, available_time, actual_time, notes, user_id, created_at 
            FROM time_entry
        ''')
        entries = sqlite_cur.fetchall()
        
        for entry in entries:
            try:
                pg_cur.execute('''
                    INSERT INTO time_entry (id, date, available_time, actual_time, notes, user_id, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', entry)
                logging.info(f"Migrated time entry ID: {entry[0]}")
            except Exception as e:
                logging.error(f"Failed to migrate time entry {entry[0]}: {e}")
                raise

        # Update sequences
        pg_cur.execute("SELECT setval('user_id_seq', (SELECT MAX(id) FROM \"user\"))")
        pg_cur.execute("SELECT setval('time_entry_id_seq', (SELECT MAX(id) FROM time_entry))")
        
        pg_conn.commit()
        logging.info("Migration completed successfully")
        
    except Exception as e:
        pg_conn.rollback()
        logging.error(f"Migration failed: {e}")
        raise
    finally:
        if 'sqlite_cur' in locals():
            sqlite_cur.close()
        if 'sqlite_conn' in locals():
            sqlite_conn.close()
        if 'pg_cur' in locals():
            pg_cur.close()

def verify_migration(sqlite_path, pg_conn):
    """Verify the migration was successful"""
    try:
        sqlite_conn = sqlite3.connect(sqlite_path)
        sqlite_cur = sqlite_conn.cursor()
        pg_cur = pg_conn.cursor()

        # Verify user count
        sqlite_cur.execute('SELECT COUNT(*) FROM "user"')
        sqlite_user_count = sqlite_cur.fetchone()[0]
        
        pg_cur.execute('SELECT COUNT(*) FROM "user"')
        pg_user_count = pg_cur.fetchone()[0]
        
        if sqlite_user_count != pg_user_count:
            raise ValueError(f"User count mismatch: SQLite={sqlite_user_count}, PostgreSQL={pg_user_count}")
        
        logging.info(f"Verified {pg_user_count} users migrated successfully")

        # Verify time entry count
        sqlite_cur.execute('SELECT COUNT(*) FROM time_entry')
        sqlite_entry_count = sqlite_cur.fetchone()[0]
        
        pg_cur.execute('SELECT COUNT(*) FROM time_entry')
        pg_entry_count = pg_cur.fetchone()[0]
        
        if sqlite_entry_count != pg_entry_count:
            raise ValueError(f"Entry count mismatch: SQLite={sqlite_entry_count}, PostgreSQL={pg_entry_count}")
        
        logging.info(f"Verified {pg_entry_count} time entries migrated successfully")

    except Exception as e:
        logging.error(f"Verification failed: {e}")
        raise
    finally:
        if 'sqlite_cur' in locals():
            sqlite_cur.close()
        if 'sqlite_conn' in locals():
            sqlite_conn.close()
        if 'pg_cur' in locals():
            pg_cur.close()

def main():
    sqlite_path = 'instance/timejournal.db'
    target_db = 'util_eyes_prod'
    
    logging.info("Starting migration process")
    
    try:
        # Create production database
        conn = get_postgres_connection()
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
        if cur.fetchone():
            logging.warning(f"Database {target_db} already exists")
            proceed = input(f"Database {target_db} already exists. Proceed with migration? (y/n): ")
            if proceed.lower() != 'y':
                logging.info("Migration cancelled by user")
                return
        else:
            cur.execute(f'CREATE DATABASE {target_db}')
            logging.info(f"Created database {target_db}")
        
        cur.close()
        conn.close()
        
        # Connect to the new database and perform migration
        conn = get_postgres_connection(target_db)
        setup_postgres_schema(conn)
        migrate_data(sqlite_path, conn)
        verify_migration(sqlite_path, conn)
        
        logging.info("Migration completed successfully")
        print("Migration completed successfully! Check the log file for details.")
        
    except Exception as e:
        logging.error(f"Migration failed: {e}")
        print(f"Migration failed. Check the log file for details.")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    main()
