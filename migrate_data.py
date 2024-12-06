from app import app, db
from datetime import datetime
from sqlalchemy import text

def table_exists(table_name):
    result = db.session.execute(text("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name=:table_name
    """), {"table_name": table_name}).fetchone()
    return result is not None

def migrate_data():
    with app.app_context():
        tags_data = []
        tag_relationships = []
        
        # Get data from old tables if they exist
        if table_exists('tag'):
            tags_data = db.session.execute(text("""
                SELECT id, name, user_id, created_at FROM tag
            """)).fetchall()
            
        if table_exists('entry_tags'):
            tag_relationships = db.session.execute(text("""
                SELECT entry_id, tag_id FROM entry_tags
            """)).fetchall()
        
        # Drop the old tables if they exist
        if table_exists('entry_tags'):
            db.session.execute(text("DROP TABLE IF EXISTS entry_tags"))
        if table_exists('tag'):
            db.session.execute(text("DROP TABLE IF EXISTS tag"))
        db.session.commit()
        
        # Create new tables
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS pursuit (
                id INTEGER PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                user_id INTEGER NOT NULL,
                created_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES user(id)
            )
        """))
        
        db.session.execute(text("""
            CREATE TABLE IF NOT EXISTS entry_pursuits (
                entry_id INTEGER NOT NULL,
                pursuit_id INTEGER NOT NULL,
                PRIMARY KEY (entry_id, pursuit_id),
                FOREIGN KEY(entry_id) REFERENCES entry(id),
                FOREIGN KEY(pursuit_id) REFERENCES pursuit(id)
            )
        """))
        
        # Insert the data into new tables if we have any
        if tags_data:
            for tag in tags_data:
                db.session.execute(
                    text("INSERT INTO pursuit (id, name, user_id, created_at) VALUES (:id, :name, :user_id, :created_at)"),
                    {"id": tag[0], "name": tag[1], "user_id": tag[2], "created_at": tag[3] or datetime.utcnow()}
                )
        
        if tag_relationships:
            for rel in tag_relationships:
                db.session.execute(
                    text("INSERT INTO entry_pursuits (entry_id, pursuit_id) VALUES (:entry_id, :pursuit_id)"),
                    {"entry_id": rel[0], "pursuit_id": rel[1]}
                )
        
        db.session.commit()
        print("Migration completed successfully!")

if __name__ == '__main__':
    migrate_data()
