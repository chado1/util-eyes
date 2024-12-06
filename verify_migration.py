from app import app, db
from sqlalchemy import text

def verify_migration():
    with app.app_context():
        # Check table structure
        tables = db.session.execute(text("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('pursuit', 'entry_pursuits')
        """)).fetchall()
        
        print("=== Tables Present ===")
        for table in tables:
            print(f"✓ Found table: {table[0]}")
            
            # Get table structure
            columns = db.session.execute(text(f"""
                PRAGMA table_info({table[0]})
            """)).fetchall()
            print("\nColumns:")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
        
        print("\n=== Data Check ===")
        # Check pursuit data
        pursuits = db.session.execute(text("""
            SELECT id, name, user_id, created_at 
            FROM pursuit
        """)).fetchall()
        print(f"\nPursuits found: {len(pursuits)}")
        for pursuit in pursuits:
            print(f"  - ID: {pursuit[0]}, Name: {pursuit[1]}, User ID: {pursuit[2]}")
        
        # Check relationships
        relationships = db.session.execute(text("""
            SELECT entry_id, pursuit_id 
            FROM entry_pursuits
        """)).fetchall()
        print(f"\nEntry-Pursuit relationships found: {len(relationships)}")
        if relationships:
            print("Sample relationships:")
            for rel in relationships[:5]:  # Show first 5 relationships
                print(f"  - Entry {rel[0]} is tagged with Pursuit {rel[1]}")

if __name__ == '__main__':
    verify_migration()
