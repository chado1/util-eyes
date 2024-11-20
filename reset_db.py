from app import app, db

with app.app_context():
    # This will drop all tables
    db.drop_all()
    
    # This will recreate all tables
    db.create_all()
    
    print("Database has been reset successfully!")
