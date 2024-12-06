"""rename tags to pursuits

Revision ID: rename_tags_to_pursuits
Revises: 
Create Date: 2024-12-06 16:04:36.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import text


# revision identifiers, used by Alembic.
revision = 'rename_tags_to_pursuits'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create new tables
    op.create_table('pursuit',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('entry_pursuits',
        sa.Column('entry_id', sa.Integer(), nullable=False),
        sa.Column('pursuit_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['entry_id'], ['entry.id'], ),
        sa.ForeignKeyConstraint(['pursuit_id'], ['pursuit.id'], ),
        sa.PrimaryKeyConstraint('entry_id', 'pursuit_id')
    )

    # Get database connection
    connection = op.get_bind()

    # Check if old tables exist before attempting migration
    has_old_tables = connection.execute(text("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'tag'
        )
    """)).scalar()

    if has_old_tables:
        # Transfer data from tag to pursuit
        connection.execute(text("""
            INSERT INTO pursuit (id, name, user_id, created_at)
            SELECT id, name, user_id, created_at FROM tag
        """))

        # Transfer data from entry_tags to entry_pursuits
        connection.execute(text("""
            INSERT INTO entry_pursuits (entry_id, pursuit_id)
            SELECT entry_id, tag_id FROM entry_tags
        """))

        # Drop old tables only after successful data transfer
        op.drop_table('entry_tags')
        op.drop_table('tag')


def downgrade():
    # Create old tables
    op.create_table('tag',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_table('entry_tags',
        sa.Column('entry_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['entry_id'], ['entry.id'], ),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], ),
        sa.PrimaryKeyConstraint('entry_id', 'tag_id')
    )

    # Get database connection
    connection = op.get_bind()

    # Transfer data back from pursuit to tag
    connection.execute(text("""
        INSERT INTO tag (id, name, user_id, created_at)
        SELECT id, name, user_id, created_at FROM pursuit
    """))

    # Transfer data back from entry_pursuits to entry_tags
    connection.execute(text("""
        INSERT INTO entry_tags (entry_id, tag_id)
        SELECT entry_id, pursuit_id FROM entry_pursuits
    """))

    # Drop new tables
    op.drop_table('entry_pursuits')
    op.drop_table('pursuit')
