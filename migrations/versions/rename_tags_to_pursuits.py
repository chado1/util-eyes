"""rename tags to pursuits

Revision ID: rename_tags_to_pursuits
Revises: 
Create Date: 2024-12-06 16:04:36.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'rename_tags_to_pursuits'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create new tables if they don't exist
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


def downgrade():
    op.drop_table('entry_pursuits')
    op.drop_table('pursuit')
