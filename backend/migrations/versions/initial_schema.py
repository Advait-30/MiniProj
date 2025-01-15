"""initial schema

Revision ID: 1a2b3c4d5e6f
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import UUIDType

def upgrade():
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('uuid', UUIDType(binary=False), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('email', sa.String(120), unique=True, nullable=False),
        sa.Column('password_hash', sa.String(256), nullable=False),
        sa.Column('pseudo_identity', sa.String(64), unique=True, nullable=False),
        sa.Column('signing_public_key', sa.Text(), nullable=False),
        sa.Column('exchange_public_key', sa.Text(), nullable=False),
        sa.Column('active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('last_login', sa.DateTime()),
        sa.PrimaryKeyConstraint('id')
    )

    # WBAN Data table
    op.create_table(
        'wban_data',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.String(64), nullable=False),
        sa.Column('data_type', sa.String(32), nullable=False),
        sa.Column('encrypted_data', sa.Text(), nullable=False),
        sa.Column('nonce', sa.String(24), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('session_id', sa.String(64), nullable=False),
        sa.Column('data_category', sa.String(32)),
        sa.Column('anonymized_location', sa.String(32)),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    ) 