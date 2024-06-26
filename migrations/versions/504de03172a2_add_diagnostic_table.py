"""Add diagnostic table

Revision ID: 504de03172a2
Revises: 0175eb528c48
Create Date: 2024-06-22 09:08:28.851681

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '504de03172a2'
down_revision = '0175eb528c48'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('diagnostic',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('patient_id', sa.Integer(), nullable=False),
    sa.Column('ecg_data', sa.String(), nullable=False),
    sa.Column('diagnosis', sa.String(), nullable=True),
    sa.Column('requested_at', sa.DateTime(), nullable=False),
    sa.Column('responded_at', sa.DateTime(), nullable=True),
    sa.Column('doctor_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['doctor_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['patient_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('diagnostic')
    # ### end Alembic commands ###
