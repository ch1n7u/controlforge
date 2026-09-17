"""add scope is_lab flag

Revision ID: eb38622b1796
Revises: 450bb749e3f0
Create Date: 2026-09-17 10:11:32.752933

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'eb38622b1796'
down_revision: Union[str, Sequence[str], None] = '450bb749e3f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Added with a server default so the migration is safe on a populated
    # table; the default is then dropped so the flag must be set explicitly.
    op.add_column(
        "scopes",
        sa.Column("is_lab", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("scopes", "is_lab", server_default=None)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scopes", "is_lab")
