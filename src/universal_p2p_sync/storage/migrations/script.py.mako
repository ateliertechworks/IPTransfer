"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import context, op

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = None
depends_on = None


def upgrade() -> None:
    schema = context.config.attributes["schema"]
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    schema = context.config.attributes["schema"]
    ${downgrades if downgrades else "pass"}
