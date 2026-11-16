"""Phase 6 security_frameworks metadata enrichment (release_date and description).

Revision ID: 0002_phase6_framework_metadata
Revises: 0001_initial_schema
Create Date: 2026-04-06 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_phase6_framework_metadata"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("security_frameworks") as batch_op:
        batch_op.add_column(
            sa.Column(
                "release_date",
                sa.String(length=40),
                server_default="",
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "description",
                sa.Text(),
                server_default="",
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("security_frameworks") as batch_op:
        batch_op.drop_column("description")
        batch_op.drop_column("release_date")
