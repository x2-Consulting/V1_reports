"""
Startup schema migrations.

SQLAlchemy's create_all() creates missing tables but never alters existing ones.
This module handles ADD COLUMN migrations for the multi-tenancy rearchitect and
seeds the default organisation on first run.

Run order: called once from app.py lifespan, after create_all().
"""

from __future__ import annotations

import logging
import re

def _safe_ident(s: str) -> str:
    """Assert that a string is a safe SQL identifier (letters, digits, underscores only)."""
    if not re.match(r'^[a-zA-Z0-9_]+$', s):
        raise ValueError(f"Unsafe SQL identifier: {s!r}")
    return s

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

_log = logging.getLogger("tv1.migrations")


def _column_exists(engine: Engine, table: str, column: str) -> bool:
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT COUNT(*) FROM information_schema.columns "
                 "WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c"),
            {"t": table, "c": column},
        )
        return (result.scalar() or 0) > 0


def _add_column_if_missing(engine: Engine, table: str, column: str, definition: str) -> None:
    t = _safe_ident(table)
    c = _safe_ident(column)
    if not _column_exists(engine, table, column):
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE `{t}` ADD COLUMN `{c}` {definition}"))
        _log.info("Migration: added column %s.%s", table, column)


def run(engine: Engine, db: Session) -> None:
    """Apply all pending migrations and seed initial data."""

    # ── 1. New columns on existing tables ─────────────────────────────────────

    _add_column_if_missing(
        engine, "users", "is_superadmin",
        "TINYINT(1) NOT NULL DEFAULT 0"
    )
    _add_column_if_missing(
        engine, "users", "organisation_id",
        "INT NULL DEFAULT NULL"
    )
    _add_column_if_missing(
        engine, "customers", "organisation_id",
        "INT NULL DEFAULT NULL"
    )
    _add_column_if_missing(
        engine, "audit_log", "organisation_id",
        "INT NULL DEFAULT NULL"
    )
    _add_column_if_missing(
        engine, "reports", "report_data_json",
        "MEDIUMTEXT NULL DEFAULT NULL"
    )

    # ── 2. Foreign key constraints (best-effort — skip if FK already exists) ──

    def _fk_exists(table: str, fk_name: str) -> bool:
        with engine.connect() as conn:
            r = conn.execute(
                text("SELECT COUNT(*) FROM information_schema.table_constraints "
                     "WHERE table_schema = DATABASE() AND table_name = :t "
                     "AND constraint_name = :n AND constraint_type = 'FOREIGN KEY'"),
                {"t": table, "n": fk_name},
            )
            return (r.scalar() or 0) > 0

    _ALLOWED_ON_DELETE = frozenset({"SET NULL", "CASCADE", "RESTRICT", "NO ACTION"})

    fks = [
        ("users",     "fk_users_organisation",     "organisation_id", "organisations", "SET NULL"),
        ("customers", "fk_customers_organisation",  "organisation_id", "organisations", "CASCADE"),
        ("audit_log", "fk_audit_organisation",      "organisation_id", "organisations", "SET NULL"),
    ]
    for table, name, col, ref, on_del in fks:
        if on_del not in _ALLOWED_ON_DELETE:
            _log.error("Migration: invalid ON DELETE action %r — skipping FK %s", on_del, name)
            continue
        if not _fk_exists(table, name):
            try:
                t = _safe_ident(table)
                n = _safe_ident(name)
                c = _safe_ident(col)
                r = _safe_ident(ref)
                with engine.begin() as conn:
                    conn.execute(text(
                        f"ALTER TABLE `{t}` ADD CONSTRAINT `{n}` "
                        f"FOREIGN KEY (`{c}`) REFERENCES `{r}`(`id`) ON DELETE {on_del}"
                    ))
                _log.info("Migration: added FK %s on %s.%s", name, table, col)
            except Exception as exc:
                _log.warning("Migration: could not add FK %s — %s (non-fatal)", name, exc)

    # ── 3. Seed default organisation if none exist ────────────────────────────

    from models import Organisation, User, Customer

    if db.query(Organisation).count() == 0:
        default_org = Organisation(name="Default Organisation", slug="default")
        db.add(default_org)
        db.flush()
        _log.info("Migration: created default organisation (id=%d)", default_org.id)
    else:
        default_org = db.query(Organisation).order_by(Organisation.id).first()

    # ── 4. Assign existing users without an org to the default org ────────────

    unassigned_users = db.query(User).filter(User.organisation_id.is_(None)).all()
    for u in unassigned_users:
        u.organisation_id = default_org.id
    if unassigned_users:
        _log.info("Migration: assigned %d user(s) to default org", len(unassigned_users))

    # ── 5. Assign existing customers without an org to the default org ────────

    unassigned_customers = db.query(Customer).filter(Customer.organisation_id.is_(None)).all()
    for c in unassigned_customers:
        c.organisation_id = default_org.id
    if unassigned_customers:
        _log.info("Migration: assigned %d customer(s) to default org", len(unassigned_customers))

    # ── 6. Promote the first admin user to superadmin if no superadmin exists ─

    if db.query(User).filter(User.is_superadmin == True).count() == 0:
        first_admin = db.query(User).filter(User.is_admin == True).order_by(User.id).first()
        if first_admin:
            first_admin.is_superadmin = True
            _log.info("Migration: promoted '%s' to superadmin", first_admin.username)

    db.commit()
    _log.info("Migrations complete.")
