"""Idempotent seeding: the administrator account and platform defaults.

Run with ``python -m app.seed``. Safe to run repeatedly.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings
from app.core import audit
from app.core.security import generate_password, hash_password
from app.models.auth import User
from app.models.enums import Role

logger = logging.getLogger("valtros.seed")


def ensure_admin(db: OrmSession) -> tuple[User, str] | tuple[User, None]:
    """Create the first administrator if none exists.

    The password comes from the generated env file rather than being printed,
    so it never appears in terminal scrollback, logs or screenshots.
    """
    settings = get_settings()
    existing = db.execute(
        select(User).where(User.role == Role.ADMIN, User.is_active.is_(True))
    ).scalars().first()
    if existing is not None:
        return existing, None

    password = settings.admin_initial_password or generate_password()
    user = User(
        username=settings.seed_admin_username,
        role=Role.ADMIN,
        full_name="Valtros Administrator",
        password_hash=hash_password(password),
        must_change_password=True,
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        action="user.create",
        object_type="user",
        object_id=user.id,
        detail={"source": "bootstrap", "username": user.username, "role": "admin"},
    )
    logger.info("created administrator account %r", user.username)
    return user, password


def run_all(db: OrmSession) -> dict:
    """Bootstrap the platform. Settings are deliberately not seeded.

    A settings row written at boot would freeze the environment's value at
    install time, so the kill switch on the box could disagree with the kill
    switch in the UI. Until someone changes a setting, the effective value comes
    from :func:`app.schemas.settings.defaults`, which reads the environment.
    """
    settings = get_settings()
    admin, password = ensure_admin(db)
    lab: dict = {}
    if settings.autoseed:
        # The lab catalog only makes sense where the lab is; an operator who
        # switches autoseed off still gets the admin account and can build their
        # own controls.
        from app.seed.lab import seed_lab

        lab = seed_lab(db)
    db.commit()
    return {
        "admin_username": admin.username,
        "admin_created": password is not None,
        "lab": lab,
    }


def main() -> None:
    from app.db import SessionLocal, engine

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    with SessionLocal() as db:
        try:
            db.execute(text("SELECT 1 FROM users LIMIT 1"))
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(
                "database is not migrated; run 'alembic upgrade head' first"
            ) from exc
        result = run_all(db)
    engine.dispose()

    print(f"admin user      : {result['admin_username']}")
    print(f"admin created   : {result['admin_created']}")
    if lab := result.get("lab"):
        print(
            "lab catalog     : "
            f"{lab['controls']} controls, {lab['tests']} tests, "
            f"{lab['targets']} targets, {lab['scopes']} scopes"
        )
    if result["admin_created"]:
        print("initial password: stored in VALTROS_ADMIN_INITIAL_PASSWORD")
        print("                  (/etc/valtros/valtros.env, root:valtros 0640)")


if __name__ == "__main__":
    main()
