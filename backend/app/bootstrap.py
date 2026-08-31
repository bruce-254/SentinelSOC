"""First-run bootstrap: create the default organisation, admin user, a couple
of sample assets, and seed the detection rules.

Only runs when the database is empty, so it is safe to restart. Controlled by
environment variables (see .env.example):

    DEFAULT_ORG_NAME     default "Default Organization"
    DEFAULT_ADMIN_USER   default "admin"
    DEFAULT_ADMIN_PASS   default "admin12345"
    DEFAULT_ADMIN_EMAIL  default "admin@sentinelsoc.local"
"""
from __future__ import annotations

import os

from sqlalchemy.orm import Session

from .core.logging import logger
from .models import Asset, Organization, User
from .pipeline.detection import seed_rules
from .security import hash_password


def bootstrap(db: Session) -> bool:
    """Create defaults if absent. Returns True if anything was created."""
    changed = False
    org_name = os.getenv("DEFAULT_ORG_NAME", "Default Organization")

    org = db.query(Organization).filter(Organization.slug == "default").first()
    if org is None:
        org = Organization(name=org_name, slug="default")
        db.add(org)
        db.flush()
        changed = True
        logger.info("bootstrapped organization %s", org_name)

    admin_user = os.getenv("DEFAULT_ADMIN_USER", "admin")
    admin_pass = os.getenv("DEFAULT_ADMIN_PASS", "admin12345")
    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@sentinelsoc.local")
    if not db.query(User).filter(User.username == admin_user).first():
        db.add(User(
            organization_id=org.id,
            username=admin_user,
            email=admin_email,
            password_hash=hash_password(admin_pass),
            role="admin",
        ))
        changed = True
        logger.info("bootstrapped admin user '%s'", admin_user)

    # A couple of example assets so risk scoring / dashboards have something to
    # enrich against out of the box.
    if db.query(Asset).filter(Asset.organization_id == org.id).count() == 0:
        db.add_all([
            Asset(organization_id=org.id, name="Web Server 01", ip_address="10.0.0.10",
                  hostname="web01", os="Ubuntu 22.04", criticality="high",
                  tags=["web", "dmz"]),
            Asset(organization_id=org.id, name="Domain Controller", ip_address="10.0.0.5",
                  hostname="dc01", os="Windows Server 2019", criticality="critical",
                  tags=["identity", "ad"]),
            Asset(organization_id=org.id, name="Workstation - HR", ip_address="10.0.1.42",
                  hostname="hr-001", os="Windows 11", criticality="medium",
                  tags=["workstation"]),
        ])
        changed = True

    seeded = seed_rules(db, org.id)
    if seeded:
        changed = True
        logger.info("seeded %d detection rules", seeded)

    if changed:
        db.commit()
    return changed
