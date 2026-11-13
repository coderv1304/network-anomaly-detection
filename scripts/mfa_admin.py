"""Break-glass MFA administration for local accounts.

Normal enrollment happens through ``POST /api/me/mfa/enroll`` while signed in.
This CLI exists for the operator case where an authenticator is lost and the
user cannot complete the web flow. It requires shell access to the host and the
same ``SECRET_KEY`` the application uses, so it is not a remote bypass.

Examples
--------
    python scripts/mfa_admin.py status --email analyst@example.com
    python scripts/mfa_admin.py enroll --email analyst@example.com
    python scripts/mfa_admin.py confirm --email analyst@example.com --code 123456
    python scripts/mfa_admin.py disable --email analyst@example.com --yes

``enroll`` prints the secret and recovery codes once. Store them in the
operator's password manager, not in shell history.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as app_module  # noqa: E402
import mfa as mfa_module  # noqa: E402


def _user(email: str):
    return app_module.User.query.filter_by(email=email.strip().lower()).first()


def _require_user(email: str):
    user = _user(email)
    if user is None:
        raise SystemExit(f"No user with email {email!r}")
    if (user.auth_source or "local") != "local":
        raise SystemExit(
            f"{email!r} authenticates via {user.auth_source!r}; MFA is managed by the identity provider"
        )
    return user


def _require_stable_key(allow_ephemeral: bool) -> None:
    if os.environ.get("SECRET_KEY"):
        return
    if allow_ephemeral:
        print(
            "WARNING: SECRET_KEY is unset. The enrollment will be encrypted with a "
            "process-local key and will not be readable by a later process.",
            file=sys.stderr,
        )
        return
    raise SystemExit(
        "SECRET_KEY is unset. Set the same SECRET_KEY the application uses, or pass "
        "--allow-ephemeral-key for a throwaway test."
    )


def command_status(user) -> int:
    remaining = len(mfa_module.load_recovery_hashes(user.mfa_recovery_hashes))
    print(f"email: {user.email}")
    print(f"role: {user.role}")
    print(f"mfa_enabled: {bool(user.totp_enabled)}")
    print(f"confirmed_at: {user.totp_confirmed_at.isoformat() if user.totp_confirmed_at else None}")
    print(f"recovery_codes_remaining: {remaining}")
    return 0


def command_enroll(user) -> int:
    if user.totp_enabled:
        raise SystemExit("MFA is already enabled. Disable it first.")
    secret = mfa_module.generate_secret()
    recovery_codes = mfa_module.generate_recovery_codes()
    user.totp_secret = mfa_module.encrypt_secret(secret, app_module.app.config["SECRET_KEY"])
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    user.mfa_recovery_hashes = mfa_module.hash_recovery_codes(recovery_codes)
    app_module.db.session.commit()
    app_module.record_audit(
        "auth.mfa.enroll",
        "user",
        user.id,
        detail={"stage": "pending_confirmation", "source": "cli"},
        tenant_id=user.tenant_id,
        actor="operator-cli",
        actor_role="operator",
        commit=True,
    )
    print(f"secret: {secret}")
    print(f"provisioning_uri: {mfa_module.provisioning_uri(secret, user.email)}")
    print("recovery_codes:")
    for code in recovery_codes:
        print(f"  {code}")
    print("MFA is pending until you run: confirm --email ... --code <current code>")
    return 0


def command_confirm(user, code: str) -> int:
    try:
        secret = mfa_module.decrypt_secret(user.totp_secret, app_module.app.config["SECRET_KEY"])
    except mfa_module.MfaError as exc:
        raise SystemExit(str(exc)) from exc
    matched_step = mfa_module.verify_code(secret, code)
    if matched_step is None:
        raise SystemExit("That code is not valid.")
    user.totp_enabled = True
    user.totp_confirmed_at = datetime.utcnow()
    user.totp_last_step = matched_step
    app_module.db.session.commit()
    app_module.record_audit(
        "auth.mfa.confirm",
        "user",
        user.id,
        detail={"stage": "enabled", "source": "cli"},
        tenant_id=user.tenant_id,
        actor="operator-cli",
        actor_role="operator",
        commit=True,
    )
    print("MFA enabled.")
    return 0


def command_disable(user) -> int:
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    user.mfa_recovery_hashes = None
    app_module.db.session.commit()
    app_module.record_audit(
        "auth.mfa.disable",
        "user",
        user.id,
        detail={"source": "cli"},
        tenant_id=user.tenant_id,
        actor="operator-cli",
        actor_role="operator",
        commit=True,
    )
    print("MFA disabled.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Show MFA state for an account")
    status.add_argument("--email", required=True)

    enroll = sub.add_parser("enroll", help="Start enrollment and print the secret once")
    enroll.add_argument("--email", required=True)
    enroll.add_argument("--allow-ephemeral-key", action="store_true")

    confirm = sub.add_parser("confirm", help="Confirm a pending enrollment with a code")
    confirm.add_argument("--email", required=True)
    confirm.add_argument("--code", required=True)
    confirm.add_argument("--allow-ephemeral-key", action="store_true")

    disable = sub.add_parser("disable", help="Remove MFA from an account")
    disable.add_argument("--email", required=True)
    disable.add_argument("--yes", action="store_true", help="Confirm the removal")
    disable.add_argument("--allow-ephemeral-key", action="store_true")

    args = parser.parse_args(argv)
    if args.command in {"enroll", "confirm", "disable"}:
        _require_stable_key(getattr(args, "allow_ephemeral_key", False))
    if args.command == "disable" and not args.yes:
        raise SystemExit("Refusing to disable MFA without --yes")

    with app_module.app.app_context():
        user = _require_user(args.email)
        if args.command == "status":
            return command_status(user)
        if args.command == "enroll":
            return command_enroll(user)
        if args.command == "confirm":
            return command_confirm(user, args.code)
        return command_disable(user)


if __name__ == "__main__":
    raise SystemExit(main())
