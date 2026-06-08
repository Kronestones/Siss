"""
sisters_admin.py — Siss Admin Routes

Add these routes to sisters_web.py by importing and registering this blueprint,
or paste the routes directly into sisters_web.py.

Admin endpoints:
  POST /sisters/api/admin/remove_user   → Remove a user by username
  POST /sisters/api/admin/restore_user  → Restore a removed user
  GET  /sisters/api/admin/users         → List all users (paginated)

Protected by ADMIN_KEY environment variable.
Never expose this key. Store only in Render environment variables.

Founded by T.L. Powers · Siss · 2026
"""

import os
from datetime import datetime, timezone
from flask import jsonify, request
from sisters_database import get_session, Sister

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def check_admin(req) -> bool:
    """Verify the admin key from Authorization header or X-Admin-Key header."""
    if not ADMIN_KEY:
        return False
    # Accept either Authorization: Bearer <key> or X-Admin-Key: <key>
    auth = req.headers.get("Authorization", "")
    xkey = req.headers.get("X-Admin-Key", "")
    token = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer ") else xkey.strip()
    return token == ADMIN_KEY


def register_admin_routes(app):
    """Call this in sisters_web.py: register_admin_routes(app)"""

    # ── Remove a user ────────────────────────────────────────────────────────

    @app.route("/sisters/api/admin/remove_user", methods=["POST"])
    def admin_remove_user():
        if not check_admin(request):
            return jsonify({"ok": False, "error": "Unauthorized."}), 401

        data     = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip().lower()
        reason   = (data.get("reason") or "No reason provided.").strip()[:500]

        if not username:
            return jsonify({"ok": False, "error": "username required."}), 400

        session = get_session()
        try:
            sister = session.query(Sister).filter(
                Sister.username == username
            ).first()

            if not sister:
                return jsonify({"ok": False, "error": "User not found."}), 404

            if sister.is_admin:
                return jsonify({"ok": False, "error": "Cannot remove an admin account."}), 403

            sister.is_suspended  = True
            sister.is_active     = False
            sister.suspended_at  = datetime.now(timezone.utc)
            sister.suspend_reason = reason
            session.commit()

            return jsonify({
                "ok":       True,
                "username": username,
                "removed":  True,
                "reason":   reason,
            })

        except Exception as e:
            session.rollback()
            print(f"[Siss Admin] remove_user error: {e}")
            return jsonify({"ok": False, "error": "Failed to remove user."}), 500
        finally:
            session.close()

    # ── Restore a user ───────────────────────────────────────────────────────

    @app.route("/sisters/api/admin/restore_user", methods=["POST"])
    def admin_restore_user():
        if not check_admin(request):
            return jsonify({"ok": False, "error": "Unauthorized."}), 401

        data     = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip().lower()

        if not username:
            return jsonify({"ok": False, "error": "username required."}), 400

        session = get_session()
        try:
            sister = session.query(Sister).filter(
                Sister.username == username
            ).first()

            if not sister:
                return jsonify({"ok": False, "error": "User not found."}), 404

            sister.is_suspended   = False
            sister.is_active      = True
            sister.suspended_at   = None
            sister.suspend_reason = None
            session.commit()

            return jsonify({"ok": True, "username": username, "restored": True})

        except Exception as e:
            session.rollback()
            return jsonify({"ok": False, "error": "Failed to restore user."}), 500
        finally:
            session.close()

    # ── List users ───────────────────────────────────────────────────────────

    @app.route("/sisters/api/admin/users", methods=["GET"])
    def admin_list_users():
        if not check_admin(request):
            return jsonify({"ok": False, "error": "Unauthorized."}), 401

        page     = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        offset   = (page - 1) * per_page

        session = get_session()
        try:
            total   = session.query(Sister).count()
            sisters = session.query(Sister).order_by(
                Sister.created_at.desc()
            ).offset(offset).limit(per_page).all()

            return jsonify({
                "ok":    True,
                "total": total,
                "page":  page,
                "users": [
                    {
                        "username":     s.username,
                        "display_name": s.display_name,
                        "is_active":    s.is_active,
                        "is_suspended": s.is_suspended,
                        "is_admin":     s.is_admin,
                        "joined_at":    s.created_at.isoformat(),
                        "last_active":  s.last_active.isoformat() if s.last_active else None,
                    }
                    for s in sisters
                ],
            })

        except Exception as e:
            return jsonify({"ok": False, "error": "Failed to list users."}), 500
        finally:
            session.close()
