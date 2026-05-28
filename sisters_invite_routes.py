"""
sisters_invite_routes.py — Routes to add to sisters_web.py

Paste these into sisters_web.py:
  1. Add to imports at the top
  2. Add the updated register() route (replaces existing one)
  3. Add the four invite routes at the bottom

Also shows the updated sisters_web.py import block.
"""

# ── ADD TO IMPORTS IN sisters_web.py ─────────────────────────────────────────
"""
from sisters_invites import (
    init_invite_tables,
    generate_invite_code,
    revoke_invite_code,
    get_my_codes,
    get_my_invite_tree,
    validate_and_use_invite_code,
    set_founder,
    FOUNDER_USERNAME,
)
"""

# ── ADD TO create_app() IN sisters_web.py ────────────────────────────────────
"""
def create_app():
    init_db()
    init_invite_tables()

    # Auto-designate founder if env var is set
    if FOUNDER_USERNAME:
        set_founder(FOUNDER_USERNAME)

    _expiry_thread.start()
    print("[Sisters] Ready.")
    return app
"""


# ══════════════════════════════════════════════════════════════════════════════
# UPDATED REGISTER ROUTE — requires invite code
# Replace the existing register() route in sisters_web.py with this one
# ══════════════════════════════════════════════════════════════════════════════

UPDATED_REGISTER_ROUTE = """
@app.route("/sisters/api/register", methods=["POST"])
def register():
    ip = get_ip()
    if not check_rate(ip, "register"):
        return jsonify({"ok": False,
                        "error": "Too many registration attempts. Try again later."}), 429

    data = request.get_json(silent=True) or {}

    username     = clean_text(data.get("username", ""), 50).lower()
    email        = clean_text(data.get("email", ""), 255).lower()
    password     = data.get("password", "")
    display_name = clean_text(data.get("display_name", ""), 100)
    invite_code  = clean_text(data.get("invite_code", ""), 20).upper().strip()

    # Validate fields
    if not username or len(username) < 3:
        return jsonify({"ok": False,
                        "error": "Username must be at least 3 characters."}), 400
    if not re.match(r'^[a-zA-Z0-9_\\-]{3,50}$', username):
        return jsonify({"ok": False,
                        "error": "Username: letters, numbers, underscores, hyphens only."}), 400
    if not valid_email(email):
        return jsonify({"ok": False, "error": "Invalid email address."}), 400
    if not password or len(password) < 8:
        return jsonify({"ok": False,
                        "error": "Password must be at least 8 characters."}), 400
    if len(password) > 128:
        return jsonify({"ok": False, "error": "Password is too long."}), 400
    if not invite_code:
        return jsonify({"ok": False,
                        "error": "An invite code is required to join Sisters of Medusa."}), 400

    session = get_session()
    try:
        if session.query(Sister).filter(Sister.username == username).first():
            return jsonify({"ok": False,
                            "error": "That username is already taken."}), 409
        if session.query(Sister).filter(Sister.email == email).first():
            return jsonify({"ok": False,
                            "error": "An account with that email already exists."}), 409

        # Create the sister account first (need ID for invite validation)
        sister = Sister(
            username           = username,
            email              = email,
            password_hash      = pwd_context.hash(password),
            display_name       = display_name or username,
            is_email_verified  = True,   # Trust-based: invite = verification
            is_network_active  = True,
            verification_token = None,
        )
        session.add(sister)
        session.flush()  # Get the ID without committing

        # Validate and consume the invite code
        invite_result = validate_and_use_invite_code(
            invite_code, sister.id, session
        )

        if not invite_result["ok"]:
            session.rollback()
            return jsonify({"ok": False, "error": invite_result["error"]}), 400

        session.commit()
        session.refresh(sister)

        token = make_token(sister.id, sister.username)
        return jsonify({
            "ok":           True,
            "token":        token,
            "username":     sister.username,
            "display_name": sister.display_name,
            "message":      "Welcome to Sisters of Medusa. You are now part of the network."
        }), 201

    except Exception as e:
        session.rollback()
        print(f"[Sisters] register error: {e}")
        return jsonify({"ok": False,
                        "error": "Registration failed. Please try again."}), 500
    finally:
        session.close()
"""


# ══════════════════════════════════════════════════════════════════════════════
# INVITE ROUTES — add these to sisters_web.py
# ══════════════════════════════════════════════════════════════════════════════

INVITE_ROUTES = """
# ── Invite Code Routes ────────────────────────────────────────────────────────

@app.route("/sisters/api/invite/generate", methods=["POST"])
@require_auth
def invite_generate(sister):
    result = generate_invite_code(sister.id)
    return jsonify(result), (201 if result["ok"] else 429)


@app.route("/sisters/api/invite/revoke", methods=["POST"])
@require_auth
def invite_revoke(sister):
    data = request.get_json(silent=True) or {}
    code = clean_text(data.get("code", ""), 20).upper().strip()
    if not code:
        return jsonify({"ok": False, "error": "code required."}), 400
    result = revoke_invite_code(code, sister.id)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/sisters/api/invite/mine", methods=["GET"])
@require_auth
def invite_mine(sister):
    result = get_my_codes(sister.id)
    return jsonify(result), (200 if result["ok"] else 500)


@app.route("/sisters/api/invite/tree", methods=["GET"])
@require_auth
def invite_tree(sister):
    result = get_my_invite_tree(sister.id)
    return jsonify(result), (200 if result["ok"] else 500)


# ── Founder admin routes ──────────────────────────────────────────────────────
# Protected by FOUNDER_SECRET env var — not tied to a user account
# so it can be called before the founder has registered

@app.route("/sisters/api/admin/set-founder", methods=["POST"])
def admin_set_founder():
    secret = os.environ.get("FOUNDER_SECRET", "")
    if not secret:
        return jsonify({"ok": False, "error": "Not configured."}), 403

    data = request.get_json(silent=True) or {}
    if data.get("secret") != secret:
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    username = clean_text(data.get("username", ""), 50)
    if not username:
        return jsonify({"ok": False, "error": "username required."}), 400

    result = set_founder(username)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/sisters/api/admin/set-circle", methods=["POST"])
def admin_set_circle():
    secret = os.environ.get("FOUNDER_SECRET", "")
    if not secret:
        return jsonify({"ok": False, "error": "Not configured."}), 403

    data = request.get_json(silent=True) or {}
    if data.get("secret") != secret:
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    username = clean_text(data.get("username", ""), 50)
    if not username:
        return jsonify({"ok": False, "error": "username required."}), 400

    from sisters_invites import set_circle
    result = set_circle(username)
    return jsonify(result), (200 if result["ok"] else 400)
"""
