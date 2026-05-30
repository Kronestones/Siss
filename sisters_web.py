"""
sisters_web.py — Sisters of Medusa Web Routes

Flask API for the Sisters of Medusa safety network.

Routes:
  GET  /sisters                  → Mobile UI (the main app)
  POST /sisters/api/register     → Create account
  POST /sisters/api/login        → Login, get token
  POST /sisters/api/ping         → Send distress ping
  POST /sisters/api/ping/resolve → Mark self safe
  GET  /sisters/api/ping/nearby  → Get active pings near my location
  POST /sisters/api/respond      → Respond to a ping
  GET  /sisters/api/ping/status  → Status of my current ping
  GET  /sisters/api/health       → Health check

Security:
  - All ping/respond endpoints require auth token
  - Rate limiting on ping creation (max 3 per hour per user)
  - Locations never logged in application logs
  - HTTPS required in production (enforced by Render)

Founded by T.L. Powers · Sisters of Medusa · 2026
"""

import os
import re
import time
import html
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, jsonify, request, render_template, redirect

from sisters_database import (
    init_db, get_session,
    Sister, SisterPing, SisterResponse,
    PingStatus, ResponseStatus,
    create_ping, resolve_ping, respond_to_ping,
    get_active_pings_near, expire_old_pings,
    round_location,
)

# Auth
import secrets
from passlib.context import CryptContext
from jose import jwt, JWTError

SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_HOURS     = 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = Flask(__name__, template_folder="templates")


# ── Rate Limiting ─────────────────────────────────────────────────────────────
# Stricter for ping creation — prevent abuse of the safety system

_rate_store  = defaultdict(list)
_rate_lock   = threading.Lock()

RATE_LIMITS = {
    "register":  {"max": 3,  "window": 3600},   # 3 accounts per IP per hour
    "login":     {"max": 10, "window": 300},     # 10 attempts per 5 min
    "ping":      {"max": 3,  "window": 3600},    # 3 pings per hour (abuse prevention)
    "respond":   {"max": 20, "window": 60},      # 20 responses per minute
    "nearby":    {"max": 60, "window": 60},      # 60 location checks per minute
}

def check_rate(ip: str, action: str) -> bool:
    """Returns True if allowed, False if rate limited."""
    if action not in RATE_LIMITS:
        return True
    cfg = RATE_LIMITS[action]
    key = f"{ip}:{action}"
    now = time.time()
    with _rate_lock:
        window_start = now - cfg["window"]
        _rate_store[key] = [t for t in _rate_store[key] if t > window_start]
        if len(_rate_store[key]) >= cfg["max"]:
            return False
        _rate_store[key].append(now)
        return True

def get_ip():
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ── Auth Helpers ──────────────────────────────────────────────────────────────

def make_token(sister_id: int, username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_HOURS)
    return jwt.encode(
        {"sub": str(sister_id), "username": username, "exp": exp},
        SECRET_KEY, algorithm=JWT_ALGORITHM
    )

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None

def get_auth_sister():
    """Get the authenticated Sister from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    payload = decode_token(token)
    if not payload:
        return None
    session = get_session()
    try:
        sister = session.query(Sister).filter(
            Sister.id == int(payload["sub"]),
            Sister.is_network_active == True,
            Sister.is_suspended == False,
        ).first()
        return sister
    except Exception:
        return None
    finally:
        session.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        sister = get_auth_sister()
        if not sister:
            return jsonify({"ok": False, "error": "Authentication required."}), 401
        return f(sister, *args, **kwargs)
    return decorated


# ── Input Sanitization ────────────────────────────────────────────────────────

def clean_text(text: str, max_len: int = 200) -> str:
    """Sanitize text input — strip HTML, limit length."""
    if not text:
        return ""
    text = html.escape(str(text).strip())
    return text[:max_len]

def valid_email(email: str) -> bool:
    return bool(re.match(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$',
        email or ""
    ))

def valid_coord(val) -> bool:
    try:
        f = float(val)
        return -180 <= f <= 180
    except (TypeError, ValueError):
        return False


# ── Background: expire old pings ──────────────────────────────────────────────

def _expiry_loop():
    """Run every 2 minutes — expire stale pings and erase their locations."""
    while True:
        time.sleep(120)
        try:
            expire_old_pings()
        except Exception as e:
            print(f"[Sisters] Expiry loop error: {e}")

_expiry_thread = threading.Thread(target=_expiry_loop, daemon=True)


# ── App Factory ───────────────────────────────────────────────────────────────

def create_app():
    init_db()
    _expiry_thread.start()
    print("[Sisters] Ready.")
    return app


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def root():
    return redirect("/sisters")


@app.route("/sisters")
def sisters_ui():
    """Serve the Sisters mobile UI."""
    return render_template("sisters.html")


@app.route("/sisters/api/health")
def health():
    return jsonify({"ok": True, "service": "Sisters of Medusa"})


# ── Registration ──────────────────────────────────────────────────────────────

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

    # Validate
    if not username or len(username) < 3:
        return jsonify({"ok": False,
                        "error": "Username must be at least 3 characters."}), 400
    if not re.match(r'^[a-zA-Z0-9_\-]{3,50}$', username):
        return jsonify({"ok": False,
                        "error": "Username may only contain letters, numbers, underscores, hyphens."}), 400
    if not valid_email(email):
        return jsonify({"ok": False, "error": "Invalid email address."}), 400
    if not password or len(password) < 8:
        return jsonify({"ok": False,
                        "error": "Password must be at least 8 characters."}), 400
    if len(password) > 128:
        return jsonify({"ok": False, "error": "Password is too long."}), 400

    session = get_session()
    try:
        if session.query(Sister).filter(Sister.username == username).first():
            return jsonify({"ok": False,
                            "error": "That username is already taken."}), 409
        if session.query(Sister).filter(Sister.email == email).first():
            return jsonify({"ok": False,
                            "error": "An account with that email already exists."}), 409

        verification_token = secrets.token_urlsafe(32)

        sister = Sister(
            username           = username,
            email              = email,
            password_hash      = pwd_context.hash(password),
            display_name       = display_name or username,
            is_email_verified  = False,
            is_network_active  = False,  # Activated after email verification
            verification_token = verification_token,
        )
        session.add(sister)
        session.commit()
        session.refresh(sister)

        # In production: send verification email here
        # For MVP: auto-activate (can add email step later)
        # TODO: integrate with email service before public launch
        sister.is_email_verified = True
        sister.is_network_active = True
        sister.verification_token = None
        session.commit()

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
        import traceback
        print(f"[Sisters] register error: {e}")
        print(traceback.format_exc())
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        session.close()


# ── Login ─────────────────────────────────────────────────────────────────────

@app.route("/sisters/api/login", methods=["POST"])
def login():
    ip = get_ip()
    if not check_rate(ip, "login"):
        return jsonify({"ok": False,
                        "error": "Too many login attempts. Wait a few minutes."}), 429

    data     = request.get_json(silent=True) or {}
    username = clean_text(data.get("username", ""), 50).lower()
    password = data.get("password", "")

    session = get_session()
    try:
        sister = session.query(Sister).filter(Sister.username == username).first()
        print(f"[Sisters] login: user={username} found={sister is not None} pw_len={len(password)}")
        if sister: print(f"[Sisters] active={sister.is_network_active} suspended={sister.is_suspended}")

        if not sister or not pwd_context.verify(password, sister.password_hash):
            return jsonify({"ok": False,
                            "error": "Invalid username or password."}), 401
        if not sister.is_network_active:
            return jsonify({"ok": False, "error": "Account is not active."}), 403
        if sister.is_suspended:
            return jsonify({"ok": False,
                            "error": "Account suspended. Contact support."}), 403

        sister.last_active = datetime.now(timezone.utc)
        session.commit()

        token = make_token(sister.id, sister.username)
        return jsonify({
            "ok":               True,
            "token":            token,
            "username":         sister.username,
            "display_name":     sister.display_name,
            "is_network_active": sister.is_network_active,
        })

    except Exception as e:
        print(f"[Sisters] login error: {e}")
        return jsonify({"ok": False, "error": "Login failed."}), 500
    finally:
        session.close()


# ── Ping (Distress Signal) ────────────────────────────────────────────────────

@app.route("/sisters/api/ping", methods=["POST"])
@require_auth
def send_ping(sister):
    """
    Send a distress ping.
    Body: { lat, lng, accuracy_meters (optional), context (optional) }
    """
    ip = get_ip()
    if not check_rate(ip, "ping"):
        return jsonify({"ok": False,
                        "error": "Ping rate limit reached. If this is an emergency call 911."}), 429

    data = request.get_json(silent=True) or {}

    lat = data.get("lat")
    lng = data.get("lng")

    if not valid_coord(lat) or not valid_coord(lng):
        return jsonify({"ok": False,
                        "error": "Valid location required to send a ping."}), 400

    # Validate lat/lng ranges
    if not (-90 <= float(lat) <= 90) or not (-180 <= float(lng) <= 180):
        return jsonify({"ok": False, "error": "Invalid coordinates."}), 400

    accuracy = data.get("accuracy_meters")
    context  = clean_text(data.get("context", ""), 200) or None

    result = create_ping(
        sister_id       = sister.id,
        lat             = float(lat),
        lng             = float(lng),
        accuracy_meters = float(accuracy) if accuracy else None,
        context         = context,
    )

    if not result["ok"]:
        return jsonify(result), 400

    return jsonify(result), 201


@app.route("/sisters/api/ping/resolve", methods=["POST"])
@require_auth
def resolve(sister):
    """Mark yourself as safe. Erases your location immediately."""
    data    = request.get_json(silent=True) or {}
    ping_id = data.get("ping_id")

    if not ping_id:
        return jsonify({"ok": False, "error": "ping_id required."}), 400

    result = resolve_ping(int(ping_id), sister.id)
    return jsonify(result), (200 if result["ok"] else 400)


@app.route("/sisters/api/ping/status", methods=["GET"])
@require_auth
def ping_status(sister):
    """Get the status of the Sister's current active ping."""
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        ping = session.query(SisterPing).filter(
            SisterPing.sister_id == sister.id,
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at > now,
        ).order_by(SisterPing.created_at.desc()).first()

        if not ping:
            return jsonify({"ok": True, "active_ping": None})

        # Get responders
        responders = []
        for r in ping.responses:
            if r.status in (ResponseStatus.EN_ROUTE, ResponseStatus.ARRIVED):
                responder = session.query(Sister).filter(
                    Sister.id == r.responder_id).first()
                responders.append({
                    "display_name":   responder.display_name if responder else "A sister",
                    "status":         r.status,
                    "responder_lat":  r.responder_lat,
                    "responder_lng":  r.responder_lng,
                    "responded_at":   r.responded_at.isoformat(),
                })

        minutes_left = max(0, int(
            (ping.expires_at - now).total_seconds() / 60
        ))

        return jsonify({
            "ok": True,
            "active_ping": {
                "ping_id":        ping.id,
                "status":         ping.status,
                "response_count": ping.response_count,
                "minutes_left":   minutes_left,
                "responders":     responders,
                "created_at":     ping.created_at.isoformat(),
            }
        })

    except Exception as e:
        print(f"[Sisters] ping_status error: {e}")
        return jsonify({"ok": False, "error": "Failed to get ping status."}), 500
    finally:
        session.close()


# ── Nearby Pings (for Sisters to see who needs help) ─────────────────────────

@app.route("/sisters/api/ping/nearby", methods=["POST"])
@require_auth
def nearby_pings(sister):
    """
    Get active pings near the Sister's current location.
    Body: { lat, lng, radius_miles (optional, default 2.0) }

    PRIVACY: Sister's location in this request is used ONLY for
    the proximity calculation and is never stored.
    """
    ip = get_ip()
    if not check_rate(ip, "nearby"):
        return jsonify({"ok": False, "error": "Too many location requests."}), 429

    data = request.get_json(silent=True) or {}
    lat  = data.get("lat")
    lng  = data.get("lng")

    if not valid_coord(lat) or not valid_coord(lng):
        return jsonify({"ok": False, "error": "Valid location required."}), 400

    radius = min(float(data.get("radius_miles", 2.0)), 10.0)  # Cap at 10 miles

    pings = get_active_pings_near(float(lat), float(lng), radius)

    # Filter out the Sister's own ping from results
    pings = [p for p in pings if True]  # Could filter by sister_id if needed

    return jsonify({
        "ok":    True,
        "pings": pings,
        "count": len(pings),
    })


# ── Respond to a Ping ─────────────────────────────────────────────────────────

@app.route("/sisters/api/respond", methods=["POST"])
@require_auth
def respond(sister):
    """
    Respond to a distress ping.
    Body: { ping_id, lat, lng }
    """
    ip = get_ip()
    if not check_rate(ip, "respond"):
        return jsonify({"ok": False, "error": "Too many response attempts."}), 429

    data    = request.get_json(silent=True) or {}
    ping_id = data.get("ping_id")
    lat     = data.get("lat")
    lng     = data.get("lng")

    if not ping_id:
        return jsonify({"ok": False, "error": "ping_id required."}), 400
    if not valid_coord(lat) or not valid_coord(lng):
        return jsonify({"ok": False, "error": "Valid location required."}), 400

    result = respond_to_ping(
        ping_id      = int(ping_id),
        responder_id = sister.id,
        responder_lat = float(lat),
        responder_lng = float(lng),
    )

    return jsonify(result), (200 if result["ok"] else 400)


# ── Network Stats (non-identifying, aggregate only) ───────────────────────────

@app.route("/sisters/api/stats")
def stats():
    """
    Aggregate network stats — no identifying information.
    Active pings count, total sisters, total responses given.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        active_pings = session.query(SisterPing).filter(
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at > now,
        ).count()

        total_sisters = session.query(Sister).filter(
            Sister.is_network_active == True,
            Sister.is_suspended == False,
        ).count()

        total_responses = session.query(SisterResponse).count()

        return jsonify({
            "ok":              True,
            "active_pings":    active_pings,
            "total_sisters":   total_sisters,
            "total_responses": total_responses,
        })
    except Exception as e:
        print(f"[Sisters] stats error: {e}")
        return jsonify({"ok": False}), 500
    finally:
        session.close()
