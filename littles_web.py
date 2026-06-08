"""
littles_web.py — Siss Littles Web Routes

Flask API for the Siss Littles family safety network.

Routes:
  GET  /littles                        → Mobile UI
  POST /littles/api/register           → Create parent account
  POST /littles/api/login              → Login, get token
  POST /littles/api/ping               → Send distress ping
  POST /littles/api/ping/resolve       → Mark self safe
  POST /littles/api/ping/cancel        → Cancel ping immediately (false alarm)
  GET  /littles/api/ping/status        → Status of my current ping
  GET  /littles/api/family/members     → Get family members + family code
  GET  /littles/api/family/alerts      → Get active alerts for this family
  POST /littles/api/respond            → Respond to a family ping
  POST /littles/api/invite/generate    → Generate an invite code
  GET  /littles/api/invite/mine        → My generated codes
  GET  /littles/api/invite/tree        → Members I've invited
  POST /littles/api/invite/revoke      → Revoke a code
  POST /littles/api/join               → Join a family via invite code
  POST /littles/api/settings           → Save parent settings
  GET  /littles/api/health             → Health check

Security:
  - All ping/family endpoints require auth token
  - Parent PIN stored as bcrypt hash server-side
  - Agreement timestamp logged with IP on registration
  - Locations never written to application logs
  - Location erased immediately on ping resolve/cancel/expire
  - HTTPS enforced in production via Render

Siss Network Bridge:
  When a family has siss_network_opt_in=True and a child sends a ping,
  the bridge queries the Siss Sisters database for active Sisters within
  2 miles and inserts a cross-network notification.

Founded by T.L. Powers · Siss Littles · 2026
"""

import os
import re
import time
import html
import secrets
import string
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from functools import wraps

from flask import Flask, Blueprint, jsonify, request, render_template, redirect

from littles_database import (
    init_db, get_session,
    Family, FamilyMember, InviteCode, FamilyPing, FamilyResponse,
    MemberRole, PingStatus, ResponseStatus, InviteStatus,
    create_ping, resolve_ping, respond_to_ping,
    get_active_family_alerts, expire_old_pings, expire_old_invite_codes,
    round_location, haversine_miles,
)

# Auth
from passlib.context import CryptContext
from jose import jwt, JWTError

SECRET_KEY    = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_HOURS     = 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

littles = Blueprint("littles", __name__, url_prefix="/littles")


# ── Rate Limiting ─────────────────────────────────────────────────────────────

_rate_store = defaultdict(list)
_rate_lock  = threading.Lock()

RATE_LIMITS = {
    "register": {"max": 3,  "window": 3600},
    "login":    {"max": 10, "window": 300},
    "ping":     {"max": 3,  "window": 3600},
    "respond":  {"max": 20, "window": 60},
    "invite":   {"max": 10, "window": 3600},
    "join":     {"max": 5,  "window": 3600},
}

def check_rate(ip: str, action: str) -> bool:
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

def make_token(member_id: int, username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_HOURS)
    return jwt.encode(
        {"sub": str(member_id), "username": username, "role": role, "exp": exp},
        SECRET_KEY, algorithm=JWT_ALGORITHM,
    )

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None

def get_auth_member():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    payload = decode_token(auth[7:])
    if not payload:
        return None
    session = get_session()
    try:
        member = session.query(FamilyMember).filter(
            FamilyMember.id          == int(payload["sub"]),
            FamilyMember.is_active   == True,
            FamilyMember.is_suspended == False,
        ).first()
        return member
    except Exception:
        return None
    finally:
        session.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        member = get_auth_member()
        if not member:
            return jsonify({"ok": False, "error": "Authentication required."}), 401
        return f(member, *args, **kwargs)
    return decorated

def require_parent(f):
    """Auth + must be a parent role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        member = get_auth_member()
        if not member:
            return jsonify({"ok": False, "error": "Authentication required."}), 401
        if member.role != MemberRole.PARENT:
            return jsonify({"ok": False, "error": "Parent access required."}), 403
        return f(member, *args, **kwargs)
    return decorated


# ── Input Sanitization ────────────────────────────────────────────────────────

def clean(text: str, max_len: int = 200) -> str:
    if not text:
        return ""
    return html.escape(str(text).strip())[:max_len]

def valid_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email or ""))

def valid_coord(val) -> bool:
    try:
        f = float(val)
        return -180 <= f <= 180
    except (TypeError, ValueError):
        return False

def valid_pin(pin: str) -> bool:
    return bool(re.match(r'^\d{4}$', pin or ""))


# ── Invite Code Generator ─────────────────────────────────────────────────────

def generate_code(length: int = 8) -> str:
    """Generate a readable invite code — uppercase letters and digits, no ambiguous chars."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(chars) for _ in range(length))


# ── Background Tasks ──────────────────────────────────────────────────────────

def _background_loop():
    while True:
        time.sleep(120)
        try:
            expire_old_pings()
            expire_old_invite_codes()
        except Exception as e:
            print(f"[Littles] Background loop error: {e}")

_bg_thread = threading.Thread(target=_background_loop, daemon=True)


# ── Siss Network Bridge ───────────────────────────────────────────────────────

def fire_siss_bridge(ping_id: int, lat: float, lng: float, sender_name: str):
    """
    When a family has opted in, notify Siss Sisters within 2 miles.
    Runs in a background thread so it doesn't block the ping response.

    This queries the Siss Sisters database (shared Neon instance) for
    active Sisters with siss_kids_opt_in=True within 2 miles and inserts
    a cross-network notification record.

    NOTE: Requires the Siss Sister model to have:
      - siss_kids_opt_in   (Boolean)  — Sister opted in to receive child alerts
      - last_known_lat/lng (Float)    — approximate last known location
    Add these columns to the Siss sisters table and expose them via
    the Siss scanner's location update endpoint.
    """
    try:
        # Import Siss database — same Neon instance, different tables
        from sisters_database import get_session as siss_session, Sister

        session = siss_session()
        try:
            # Get Sisters who have opted in and have a known location
            candidates = session.query(Sister).filter(
                Sister.is_network_active == True,
                Sister.is_suspended      == False,
                Sister.siss_kids_opt_in  == True,
                Sister.last_known_lat    != None,
                Sister.last_known_lng    != None,
            ).all()

            notified = 0
            for sister in candidates:
                dist = haversine_miles(
                    lat, lng,
                    sister.last_known_lat,
                    sister.last_known_lng,
                )
                if dist <= 2.0:
                    # Insert cross-network notification
                    # (Siss frontend polls /sisters/api/ping/nearby — child pings
                    #  appear there with type='child_distress' if Sister opted in)
                    _insert_siss_notification(session, sister.id, ping_id, lat, lng, sender_name)
                    notified += 1

            if notified:
                session.commit()
                print(f"[Littles Bridge] Notified {notified} Sister(s) of child distress ping {ping_id}.")

        finally:
            session.close()

    except ImportError:
        print("[Littles Bridge] sisters_database not available — bridge skipped.")
    except Exception as e:
        print(f"[Littles Bridge] Error: {e}")


def _insert_siss_notification(session, sister_id: int, ping_id: int, lat: float, lng: float, sender_name: str):
    """
    Insert a cross-network notification into the Siss database.
    Requires a SissKidsNotification model in sisters_database.py — add:

    class SissKidsNotification(Base):
        __tablename__ = "siss_kids_notifications"
        id          = Column(Integer, primary_key=True)
        sister_id   = Column(Integer, ForeignKey("sisters.id"))
        ping_id     = Column(Integer)            # littles_pings.id
        lat         = Column(Float)
        lng         = Column(Float)
        sender_name = Column(String(100))
        created_at  = Column(DateTime(timezone=True))
        expires_at  = Column(DateTime(timezone=True))
        seen        = Column(Boolean, default=False)
    """
    try:
        from sisters_database import SissKidsNotification
        now = datetime.now(timezone.utc)
        notif = SissKidsNotification(
            sister_id   = sister_id,
            ping_id     = ping_id,
            lat         = lat,
            lng         = lng,
            sender_name = sender_name,
            created_at  = now,
            expires_at  = now + timedelta(hours=1),
            seen        = False,
        )
        session.add(notif)
    except ImportError:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@littles.route("/")
def littles_ui():
    return render_template("littles.html")


@littles.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "Siss Littles"})


# ── Registration ──────────────────────────────────────────────────────────────

@littles.route("/api/register", methods=["POST"])
def register():
    ip = get_ip()
    if not check_rate(ip, "register"):
        return jsonify({"ok": False, "error": "Too many registration attempts. Try again later."}), 429

    data = request.get_json(silent=True) or {}

    username     = clean(data.get("username", ""), 50).lower()
    email        = clean(data.get("email", ""), 255).lower()
    display_name = clean(data.get("display_name", ""), 100)
    password     = data.get("password", "")
    pin          = data.get("pin", "")
    family_name  = clean(data.get("family_name", "My Family"), 100)
    agreed_at    = data.get("agreed_at", "")

    # Validate
    if not username or len(username) < 3:
        return jsonify({"ok": False, "error": "Username must be at least 3 characters."}), 400
    if not re.match(r'^[a-zA-Z0-9_\-]{3,50}$', username):
        return jsonify({"ok": False, "error": "Username may only contain letters, numbers, underscores, hyphens."}), 400
    if not valid_email(email):
        return jsonify({"ok": False, "error": "Invalid email address."}), 400
    if not display_name:
        return jsonify({"ok": False, "error": "Display name is required."}), 400
    if not password or len(password) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
    if len(password) > 128:
        return jsonify({"ok": False, "error": "Password is too long."}), 400
    if not valid_pin(pin):
        return jsonify({"ok": False, "error": "PIN must be exactly 4 digits."}), 400
    if not agreed_at:
        return jsonify({"ok": False, "error": "Terms of service agreement is required."}), 400

    session = get_session()
    try:
        if session.query(FamilyMember).filter(FamilyMember.username == username).first():
            return jsonify({"ok": False, "error": "That username is already taken."}), 409
        if session.query(FamilyMember).filter(FamilyMember.email == email).first():
            return jsonify({"ok": False, "error": "That email is already registered."}), 409

        # Create family
        family = Family(name=family_name)
        session.add(family)
        session.flush()  # get family.id

        # Create parent member
        member = FamilyMember(
            family_id     = family.id,
            role          = MemberRole.PARENT,
            username      = username,
            email         = email,
            display_name  = display_name,
            password_hash = pwd_context.hash(password),
            pin_hash      = pwd_context.hash(pin),
            agreed_at     = datetime.now(timezone.utc),
            agreed_ip     = ip,
            joined_via    = "registration",
            last_active   = datetime.now(timezone.utc),
        )
        session.add(member)
        session.commit()

        token = make_token(member.id, member.username, member.role)
        return jsonify({
            "ok":          True,
            "token":       token,
            "username":    member.username,
            "display_name": member.display_name,
            "role":        member.role,
            "family_id":   family.id,
            "family_name": family.name,
        }), 201

    except Exception as e:
        session.rollback()
        print(f"[Littles] register error: {e}")
        return jsonify({"ok": False, "error": "Registration failed."}), 500
    finally:
        session.close()


# ── Login ─────────────────────────────────────────────────────────────────────

@littles.route("/api/login", methods=["POST"])
def login():
    ip = get_ip()
    if not check_rate(ip, "login"):
        return jsonify({"ok": False, "error": "Too many login attempts. Try again in a few minutes."}), 429

    data     = request.get_json(silent=True) or {}
    username = clean(data.get("username", ""), 50).lower()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password are required."}), 400

    session = get_session()
    try:
        member = session.query(FamilyMember).filter(FamilyMember.username == username).first()
        if not member or not member.password_hash or not pwd_context.verify(password, member.password_hash):
            return jsonify({"ok": False, "error": "Invalid username or password."}), 401
        if not member.is_active:
            return jsonify({"ok": False, "error": "Account is not active."}), 403
        if member.is_suspended:
            return jsonify({"ok": False, "error": "Account suspended. Contact support."}), 403

        member.last_active = datetime.now(timezone.utc)
        session.commit()

        token = make_token(member.id, member.username, member.role)
        return jsonify({
            "ok":           True,
            "token":        token,
            "username":     member.username,
            "display_name": member.display_name,
            "role":         member.role,
            "family_id":    member.family_id,
        })

    except Exception as e:
        print(f"[Littles] login error: {e}")
        return jsonify({"ok": False, "error": "Login failed."}), 500
    finally:
        session.close()


# ── Ping (Distress Signal) ────────────────────────────────────────────────────

@littles.route("/api/ping", methods=["POST"])
@require_auth
def send_ping(member):
    ip = get_ip()
    if not check_rate(ip, "ping"):
        return jsonify({
            "ok":    False,
            "error": "Ping rate limit reached. If this is a real emergency, call 911 immediately."
        }), 429

    data = request.get_json(silent=True) or {}
    lat  = data.get("lat")
    lng  = data.get("lng")

    if not valid_coord(lat) or not valid_coord(lng):
        return jsonify({"ok": False, "error": "Valid location required to send a ping."}), 400
    if not (-90 <= float(lat) <= 90) or not (-180 <= float(lng) <= 180):
        return jsonify({"ok": False, "error": "Invalid coordinates."}), 400

    accuracy = data.get("accuracy_meters")
    context  = clean(data.get("context", ""), 200) or None

    result = create_ping(
        sender_id       = member.id,
        family_id       = member.family_id,
        lat             = float(lat),
        lng             = float(lng),
        accuracy_meters = float(accuracy) if accuracy else None,
        context         = context,
    )

    if not result["ok"]:
        return jsonify(result), 400

    # Fire Siss network bridge in background if family has opted in
    session = get_session()
    try:
        family = session.query(Family).filter(Family.id == member.family_id).first()
        if family and family.siss_network_opt_in:
            t = threading.Thread(
                target=fire_siss_bridge,
                args=(result["ping_id"], float(lat), float(lng), member.display_name),
                daemon=True,
            )
            t.start()
            result["siss_bridge"] = True
    finally:
        session.close()

    return jsonify(result), 201


@littles.route("/api/ping/resolve", methods=["POST"])
@require_auth
def resolve(member):
    data    = request.get_json(silent=True) or {}
    ping_id = data.get("ping_id")
    if not ping_id:
        return jsonify({"ok": False, "error": "ping_id required."}), 400
    result = resolve_ping(int(ping_id), member.id, cancelled=False)
    return jsonify(result), (200 if result["ok"] else 400)


@littles.route("/api/ping/cancel", methods=["POST"])
@require_auth
def cancel_ping(member):
    """Immediate cancel — false alarm. Notifies family it was a mistake."""
    data    = request.get_json(silent=True) or {}
    ping_id = data.get("ping_id")
    if not ping_id:
        return jsonify({"ok": False, "error": "ping_id required."}), 400
    result = resolve_ping(int(ping_id), member.id, cancelled=True)
    return jsonify(result), (200 if result["ok"] else 400)


@littles.route("/api/ping/status", methods=["GET"])
@require_auth
def ping_status(member):
    session = get_session()
    try:
        now  = datetime.now(timezone.utc)
        ping = session.query(FamilyPing).filter(
            FamilyPing.sender_id == member.id,
            FamilyPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            FamilyPing.expires_at > now,
        ).order_by(FamilyPing.created_at.desc()).first()

        if not ping:
            return jsonify({"ok": True, "active_ping": None})

        responders = []
        for r in ping.responses:
            if r.status in (ResponseStatus.EN_ROUTE, ResponseStatus.ARRIVED):
                resp = session.query(FamilyMember).filter(FamilyMember.id == r.responder_id).first()
                responders.append({
                    "display_name":  resp.display_name if resp else "A family member",
                    "status":        r.status,
                    "responder_lat": r.responder_lat,
                    "responder_lng": r.responder_lng,
                    "responded_at":  r.responded_at.isoformat(),
                })

        minutes_left = max(0, int((ping.expires_at - now).total_seconds() / 60))

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
        print(f"[Littles] ping_status error: {e}")
        return jsonify({"ok": False, "error": "Failed to get ping status."}), 500
    finally:
        session.close()


# ── Family ────────────────────────────────────────────────────────────────────

@littles.route("/api/family/members", methods=["GET"])
@require_auth
def family_members(member):
    session = get_session()
    try:
        members = session.query(FamilyMember).filter(
            FamilyMember.family_id   == member.family_id,
            FamilyMember.is_active   == True,
            FamilyMember.is_suspended == False,
        ).order_by(FamilyMember.role.desc(), FamilyMember.display_name).all()

        # Get or surface the current active invite code for the family
        now = datetime.now(timezone.utc)
        active_code = session.query(InviteCode).filter(
            InviteCode.family_id == member.family_id,
            InviteCode.status    == InviteStatus.ACTIVE,
            InviteCode.expires_at > now,
        ).order_by(InviteCode.created_at.desc()).first()

        family = session.query(Family).filter(Family.id == member.family_id).first()

        return jsonify({
            "ok": True,
            "members": [
                {
                    "id":           m.id,
                    "display_name": m.display_name,
                    "username":     m.username,
                    "role":         m.role,
                    "online":       (
                        m.last_active and
                        (now - m.last_active).total_seconds() < 300
                    ),
                    "joined_at":    m.created_at.isoformat(),
                }
                for m in members
            ],
            "family_name":       family.name if family else "My Family",
            "family_code":       active_code.code if active_code else None,
            "siss_network_opt_in": family.siss_network_opt_in if family else False,
        })

    except Exception as e:
        print(f"[Littles] family_members error: {e}")
        return jsonify({"ok": False, "error": "Failed to load family."}), 500
    finally:
        session.close()


@littles.route("/api/family/alerts", methods=["GET"])
@require_auth
def family_alerts(member):
    alerts = get_active_family_alerts(member.family_id)
    return jsonify({"ok": True, "alerts": alerts})


# ── Respond ───────────────────────────────────────────────────────────────────

@littles.route("/api/respond", methods=["POST"])
@require_auth
def respond(member):
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

    # Verify ping belongs to member's family
    session = get_session()
    try:
        ping = session.query(FamilyPing).filter(FamilyPing.id == int(ping_id)).first()
        if not ping or ping.family_id != member.family_id:
            return jsonify({"ok": False, "error": "Ping not found."}), 404
    finally:
        session.close()

    result = respond_to_ping(
        ping_id       = int(ping_id),
        responder_id  = member.id,
        responder_lat = float(lat),
        responder_lng = float(lng),
    )
    return jsonify(result), (200 if result["ok"] else 400)


# ── Invites ───────────────────────────────────────────────────────────────────

@littles.route("/api/invite/generate", methods=["POST"])
@require_parent
def generate_invite(member):
    ip = get_ip()
    if not check_rate(ip, "invite"):
        return jsonify({"ok": False, "error": "Too many invite requests."}), 429

    session = get_session()
    try:
        # Enforce max 5 active codes per family at once
        now = datetime.now(timezone.utc)
        active_count = session.query(InviteCode).filter(
            InviteCode.family_id == member.family_id,
            InviteCode.status    == InviteStatus.ACTIVE,
            InviteCode.expires_at > now,
        ).count()

        if active_count >= 5:
            return jsonify({
                "ok":    False,
                "error": "You have 5 active codes already. Revoke one before generating more.",
            }), 429

        # Generate unique code
        for _ in range(10):
            code = generate_code()
            if not session.query(InviteCode).filter(InviteCode.code == code).first():
                break

        invite = InviteCode(
            family_id       = member.family_id,
            generated_by_id = member.id,
            code            = code,
            status          = InviteStatus.ACTIVE,
            expires_at      = now + timedelta(hours=48),
        )
        session.add(invite)
        session.commit()

        return jsonify({
            "ok":        True,
            "code":      code,
            "expires_at": invite.expires_at.isoformat(),
        })

    except Exception as e:
        session.rollback()
        print(f"[Littles] generate_invite error: {e}")
        return jsonify({"ok": False, "error": "Failed to generate invite."}), 500
    finally:
        session.close()


@littles.route("/api/invite/mine", methods=["GET"])
@require_parent
def my_invites(member):
    session = get_session()
    try:
        now   = datetime.now(timezone.utc)
        codes = session.query(InviteCode).filter(
            InviteCode.family_id       == member.family_id,
            InviteCode.generated_by_id == member.id,
        ).order_by(InviteCode.created_at.desc()).limit(20).all()

        return jsonify({
            "ok": True,
            "codes": [
                {
                    "code":       c.code,
                    "status":     c.status,
                    "created_at": c.created_at.isoformat(),
                    "expires_at": c.expires_at.isoformat(),
                    "used_at":    c.used_at.isoformat() if c.used_at else None,
                }
                for c in codes
            ],
        })

    except Exception as e:
        print(f"[Littles] my_invites error: {e}")
        return jsonify({"ok": False, "error": "Failed to load invites."}), 500
    finally:
        session.close()


@littles.route("/api/invite/tree", methods=["GET"])
@require_parent
def invite_tree(member):
    """Members that this parent has invited."""
    session = get_session()
    try:
        invited = session.query(FamilyMember).filter(
            FamilyMember.invited_by_id == member.id,
            FamilyMember.is_active     == True,
        ).order_by(FamilyMember.created_at.desc()).all()

        return jsonify({
            "ok": True,
            "tree": [
                {
                    "display_name": m.display_name,
                    "role":         m.role,
                    "joined_at":    m.created_at.isoformat(),
                }
                for m in invited
            ],
        })

    except Exception as e:
        print(f"[Littles] invite_tree error: {e}")
        return jsonify({"ok": False, "error": "Failed to load invite tree."}), 500
    finally:
        session.close()


@littles.route("/api/invite/revoke", methods=["POST"])
@require_parent
def revoke_invite(member):
    data = request.get_json(silent=True) or {}
    code = clean(data.get("code", ""), 20).upper()

    if not code:
        return jsonify({"ok": False, "error": "code required."}), 400

    session = get_session()
    try:
        invite = session.query(InviteCode).filter(
            InviteCode.code            == code,
            InviteCode.family_id       == member.family_id,
            InviteCode.generated_by_id == member.id,
            InviteCode.status          == InviteStatus.ACTIVE,
        ).first()

        if not invite:
            return jsonify({"ok": False, "error": "Code not found or already used."}), 404

        invite.status = InviteStatus.REVOKED
        session.commit()
        return jsonify({"ok": True})

    except Exception as e:
        session.rollback()
        print(f"[Littles] revoke_invite error: {e}")
        return jsonify({"ok": False, "error": "Failed to revoke code."}), 500
    finally:
        session.close()


@littles.route("/api/join", methods=["POST"])
def join_family():
    """
    Join a family via invite code.
    Used when a second parent or older child sets up their own account.
    """
    ip = get_ip()
    if not check_rate(ip, "join"):
        return jsonify({"ok": False, "error": "Too many join attempts."}), 429

    data         = request.get_json(silent=True) or {}
    code         = clean(data.get("code", ""), 20).upper()
    username     = clean(data.get("username", ""), 50).lower()
    display_name = clean(data.get("display_name", ""), 100)
    password     = data.get("password", "")
    role         = data.get("role", "child")  # 'parent' or 'child'
    agreed_at    = data.get("agreed_at", "")

    if not code:
        return jsonify({"ok": False, "error": "Invite code is required."}), 400
    if not username or len(username) < 3:
        return jsonify({"ok": False, "error": "Username must be at least 3 characters."}), 400
    if not re.match(r'^[a-zA-Z0-9_\-]{3,50}$', username):
        return jsonify({"ok": False, "error": "Invalid username format."}), 400
    if not display_name:
        return jsonify({"ok": False, "error": "Display name is required."}), 400
    if not agreed_at:
        return jsonify({"ok": False, "error": "Terms agreement is required."}), 400

    member_role = MemberRole.PARENT if role == "parent" else MemberRole.CHILD

    # Password only required for parent role
    if member_role == MemberRole.PARENT:
        if not password or len(password) < 8:
            return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400

    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        invite = session.query(InviteCode).filter(
            InviteCode.code      == code,
            InviteCode.status    == InviteStatus.ACTIVE,
            InviteCode.expires_at > now,
        ).first()

        if not invite:
            return jsonify({"ok": False, "error": "Invalid or expired invite code."}), 404

        if session.query(FamilyMember).filter(FamilyMember.username == username).first():
            return jsonify({"ok": False, "error": "That username is already taken."}), 409

        member = FamilyMember(
            family_id     = invite.family_id,
            role          = member_role,
            username      = username,
            display_name  = display_name,
            password_hash = pwd_context.hash(password) if password else None,
            agreed_at     = now,
            agreed_ip     = ip,
            invited_by_id = invite.generated_by_id,
            joined_via    = "invite_code",
            last_active   = now,
        )
        session.add(member)

        # Mark code as used
        invite.status    = InviteStatus.USED
        invite.used_at   = now
        invite.used_by_id = member.id  # set after flush
        session.flush()
        invite.used_by_id = member.id

        session.commit()

        token = make_token(member.id, member.username, member.role) if password else None

        return jsonify({
            "ok":           True,
            "token":        token,
            "username":     member.username,
            "display_name": member.display_name,
            "role":         member.role,
            "family_id":    member.family_id,
        }), 201

    except Exception as e:
        session.rollback()
        print(f"[Littles] join error: {e}")
        return jsonify({"ok": False, "error": "Failed to join family."}), 500
    finally:
        session.close()


# ── Settings ──────────────────────────────────────────────────────────────────

@littles.route("/api/settings", methods=["POST"])
@require_parent
def save_settings(member):
    data = request.get_json(silent=True) or {}

    session = get_session()
    try:
        family = session.query(Family).filter(Family.id == member.family_id).first()
        if not family:
            return jsonify({"ok": False, "error": "Family not found."}), 404

        if "siss_network" in data:
            family.siss_network_opt_in = bool(data["siss_network"])

        session.commit()
        return jsonify({"ok": True})

    except Exception as e:
        session.rollback()
        print(f"[Littles] save_settings error: {e}")
        return jsonify({"ok": False, "error": "Failed to save settings."}), 500
    finally:
        session.close()


# ══════════════════════════════════════════════════════════════════════════════
# APP FACTORY
# ══════════════════════════════════════════════════════════════════════════════

def create_app():
    """
    Call this from your main app.py:

        from littles_web import create_app as create_littles
        from sisters_web import create_app as create_sisters

        app = Flask(__name__)
        app.register_blueprint(littles_blueprint)
        app.register_blueprint(sisters_blueprint)

    Or register the blueprint in your existing Medusa app:

        from littles_web import littles
        app.register_blueprint(littles)
    """
    init_db()
    _bg_thread.start()
    print("[Littles] Ready.")
    return littles
