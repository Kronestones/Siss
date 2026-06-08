"""
littles_database.py — Siss Littles Database Models & Helpers

Database layer for the Siss Littles family safety network.

Models:
  Family         — a family unit, owned by a parent member
  FamilyMember   — a person in a family (parent or child role)
  InviteCode     — single-use codes to join a family
  FamilyPing     — distress ping sent by a family member
  FamilyResponse — a response to a distress ping

Founded by T.L. Powers · Siss Littles · 2026
"""

import os
import enum
import math
from datetime import datetime, timezone, timedelta

from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    Boolean, DateTime, ForeignKey, Text, Enum as SAEnum,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# ── Database connection ───────────────────────────────────────────────────────

DATABASE_URL = os.environ.get(
    "LITTLES_DATABASE_URL",
    os.environ.get("DATABASE_URL", "sqlite:///littles.db")
)

# Neon/PostgreSQL uses 'postgresql://' — SQLAlchemy needs 'postgresql+psycopg2://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg2" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={"sslmode": "require"} if "postgresql" in DATABASE_URL else {},
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


# ── Enums ─────────────────────────────────────────────────────────────────────

class MemberRole(str, enum.Enum):
    PARENT = "parent"   # can manage family, access dashboard, generate invites
    CHILD  = "child"    # sees only child view, can send SOS


class PingStatus(str, enum.Enum):
    ACTIVE    = "active"      # ping is live
    RESPONDED = "responded"   # at least one response received
    RESOLVED  = "resolved"    # sender marked safe
    EXPIRED   = "expired"     # timed out with no resolution
    CANCELLED = "cancelled"   # sender cancelled immediately (false alarm)


class ResponseStatus(str, enum.Enum):
    EN_ROUTE = "en_route"
    ARRIVED  = "arrived"
    WITHDREW = "withdrew"


class InviteStatus(str, enum.Enum):
    ACTIVE  = "active"
    USED    = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ══════════════════════════════════════════════════════════════════════════════
# MODELS
# ══════════════════════════════════════════════════════════════════════════════

class Family(Base):
    """
    A family unit. Created by the first parent to register.
    All members share a family_code for joining.
    """
    __tablename__ = "littles_families"

    id         = Column(Integer, primary_key=True)
    name       = Column(String(100), nullable=False, default="My Family")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Cross-network opt-in: if True, nearby Siss Sisters are alerted on child ping
    siss_network_opt_in = Column(Boolean, default=False, nullable=False)

    members  = relationship("FamilyMember", back_populates="family", cascade="all, delete-orphan")
    pings    = relationship("FamilyPing",   back_populates="family", cascade="all, delete-orphan")
    invites  = relationship("InviteCode",   back_populates="family", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Family id={self.id} name={self.name!r}>"


class FamilyMember(Base):
    """
    A person in the Siss Littles network.
    Parents register with email/password/PIN.
    Children join via family code — minimal account, parent-managed.
    """
    __tablename__ = "littles_members"

    id           = Column(Integer, primary_key=True)
    family_id    = Column(Integer, ForeignKey("littles_families.id"), nullable=False)
    role         = Column(SAEnum(MemberRole), nullable=False, default=MemberRole.CHILD)

    username     = Column(String(50),  unique=True, nullable=False, index=True)
    email        = Column(String(255), unique=True, nullable=True)   # optional for child accounts
    display_name = Column(String(100), nullable=False)

    password_hash = Column(String(255), nullable=True)  # None for child-only accounts
    pin_hash      = Column(String(255), nullable=True)  # parent PIN (bcrypt)

    # Terms agreement — logged server-side
    agreed_at    = Column(DateTime(timezone=True), nullable=True)
    agreed_ip    = Column(String(64), nullable=True)

    # Invite tracking
    invited_by_id = Column(Integer, ForeignKey("littles_members.id"), nullable=True)
    joined_via    = Column(String(20), nullable=True)  # 'registration' | 'invite_code'

    # Account state
    is_active    = Column(Boolean, default=True,  nullable=False)
    is_suspended = Column(Boolean, default=False, nullable=False)
    last_active  = Column(DateTime(timezone=True), nullable=True)
    created_at   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    family       = relationship("Family", back_populates="members")
    invited_by   = relationship("FamilyMember", remote_side=[id], foreign_keys=[invited_by_id])
    pings        = relationship("FamilyPing",    back_populates="sender",    foreign_keys="FamilyPing.sender_id")
    responses    = relationship("FamilyResponse", back_populates="responder", foreign_keys="FamilyResponse.responder_id")
    codes_generated = relationship("InviteCode", back_populates="generated_by", foreign_keys="InviteCode.generated_by_id")

    def __repr__(self):
        return f"<FamilyMember id={self.id} username={self.username!r} role={self.role}>"


class InviteCode(Base):
    """
    Single-use invite code to join a family.
    Generated by a parent, used once.
    """
    __tablename__ = "littles_invite_codes"

    id               = Column(Integer, primary_key=True)
    family_id        = Column(Integer, ForeignKey("littles_families.id"), nullable=False)
    generated_by_id  = Column(Integer, ForeignKey("littles_members.id"), nullable=False)

    code       = Column(String(20), unique=True, nullable=False, index=True)
    status     = Column(SAEnum(InviteStatus), default=InviteStatus.ACTIVE, nullable=False)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at    = Column(DateTime(timezone=True), nullable=True)
    used_by_id = Column(Integer, ForeignKey("littles_members.id"), nullable=True)

    family       = relationship("Family",       back_populates="invites")
    generated_by = relationship("FamilyMember", back_populates="codes_generated",  foreign_keys=[generated_by_id])
    used_by      = relationship("FamilyMember", foreign_keys=[used_by_id])

    def __repr__(self):
        return f"<InviteCode code={self.code!r} status={self.status}>"


class FamilyPing(Base):
    """
    A distress ping sent by a family member (usually a child).
    Location is erased on resolution or expiry.
    Optionally bridges to the Siss network if family has opted in.
    """
    __tablename__ = "littles_pings"

    id        = Column(Integer, primary_key=True)
    family_id = Column(Integer, ForeignKey("littles_families.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("littles_members.id"),  nullable=False)

    status     = Column(SAEnum(PingStatus), default=PingStatus.ACTIVE, nullable=False)

    # Location — rounded for privacy, erased on resolve/expire
    lat              = Column(Float, nullable=True)
    lng              = Column(Float, nullable=True)
    accuracy_meters  = Column(Float, nullable=True)

    # Optional context message
    context = Column(String(200), nullable=True)

    # Siss network bridge
    siss_bridge_fired = Column(Boolean, default=False, nullable=False)

    response_count = Column(Integer, default=0, nullable=False)

    created_at  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at  = Column(DateTime(timezone=True), nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    family    = relationship("Family",        back_populates="pings")
    sender    = relationship("FamilyMember",  back_populates="pings", foreign_keys=[sender_id])
    responses = relationship("FamilyResponse", back_populates="ping", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<FamilyPing id={self.id} status={self.status} sender_id={self.sender_id}>"


class FamilyResponse(Base):
    """
    A response from a family member (or Siss Sister) to a distress ping.
    Responder location is used only for display and is not permanently stored.
    """
    __tablename__ = "littles_responses"

    id           = Column(Integer, primary_key=True)
    ping_id      = Column(Integer, ForeignKey("littles_pings.id"),   nullable=False)
    responder_id = Column(Integer, ForeignKey("littles_members.id"), nullable=False)

    status = Column(SAEnum(ResponseStatus), default=ResponseStatus.EN_ROUTE, nullable=False)

    # Responder's location at time of response — not persisted long-term
    responder_lat = Column(Float, nullable=True)
    responder_lng = Column(Float, nullable=True)

    # If a Siss Sister (not a family member) responded via the bridge
    siss_sister_name = Column(String(100), nullable=True)

    responded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    ping      = relationship("FamilyPing",   back_populates="responses")
    responder = relationship("FamilyMember", back_populates="responses", foreign_keys=[responder_id])

    def __repr__(self):
        return f"<FamilyResponse id={self.id} ping_id={self.ping_id} status={self.status}>"


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_session():
    return SessionLocal()


def init_db():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    print("[Littles] Database ready.")


def round_location(lat: float, lng: float, precision: int = 3):
    """
    Round coordinates for privacy.
    precision=3 → ~111m accuracy (enough for response, not enough to pinpoint a room).
    """
    return round(lat, precision), round(lng, precision)


def haversine_miles(lat1, lng1, lat2, lng2) -> float:
    """Calculate distance in miles between two coordinates."""
    R = 3958.8  # Earth radius in miles
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def create_ping(
    sender_id: int,
    family_id: int,
    lat: float,
    lng: float,
    accuracy_meters: float = None,
    context: str = None,
) -> dict:
    """
    Create a distress ping for a family member.
    Enforces: no duplicate active pings per sender.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)

        # Check for existing active ping
        existing = session.query(FamilyPing).filter(
            FamilyPing.sender_id == sender_id,
            FamilyPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            FamilyPing.expires_at > now,
        ).first()

        if existing:
            return {"ok": False, "error": "You already have an active ping.", "ping_id": existing.id}

        rlat, rlng = round_location(lat, lng)

        ping = FamilyPing(
            family_id       = family_id,
            sender_id       = sender_id,
            lat             = rlat,
            lng             = rlng,
            accuracy_meters = accuracy_meters,
            context         = context,
            status          = PingStatus.ACTIVE,
            expires_at      = now + timedelta(hours=1),
        )
        session.add(ping)
        session.commit()

        return {"ok": True, "ping_id": ping.id}

    except Exception as e:
        session.rollback()
        print(f"[Littles] create_ping error: {e}")
        return {"ok": False, "error": "Failed to create ping."}
    finally:
        session.close()


def resolve_ping(ping_id: int, sender_id: int, cancelled: bool = False) -> dict:
    """
    Resolve a ping — sender marks themselves safe (or cancels).
    Erases location immediately.
    """
    session = get_session()
    try:
        ping = session.query(FamilyPing).filter(
            FamilyPing.id        == ping_id,
            FamilyPing.sender_id == sender_id,
        ).first()

        if not ping:
            return {"ok": False, "error": "Ping not found."}
        if ping.status in (PingStatus.RESOLVED, PingStatus.EXPIRED, PingStatus.CANCELLED):
            return {"ok": False, "error": "Ping is already closed."}

        ping.status      = PingStatus.CANCELLED if cancelled else PingStatus.RESOLVED
        ping.resolved_at = datetime.now(timezone.utc)

        # Erase location immediately
        ping.lat = None
        ping.lng = None

        # Erase responder locations
        for r in ping.responses:
            r.responder_lat = None
            r.responder_lng = None

        session.commit()
        return {"ok": True, "cancelled": cancelled}

    except Exception as e:
        session.rollback()
        print(f"[Littles] resolve_ping error: {e}")
        return {"ok": False, "error": "Failed to resolve ping."}
    finally:
        session.close()


def respond_to_ping(ping_id: int, responder_id: int, responder_lat: float, responder_lng: float) -> dict:
    """Record a family member responding to a ping."""
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        ping = session.query(FamilyPing).filter(
            FamilyPing.id        == ping_id,
            FamilyPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            FamilyPing.expires_at > now,
        ).first()

        if not ping:
            return {"ok": False, "error": "Ping not found or already closed."}

        # Check for existing response from this member
        existing = session.query(FamilyResponse).filter(
            FamilyResponse.ping_id      == ping_id,
            FamilyResponse.responder_id == responder_id,
        ).first()

        if existing:
            existing.status       = ResponseStatus.EN_ROUTE
            existing.responder_lat = responder_lat
            existing.responder_lng = responder_lng
            existing.responded_at  = now
        else:
            response = FamilyResponse(
                ping_id       = ping_id,
                responder_id  = responder_id,
                responder_lat = responder_lat,
                responder_lng = responder_lng,
                status        = ResponseStatus.EN_ROUTE,
            )
            session.add(response)
            ping.response_count += 1
            ping.status = PingStatus.RESPONDED

        session.commit()
        return {
            "ok":              True,
            "ping_id":         ping_id,
            "sender_lat":      ping.lat,
            "sender_lng":      ping.lng,
        }

    except Exception as e:
        session.rollback()
        print(f"[Littles] respond_to_ping error: {e}")
        return {"ok": False, "error": "Failed to record response."}
    finally:
        session.close()


def get_active_family_alerts(family_id: int) -> list:
    """Get all active pings for a family — for the parent dashboard."""
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        pings = session.query(FamilyPing).filter(
            FamilyPing.family_id == family_id,
            FamilyPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            FamilyPing.expires_at > now,
        ).order_by(FamilyPing.created_at.desc()).all()

        result = []
        for p in pings:
            sender = session.query(FamilyMember).filter(FamilyMember.id == p.sender_id).first()
            result.append({
                "ping_id":     p.id,
                "sender_name": sender.display_name if sender else "A family member",
                "status":      p.status,
                "lat":         p.lat,
                "lng":         p.lng,
                "context":     p.context,
                "created_at":  p.created_at.isoformat(),
                "response_count": p.response_count,
            })
        return result

    except Exception as e:
        print(f"[Littles] get_active_family_alerts error: {e}")
        return []
    finally:
        session.close()


def expire_old_pings():
    """
    Background task: expire stale pings and erase their locations.
    Run every 2 minutes.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        stale = session.query(FamilyPing).filter(
            FamilyPing.expires_at < now,
            FamilyPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
        ).all()

        for p in stale:
            p.status = PingStatus.EXPIRED
            p.lat    = None
            p.lng    = None
            for r in p.responses:
                r.responder_lat = None
                r.responder_lng = None

        if stale:
            session.commit()
            print(f"[Littles] Expired {len(stale)} ping(s).")

    except Exception as e:
        session.rollback()
        print(f"[Littles] expire_old_pings error: {e}")
    finally:
        session.close()


def expire_old_invite_codes():
    """Mark expired invite codes as expired."""
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        stale = session.query(InviteCode).filter(
            InviteCode.expires_at < now,
            InviteCode.status == InviteStatus.ACTIVE,
        ).all()
        for c in stale:
            c.status = InviteStatus.EXPIRED
        if stale:
            session.commit()
    except Exception as e:
        session.rollback()
        print(f"[Littles] expire_old_invite_codes error: {e}")
    finally:
        session.close()
