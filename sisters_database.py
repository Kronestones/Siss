"""
sisters_database.py — Sisters of Medusa

Database models for the Sisters of Medusa safety network.

Models:
  Sister      — A verified member of the network
  SisterPing  — A distress signal broadcast by a Sister
  SisterResponse — A Sister acknowledging and responding to a ping

Design principles:
  - Location data is EPHEMERAL. Pings auto-expire after 90 minutes.
  - No location stored after ping resolves or expires.
  - No behavioral profiles. No tracking between sessions.
  - A Sister's location is only ever shared when SHE chooses to ping.
  - Responder locations are only shared with the pinging Sister.
  - All location data is rounded to 4 decimal places (~11m precision)
    — enough for nearby Sisters to find someone, not enough for surveillance.

Founded by T.L. Powers · Sisters of Medusa · 2026
Built on the values of The Commons, Themis, and Medusa.
"""

import os
import math
from datetime import datetime, timedelta, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    Boolean, DateTime, Text, ForeignKey, Enum
)
try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import enum

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sisters.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    pool_pre_ping=True,
    pool_recycle=300,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Enums ─────────────────────────────────────────────────────────────────────

class PingStatus(str, enum.Enum):
    ACTIVE    = "active"     # Ping is live — sisters nearby are being alerted
    RESPONDED = "responded"  # At least one sister is on her way
    RESOLVED  = "resolved"   # Sister confirmed safe — ping closed
    EXPIRED   = "expired"    # 90 minutes elapsed — auto-closed
    CANCELLED = "cancelled"  # Sister cancelled herself

class ResponseStatus(str, enum.Enum):
    ACKNOWLEDGED = "acknowledged"  # Sister saw the ping
    EN_ROUTE     = "en_route"      # Sister confirmed she is coming
    ARRIVED      = "arrived"       # Sister confirmed arrival
    WITHDRAWN    = "withdrawn"     # Sister could not come after all


# ── Models ────────────────────────────────────────────────────────────────────

class Sister(Base):
    """
    A verified member of the Sisters of Medusa network.

    Verification is intentionally lightweight — we do not require
    government ID or biometrics. The verification layer is:
      1. Email confirmation (proves they control the address)
      2. Manual review period (24h) before ping access is granted
      3. Community trust score — built through responses, not surveillance

    A Sister can be suspended by the network if she misuses the ping
    system (false pings confirmed by multiple responders).
    """
    __tablename__ = "sisters"

    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String(50), unique=True, index=True, nullable=False)
    email           = Column(String(255), unique=True, index=True, nullable=False)
    password_hash   = Column(String(255), nullable=False)
    display_name    = Column(String(100), nullable=True)

    # Verification
    is_email_verified   = Column(Boolean, default=False)
    is_network_active   = Column(Boolean, default=False)  # Can send and receive pings
    verification_token  = Column(String(128), nullable=True)  # For email confirmation

    # Trust
    pings_sent          = Column(Integer, default=0)    # How many pings she has sent
    responses_given     = Column(Integer, default=0)    # How many pings she has responded to
    false_ping_flags    = Column(Integer, default=0)    # Flags from responders (misuse)
    is_suspended        = Column(Boolean, default=False)

    # Privacy — no behavioral profile, no location stored outside active pings
    # No biometrics. No phone number required. No real name required.
    joined_at       = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_active     = Column(DateTime, nullable=True)

    pings           = relationship("SisterPing", back_populates="sister",
                                   foreign_keys="SisterPing.sister_id")
    responses       = relationship("SisterResponse", back_populates="responder")


class SisterPing(Base):
    """
    A distress signal sent by a Sister.

    CRITICAL PRIVACY DESIGN:
    - lat/lng are stored rounded to 4 decimal places (~11 meter precision).
      This is enough for a nearby Sister to find someone.
      It is not enough for surveillance or precise tracking.
    - Pings auto-expire after PING_TTL_MINUTES (90 minutes).
    - When a ping expires or resolves, lat/lng are set to NULL.
    - The ping record is retained (for safety audit) but location is erased.
    - Location is NEVER shared with anyone except verified Sisters
      within the configured radius who are actively logged in.
    """
    __tablename__ = "sister_pings"

    PING_TTL_MINUTES = 90  # Auto-expire after this many minutes
    DEFAULT_RADIUS_MILES = 2.0  # Alert Sisters within this radius

    id              = Column(Integer, primary_key=True, index=True)
    sister_id       = Column(Integer, ForeignKey("sisters.id"), nullable=False)

    # Location — ephemeral, rounded, erased on resolution/expiry
    lat             = Column(Float, nullable=True)   # Rounded to 4 decimal places
    lng             = Column(Float, nullable=True)   # Rounded to 4 decimal places
    accuracy_meters = Column(Float, nullable=True)   # GPS accuracy at ping time

    # Context (optional — Sister can add a brief note)
    # e.g. "parking garage level 3" or "followed from bus stop"
    # No names, no identifying info required
    context         = Column(String(200), nullable=True)

    # Status and timing
    status          = Column(String(20), default=PingStatus.ACTIVE)
    created_at      = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at      = Column(DateTime, nullable=False)  # Set at creation
    resolved_at     = Column(DateTime, nullable=True)

    # How many Sisters were notified
    notified_count  = Column(Integer, default=0)
    response_count  = Column(Integer, default=0)

    sister          = relationship("Sister", back_populates="pings",
                                   foreign_keys=[sister_id])
    responses       = relationship("SisterResponse", back_populates="ping")

    def is_active(self) -> bool:
        """True if the ping is still live and not expired."""
        if self.status not in (PingStatus.ACTIVE, PingStatus.RESPONDED):
            return False
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return True

    def erase_location(self):
        """
        Called on resolution or expiry.
        Erases the precise location — the ping record remains for audit
        but no one can retrieve where the Sister was.
        """
        self.lat = None
        self.lng = None
        self.accuracy_meters = None


class SisterResponse(Base):
    """
    A Sister's response to a distress ping.

    CRITICAL PRIVACY DESIGN:
    - The responder's lat/lng are shared ONLY with the pinging Sister,
      and ONLY while the ping is active.
    - Responder location is erased when the ping resolves or expires.
    - Responders are identified by display_name only — not username/email.
    """
    __tablename__ = "sister_responses"

    id              = Column(Integer, primary_key=True, index=True)
    ping_id         = Column(Integer, ForeignKey("sister_pings.id"), nullable=False)
    responder_id    = Column(Integer, ForeignKey("sisters.id"), nullable=False)

    # Responder location at time of response — ephemeral, erased with ping
    responder_lat   = Column(Float, nullable=True)
    responder_lng   = Column(Float, nullable=True)

    status          = Column(String(20), default=ResponseStatus.ACKNOWLEDGED)
    responded_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    arrived_at      = Column(DateTime, nullable=True)

    ping            = relationship("SisterPing", back_populates="responses")
    responder       = relationship("Sister", back_populates="responses")

    def erase_location(self):
        """Erases responder location on ping resolution."""
        self.responder_lat = None
        self.responder_lng = None


# ── Database Init ─────────────────────────────────────────────────────────────

def init_db():
    Base.metadata.create_all(bind=engine)
    print("[Sisters] Database tables initialized.")

def get_session():
    return SessionLocal()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Geospatial ────────────────────────────────────────────────────────────────
# Haversine formula — adapted from Themis (argos.py)
# Gives distance in miles between two lat/lng points.

def haversine_miles(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Calculate distance in miles between two GPS coordinates.
    Uses the Haversine formula — accurate for distances < 500 miles.
    Adapted from Themis ArgosScanner.
    """
    R = 3956.0  # Earth radius in miles
    d_lat = math.radians(lat2 - lat1)
    d_lng = math.radians(lng2 - lng1)
    a = (math.sin(d_lat / 2) ** 2 +
         math.cos(math.radians(lat1)) *
         math.cos(math.radians(lat2)) *
         math.sin(d_lng / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def round_location(lat: float, lng: float):
    """
    Round coordinates to 4 decimal places (~11 meter precision).
    Enough to find someone. Not enough for surveillance.
    """
    return round(lat, 4), round(lng, 4)


def get_active_pings_near(lat: float, lng: float,
                           radius_miles: float = 2.0) -> list:
    """
    Return all active pings within radius_miles of the given location.
    Used to alert Sisters nearby when a ping is sent.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        # Pull all active pings — filter by distance in Python
        # (For large deployments, use PostGIS. For MVP this is fine.)
        pings = session.query(SisterPing).filter(
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at > now,
            SisterPing.lat.isnot(None),
            SisterPing.lng.isnot(None),
        ).all()

        nearby = []
        for ping in pings:
            dist = haversine_miles(lat, lng, ping.lat, ping.lng)
            if dist <= radius_miles:
                nearby.append({
                    "ping_id":       ping.id,
                    "distance_miles": round(dist, 2),
                    "lat":            ping.lat,
                    "lng":            ping.lng,
                    "context":        ping.context,
                    "status":         ping.status,
                    "created_at":     ping.created_at.isoformat(),
                    "expires_at":     ping.expires_at.isoformat(),
                    "response_count": ping.response_count,
                })
        return sorted(nearby, key=lambda x: x["distance_miles"])
    except Exception as e:
        print(f"[Sisters DB] get_active_pings_near error: {e}")
        return []
    finally:
        session.close()


def expire_old_pings():
    """
    Mark expired pings and erase their location data.
    Call this on a background schedule — every few minutes.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)
        expired = session.query(SisterPing).filter(
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at <= now,
        ).all()

        for ping in expired:
            ping.status = PingStatus.EXPIRED
            ping.erase_location()
            for response in ping.responses:
                response.erase_location()

        if expired:
            session.commit()
            print(f"[Sisters] Expired and erased location for {len(expired)} ping(s).")
    except Exception as e:
        session.rollback()
        print(f"[Sisters DB] expire_old_pings error: {e}")
    finally:
        session.close()


def create_ping(sister_id: int, lat: float, lng: float,
                accuracy_meters: float = None,
                context: str = None,
                radius_miles: float = 2.0) -> dict:
    """
    Create a new distress ping.
    Returns the ping dict or an error.
    """
    session = get_session()
    try:
        # Check sister exists and is active
        sister = session.query(Sister).filter(
            Sister.id == sister_id,
            Sister.is_network_active == True,
            Sister.is_suspended == False,
        ).first()

        if not sister:
            return {"ok": False, "error": "Not authorized to send a ping."}

        # Check for existing active ping from this sister
        now = datetime.now(timezone.utc)
        existing = session.query(SisterPing).filter(
            SisterPing.sister_id == sister_id,
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at > now,
        ).first()

        if existing:
            return {"ok": False, "error": "You already have an active ping.",
                    "ping_id": existing.id}

        # Round location for privacy
        rlat, rlng = round_location(lat, lng)

        # Clean context
        safe_context = None
        if context:
            safe_context = context.strip()[:200]

        ping = SisterPing(
            sister_id       = sister_id,
            lat             = rlat,
            lng             = rlng,
            accuracy_meters = accuracy_meters,
            context         = safe_context,
            status          = PingStatus.ACTIVE,
            created_at      = now,
            expires_at      = now + timedelta(minutes=SisterPing.PING_TTL_MINUTES),
        )
        session.add(ping)

        # Update sister stats
        sister.pings_sent += 1
        sister.last_active = now

        session.commit()
        session.refresh(ping)

        return {
            "ok":         True,
            "ping_id":    ping.id,
            "expires_at": ping.expires_at.isoformat(),
            "lat":        ping.lat,
            "lng":        ping.lng,
        }

    except Exception as e:
        session.rollback()
        print(f"[Sisters DB] create_ping error: {e}")
        return {"ok": False, "error": "Failed to send ping. Please try again."}
    finally:
        session.close()


def resolve_ping(ping_id: int, sister_id: int) -> dict:
    """
    Mark a ping as resolved — Sister is safe.
    Erases location data immediately.
    """
    session = get_session()
    try:
        ping = session.query(SisterPing).filter(
            SisterPing.id == ping_id,
            SisterPing.sister_id == sister_id,
        ).first()

        if not ping:
            return {"ok": False, "error": "Ping not found."}

        ping.status = PingStatus.RESOLVED
        ping.resolved_at = datetime.now(timezone.utc)
        ping.erase_location()

        for response in ping.responses:
            response.erase_location()

        session.commit()
        return {"ok": True}

    except Exception as e:
        session.rollback()
        print(f"[Sisters DB] resolve_ping error: {e}")
        return {"ok": False, "error": "Failed to resolve ping."}
    finally:
        session.close()


def respond_to_ping(ping_id: int, responder_id: int,
                    responder_lat: float, responder_lng: float) -> dict:
    """
    A Sister responds to a ping — confirms she is coming.
    """
    session = get_session()
    try:
        now = datetime.now(timezone.utc)

        ping = session.query(SisterPing).filter(
            SisterPing.id == ping_id,
            SisterPing.status.in_([PingStatus.ACTIVE, PingStatus.RESPONDED]),
            SisterPing.expires_at > now,
        ).first()

        if not ping:
            return {"ok": False, "error": "Ping is no longer active."}

        if ping.sister_id == responder_id:
            return {"ok": False, "error": "Cannot respond to your own ping."}

        # Check for duplicate response
        existing = session.query(SisterResponse).filter(
            SisterResponse.ping_id == ping_id,
            SisterResponse.responder_id == responder_id,
        ).first()

        if existing:
            # Update to en_route if they're confirming
            existing.status = ResponseStatus.EN_ROUTE
            existing.responder_lat = round(responder_lat, 4)
            existing.responder_lng = round(responder_lng, 4)
            session.commit()
            return {"ok": True, "response_id": existing.id}

        rlat, rlng = round_location(responder_lat, responder_lng)

        response = SisterResponse(
            ping_id       = ping_id,
            responder_id  = responder_id,
            responder_lat = rlat,
            responder_lng = rlng,
            status        = ResponseStatus.EN_ROUTE,
            responded_at  = now,
        )
        session.add(response)

        # Update ping status and count
        ping.status = PingStatus.RESPONDED
        ping.response_count += 1

        # Update responder stats
        responder = session.query(Sister).filter(
            Sister.id == responder_id).first()
        if responder:
            responder.responses_given += 1
            responder.last_active = now

        session.commit()
        session.refresh(response)

        return {"ok": True, "response_id": response.id}

    except Exception as e:
        session.rollback()
        print(f"[Sisters DB] respond_to_ping error: {e}")
        return {"ok": False, "error": "Failed to register response."}
    finally:
        session.close()
