import uuid 
from datetime import datetime, timezone 
from typing import List, Optional
from sqlalchemy import String, DateTime, ForeignKey, Integer, CheckConstraint 
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, BYTEA 
from app.db.base import Base 


class TimestampMixin:
    """Reusable mixin for UTC timestamp fields."""
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    __table_args__ = (
        CheckConstraint("OCTET_LENGTH(kdf_salt) >= 16", name="check_kdf_salt_length"),  
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    email: Mapped[str] = mapped_column(
        String(255),
        nullable=False, 
        unique=True,
        index=True
    )

    kdf_salt: Mapped[bytes] = mapped_column(
        BYTEA,
        nullable=False,
    )

    # KDF parameters
    kdf_memory: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=65536
    )
    
    kdf_iterations: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3
    )
    
    kdf_parallelism: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=4
    )

    server_password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

  
    auth_challenges: Mapped[List["AuthChallenge"]] = relationship(
        back_populates="user", 
        cascade="all, delete-orphan"
    )

    vault_items: Mapped[List["VaultItem"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )


class AuthChallenge(Base, TimestampMixin):
    __tablename__ = "auth_challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    challenge: Mapped[bytes] = mapped_column(
        BYTEA,
        nullable=False
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), 
        index=True,
        nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="auth_challenges")


class VaultItem(Base, TimestampMixin):
    __tablename__ = "vault_items"

    __table_args__ = (
        CheckConstraint("OCTET_LENGTH(nonce) = 12", name="check_nonce_length"),  # Added comma
        CheckConstraint("OCTET_LENGTH(auth_tag) = 16", name="check_auth_tag_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        primary_key=True
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False
    )

    nonce: Mapped[bytes] = mapped_column(
        BYTEA,
        nullable=False
    )

    ciphertext: Mapped[bytes] = mapped_column(
        BYTEA,
        nullable=False
    )

    auth_tag: Mapped[bytes] = mapped_column( 
        BYTEA,
        nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="vault_items")