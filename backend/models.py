
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.sql import func

from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    event_type = Column(String(100), nullable=False)
    description = Column(String(500))
    is_attack = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())



from sqlalchemy import ForeignKey, Text


class UserPrivateData(Base):
    __tablename__ = "user_private_data"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    encrypted_value = Column(Text, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
