"""
Database models and setup for VulnMaster.
Uses SQLite with async SQLAlchemy 2.0 syntax.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column
from sqlalchemy import String, Integer, Text, DateTime, ForeignKey, Index
from datetime import datetime
from typing import Optional, List
import logging

# SQLite database file (using aiosqlite for async support)
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./vulnmaster.db"

# Create async database engine
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=False,
    future=True
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

# Base class for models (SQLAlchemy 2.0 style)
class Base(DeclarativeBase):
    pass


class Scan(Base):
    """Model for storing scan records."""
    __tablename__ = "scans"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target_url: Mapped[str] = mapped_column(String, nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String, nullable=False)  # e.g., "SQL Injection"
    status: Mapped[str] = mapped_column(String, default="pending", index=True)  # pending, running, completed, failed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    # Relationship to vulnerabilities
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", 
        back_populates="scan", 
        cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    """Model for storing detected vulnerabilities with educational Blue Team fields."""
    __tablename__ = "vulnerabilities"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    
    name: Mapped[str] = mapped_column(String, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String, nullable=False, index=True)  # Critical, High, Medium, Low
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Educational Blue Team fields
    attack: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # CURL command (Red Team PoC)
    cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Vulnerable code snippet
    fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Secure code snippet
    why: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Explanation of why fix works
    
    # Legacy fields (for backward compatibility)
    poc_command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Deprecated, use 'attack'
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Deprecated, use 'fix' and 'why'
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationship to scan
    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")


class Note(Base):
    """Model for storing user notes on vulnerabilities."""
    __tablename__ = "notes"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Relationship to vulnerability
    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability")


async def init_db():
    """Initialize the database by creating all tables and indexes."""
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
        
        # Create composite indexes for common query patterns
        # Note: Indexes on columns are already created via mapped_column(index=True)
        # These composite indexes provide additional optimization for specific queries
        try:
            # SQLite syntax for creating indexes (using text() for raw SQL)
            from sqlalchemy import text
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_vulns_scan_severity ON vulnerabilities(scan_id, severity)"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_scans_status_created ON scans(status, created_at)"
            ))
        except Exception as e:
            # Indexes may already exist, ignore
            logger = logging.getLogger(__name__)
            logger.debug(f"Index creation skipped (may already exist): {e}")


async def get_db() -> AsyncSession:
    """
    Dependency function to get async database session.
    Yields a database session and ensures it's closed after use.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
