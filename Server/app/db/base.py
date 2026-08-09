from sqlalchemy.orm import DeclarativeBase

class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models in SecureBox.
    Maintains schema metadata and provides a unified parent class for all models.
    """
    pass
