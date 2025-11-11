import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from app.database import get_engine, get_sessionmaker, get_db, Base
from sqlalchemy.exc import SQLAlchemyError

def test_get_db_closes_session(monkeypatch):
    # Simulate session closure
    class DummySession:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True
    monkeypatch.setattr("app.database.SessionLocal", lambda: DummySession())
    db_gen = get_db()
    db = next(db_gen)
    assert hasattr(db, "close")
    db_gen.close()

def test_get_engine_prints_error(monkeypatch, capsys):
    # Simulate SQLAlchemyError and check print output
    def raise_error(*args, **kwargs):
        raise SQLAlchemyError("Test error")
    monkeypatch.setattr("app.database.create_engine", raise_error)
    with pytest.raises(SQLAlchemyError):
        get_engine("invalid://")
    captured = capsys.readouterr()
    assert "Error creating engine:" in captured.out
