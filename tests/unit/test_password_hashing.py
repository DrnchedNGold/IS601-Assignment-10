import pytest
from app.models.user import User

def test_hash_password_is_different():
    raw_password = "SecurePass123"
    hashed = User.hash_password(raw_password)
    assert hashed != raw_password
    assert isinstance(hashed, str)

def test_verify_password_success():
    raw_password = "SecurePass123"
    hashed = User.hash_password(raw_password)
    assert User.verify_password_static(raw_password, hashed)

def test_verify_password_failure():
    raw_password = "SecurePass123"
    wrong_password = "WrongPass"
    hashed = User.hash_password(raw_password)
    assert not User.verify_password_static(wrong_password, hashed)
