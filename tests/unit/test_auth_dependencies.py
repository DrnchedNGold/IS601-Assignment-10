import pytest
from fastapi import HTTPException, status
from app.auth.dependencies import get_current_user, get_current_active_user
from app.models.user import User
from app.schemas.user import UserResponse

class MockDB:
    def __init__(self, user=None):
        self._user = user
    def query(self, model):
        return self
    def filter(self, cond):
        return self
    def first(self):
        return self._user

from uuid import uuid4
from datetime import datetime

class MockUser:
    id = uuid4()
    username = "testuser"
    email = "test@example.com"
    first_name = "Test"
    last_name = "User"
    is_active = True
    is_verified = True
    created_at = datetime.utcnow()
    updated_at = datetime.utcnow()

class MockInactiveUser(MockUser):
    is_active = False
    is_verified = False
    username = "inactiveuser"
    email = "inactive@example.com"
    first_name = "Inactive"
    last_name = "User"

def test_get_current_user_valid(monkeypatch):
    user = MockUser()
    db = MockDB(user=user)
    monkeypatch.setattr(User, "verify_token", lambda token: 1)
    result = get_current_user(db, token="validtoken")
    assert isinstance(result, UserResponse)
    assert result.is_active is True

def test_get_current_user_invalid_token(monkeypatch):
    db = MockDB()
    monkeypatch.setattr(User, "verify_token", lambda token: None)
    with pytest.raises(HTTPException) as exc:
        get_current_user(db, token="badtoken")
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_user_user_not_found(monkeypatch):
    db = MockDB(user=None)
    monkeypatch.setattr(User, "verify_token", lambda token: 1)
    with pytest.raises(HTTPException) as exc:
        get_current_user(db, token="validtoken")
    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_active_user_active(monkeypatch):
    user = MockUser()
    user_response = UserResponse.model_validate(user)
    result = get_current_active_user(current_user=user_response)
    assert isinstance(result, UserResponse)
    assert result.is_active is True

def test_get_current_active_user_inactive(monkeypatch):
    user = MockInactiveUser()
    user_response = UserResponse.model_validate(user)
    with pytest.raises(HTTPException) as exc:
        get_current_active_user(current_user=user_response)
    assert exc.value.status_code == status.HTTP_400_BAD_REQUEST
