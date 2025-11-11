import pytest
from app.models.user import User
from uuid import uuid4
from jose import JWTError

def test_hash_password_and_verify():
    pw = "SecurePass123"
    hashed = User.hash_password(pw)
    assert User.verify_password_static(pw, hashed)
    assert not User.verify_password_static("WrongPass", hashed)

def test_create_access_token_and_verify():
    user_id = str(uuid4())
    token = User.create_access_token({"sub": user_id})
    decoded_id = User.verify_token(token)
    assert str(decoded_id) == user_id

def test_create_access_token_custom_expiry():
    user_id = str(uuid4())
    import datetime
    token = User.create_access_token({"sub": user_id}, expires_delta=datetime.timedelta(seconds=1))
    decoded_id = User.verify_token(token)
    assert str(decoded_id) == user_id

def test_verify_token_invalid():
    assert User.verify_token("invalid.token") is None

def test_verify_token_missing_sub():
    import jwt
    from app.models.user import SECRET_KEY, ALGORITHM
    token = jwt.encode({"exp": 9999999999}, SECRET_KEY, algorithm=ALGORITHM)
    assert User.verify_token(token) is None

def test_verify_token_expired():
    import datetime, jwt
    from app.models.user import SECRET_KEY, ALGORITHM
    expired_token = jwt.encode({"sub": str(uuid4()), "exp": datetime.datetime.utcnow() - datetime.timedelta(minutes=1)}, SECRET_KEY, algorithm=ALGORITHM)
    assert User.verify_token(expired_token) is None

def test_repr_method():
    user = User(
        first_name="A",
        last_name="B",
        email="repr@example.com",
        username="repruser",
        password=User.hash_password("SecurePass123"),
        is_active=True,
        is_verified=False
    )
    assert "<User(name=A B, email=repr@example.com)>" in repr(user)

def test_register_validation_error(db_session):
    bad_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "not-an-email",
        "username": "user",
        "password": "SecurePass123"
    }
    with pytest.raises(ValueError):
        User.register(db_session, bad_data)

def test_register_duplicate_email(db_session):
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "test@example.com",
        "username": "user1",
        "password": "SecurePass123"
    }
    User.register(db_session, user_data)
    with pytest.raises(ValueError):
        User.register(db_session, {**user_data, "username": "user2"})

def test_register_duplicate_username(db_session):
    import uuid
    unique_username = f"user_{uuid.uuid4().hex}"
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": f"{unique_username}@example.com",
        "username": unique_username,
        "password": "SecurePass123"
    }
    # First registration should succeed
    User.register(db_session, user_data)
    # Second registration with same username should fail
    with pytest.raises(ValueError):
        User.register(db_session, {**user_data, "email": f"other_{unique_username}@example.com"})

def test_register_invalid_password(db_session):
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "badpw@example.com",
        "username": "badpwuser",
        "password": "short"
    }
    with pytest.raises(ValueError):
        User.register(db_session, user_data)

def test_authenticate_success(db_session):
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "auth@example.com",
        "username": "authuser",
        "password": "SecurePass123"
    }
    user = User.register(db_session, user_data)
    token = User.authenticate(db_session, "authuser", "SecurePass123")
    assert token is not None
    assert "access_token" in token
    assert "user" in token
    assert token["user"]["username"] == "authuser"

def test_authenticate_failure(db_session):
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "fail@example.com",
        "username": "failuser",
        "password": "SecurePass123"
    }
    User.register(db_session, user_data)
    token = User.authenticate(db_session, "failuser", "WrongPass")
    assert token is None

def test_authenticate_with_email(db_session):
    user_data = {
        "first_name": "A",
        "last_name": "B",
        "email": "emailauth@example.com",
        "username": "emailuser",
        "password": "SecurePass123"
    }
    User.register(db_session, user_data)
    token = User.authenticate(db_session, "emailauth@example.com", "SecurePass123")
    assert token is not None

def test_authenticate_nonexistent_user(db_session):
    token = User.authenticate(db_session, "nouser", "nopass")
    assert token is None

def test_register_validationerror_branch(db_session):
    # This triggers Pydantic ValidationError for missing required fields
    bad_data = {
        "first_name": "A",
        "last_name": "B",
        "username": "user",
        "password": "SecurePass123"
        # missing email
    }
    with pytest.raises(ValueError):
        User.register(db_session, bad_data)
