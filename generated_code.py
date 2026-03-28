from typing import Optional
from pydantic import BaseModel
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], default="pbkdf2_sha256",
                           hashfunc="sha256",
                           salt_size=8,
                           verkey_size=32,
                           rounds=29000)

class User(BaseModel):
    """ User model """
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    """ Login request model """
    username: str
    password: str
    token: Optional[str] = None

def hash_password(password: str):
    """ Hash a password using Passlib """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    """ Verify a password using Passlib """
    return pwd_context.verify(plain_password, hashed_password)

def add_user(username: str, email: str, password: str) -> User:
    """ Add a new user """
    try:
        hashed_password = hash_password(password)
        user = User(username=username, email=email, password=hashed_password)
        return user
    except Exception as e:
        print(f"Error adding user: {e}")
        return None

def login_user(username: str, password: str) -> dict:
    """ Login a user """
    try:
        user = add_user(username, "", password)
        if user is not None:
            # Generate token for user
            token = "your_token_generation_logic_here"
            return {"user": {"username": username, "email": "", "token": token}}

        # Check if hashed user exists
        user = get_user(username)
        if user:
            # Verify password for existing user
            if verify_password(password, user.password):
                # Generate token for user
                token = "your_token_generation_logic_here"
                return {"user": {"username": username, "email": user.email, "token": token}}
        print("Invalid username or password")
        return None

    except Exception as e:
        print(f"Error logging in user: {e}")
        return None

def get_user(username: str) -> Optional[User]:
    """ Get user by username """
    try:
        # Assuming users are stored in a MongoDB or a database
        user = User(username=username, email="", password="")
        return user
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

if __name__ == "__main__":
    user = add_user("test_user", "test@example.com", "password123")
    print(user.username)
    print(get_user("test_user").username)
    print(login_user("test_user", "password123"))
    print(login_user("test_user", "wrong_password"))