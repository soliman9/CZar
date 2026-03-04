import os
import json
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
import logging


class UserManager:
    """Manages user accounts and authentication."""

    def __init__(self, currentOS):
        self.currentOS = currentOS
        self.users_file = "users.json"
        self.ph = PasswordHasher()
        self._ensure_users_file_exists()

    def _ensure_users_file_exists(self):
        """Create users.json if it doesn't exist."""
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _load_users(self):
        """Load user data from users.json."""
        try:
            with open(self.users_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_users(self, users_data):
        """Save user data to users.json."""
        with open(self.users_file, "w", encoding="utf-8") as f:
            json.dump(users_data, f, indent=2)

    def user_exists(self, username):
        """Check if a user account exists."""
        users = self._load_users()
        return username in users

    def create_user(self, username, password):
        """Create a new user account."""
        if self.user_exists(username):
            return False, "User already exists"

        users = self._load_users()
        try:
            hashed_password = self.ph.hash(password)
            users[username] = {
                "password_hash": hashed_password,
                "created": True
            }
            self._save_users(users)

            # Create user-specific data directory
            self._create_user_data_directory(username)
            return True, "User created successfully"
        except (InvalidHash, OSError) as e:
            logging.error("User creation failed: %s", str(e))
            return False, "Failed to create user"

    def authenticate_user(self, username, password):
        """Authenticate a user with username and password."""
        users = self._load_users()
        if username not in users:
            return False, "User not found"

        try:
            stored_hash = users[username]["password_hash"]
            self.ph.verify(stored_hash, password)
            return True, "Authentication successful"
        except VerifyMismatchError:
            logging.error("Authentication failed for user %s", username)
            return False, "Invalid password"

    def _create_user_data_directory(self, username):
        """Create a data directory for the user."""
        if self.currentOS == "Windows":
            user_dir = f"data/{username}"
            try:
                os.makedirs(user_dir, exist_ok=True)
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(user_dir, 0x02)
            except OSError as e:
                logging.error("Failed to create user directory: %s", str(e))
        elif self.currentOS == "Linux":
            user_dir = f".data/{username}"
            try:
                os.makedirs(user_dir, exist_ok=True)
            except OSError as e:
                logging.error("Failed to create user directory: %s", str(e))

    def get_user_data_dir(self, username):
        """Get the data directory path for a user."""
        if self.currentOS == "Windows":
            return f"data/{username}"
        elif self.currentOS == "Linux":
            return f".data/{username}"
        else:
            return None

    def list_users(self):
        """List all registered users."""
        users = self._load_users()
        return list(users.keys())
