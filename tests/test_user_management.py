"""
Unit tests for userManagement module.
"""

import unittest
import tempfile
import json
import os
from userManagement import UserManager


class TestUserManagement(unittest.TestCase):
    """Test cases for UserManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        os.chdir(self.original_cwd)
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_user_manager_initialization(self):
        """Test UserManager initializes correctly."""
        manager = UserManager("Windows")
        self.assertIsNotNone(manager)
        self.assertEqual(manager.currentOS, "Windows")

    def test_create_user(self):
        """Test user creation."""
        manager = UserManager("Windows")
        success, msg = manager.create_user("testuser", "password123")
        self.assertTrue(success)
        self.assertIn("created", msg.lower())

    def test_user_exists(self):
        """Test checking if user exists."""
        manager = UserManager("Windows")
        manager.create_user("testuser", "password123")
        self.assertTrue(manager.user_exists("testuser"))
        self.assertFalse(manager.user_exists("nonexistent"))

    def test_authenticate_user(self):
        """Test user authentication."""
        manager = UserManager("Windows")
        manager.create_user("testuser", "password123")

        # Test correct password
        success, msg = manager.authenticate_user("testuser", "password123")
        self.assertTrue(success)

        # Test wrong password
        success, msg = manager.authenticate_user("testuser", "wrongpassword")
        self.assertFalse(success)

    def test_authenticate_nonexistent_user(self):
        """Test authentication with non-existent user."""
        manager = UserManager("Windows")
        success, msg = manager.authenticate_user("nouser", "password")
        self.assertFalse(success)
        self.assertIn("not found", msg.lower())

    def test_duplicate_user_creation(self):
        """Test that duplicate users cannot be created."""
        manager = UserManager("Windows")
        manager.create_user("testuser", "password123")

        success, msg = manager.create_user("testuser", "different123")
        self.assertFalse(success)
        self.assertIn("already exists", msg.lower())

    def test_users_file_creation(self):
        """Test that users.json is created."""
        manager = UserManager("Windows")
        manager.create_user("testuser", "password123")

        users_file = os.path.join("data", "users.json")
        self.assertTrue(os.path.exists(users_file))

        with open(users_file, 'r', encoding='utf-8') as f:
            users_data = json.load(f)
        self.assertIn("testuser", users_data)


if __name__ == '__main__':
    unittest.main()
