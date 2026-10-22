"""Small standard-library tests for password hashing."""
import unittest
from main import hash_password, verify_password


class PasswordHashTests(unittest.TestCase):
    def test_correct_password_verifies(self):
        salt, digest = hash_password("ExamplePass123")
        self.assertTrue(verify_password("ExamplePass123", salt, digest))

    def test_wrong_password_fails(self):
        salt, digest = hash_password("ExamplePass123")
        self.assertFalse(verify_password("WrongPassword123", salt, digest))

    def test_same_password_uses_random_salt(self):
        salt1, digest1 = hash_password("ExamplePass123")
        salt2, digest2 = hash_password("ExamplePass123")
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(digest1, digest2)


if __name__ == "__main__":
    unittest.main()
