"""
Global Pytest Configuration and Test Environment Fixtures
Configures test secrets and isolated database parameters.
"""

import os
import pytest

TEST_JWT_SECRET = "8f3a5b2c9d1e4f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd"
TEST_MANIFEST_SECRET = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

# Configure valid test environment variables before any tests import security/database
os.environ["JWT_SECRET_KEY"] = TEST_JWT_SECRET
os.environ["MANIFEST_SIGNING_SECRET"] = TEST_MANIFEST_SECRET
os.environ["JWT_ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"


@pytest.fixture(autouse=True)
def reset_test_environment(monkeypatch):
    """Ensures consistent test secrets are available for all tests."""
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_JWT_SECRET)
    monkeypatch.setenv("MANIFEST_SIGNING_SECRET", TEST_MANIFEST_SECRET)
    monkeypatch.setenv("JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
