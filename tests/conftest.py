"""
Pytest configuration and fixtures
"""
import pytest
import os

# Set test environment variables before importing app
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key-for-testing'
os.environ['STRIPE_SECRET_KEY'] = 'sk_test_fake'
os.environ['STRIPE_WEBHOOK_SECRET'] = 'whsec_fake'
