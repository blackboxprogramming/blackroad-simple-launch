"""
BlackRoad OS - API Test Suite
Run with: pytest tests/ -v
"""

import pytest
import json
from datetime import datetime, timedelta

# Import app after setting test config
import os
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['STRIPE_SECRET_KEY'] = 'sk_test_fake'

from app import app, db, User, Event, NewsletterSubscriber, ContactSubmission


@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()


@pytest.fixture
def auth_headers(client):
    """Create authenticated user and return headers"""
    # Register user
    response = client.post('/api/auth/register', json={
        'email': 'test@example.com',
        'password': 'password123',
        'name': 'Test User'
    })
    data = json.loads(response.data)
    token = data['access_token']
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def admin_headers(client):
    """Create admin user and return headers"""
    with app.app_context():
        admin = User(
            email='admin@example.com',
            name='Admin User',
            is_admin=True
        )
        admin.set_password('adminpass123')
        db.session.add(admin)
        db.session.commit()

    response = client.post('/api/auth/login', json={
        'email': 'admin@example.com',
        'password': 'adminpass123'
    })
    data = json.loads(response.data)
    token = data['access_token']
    return {'Authorization': f'Bearer {token}'}


# ===========================================
# Health Check Tests
# ===========================================

class TestHealth:
    def test_health_check(self, client):
        """Test health endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data

    def test_api_status(self, client):
        """Test API status endpoint"""
        response = client.get('/api/status')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'operational'


# ===========================================
# Authentication Tests
# ===========================================

class TestAuthentication:
    def test_register_success(self, client):
        """Test successful registration"""
        response = client.post('/api/auth/register', json={
            'email': 'new@example.com',
            'password': 'password123',
            'name': 'New User'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['user']['email'] == 'new@example.com'

    def test_register_duplicate_email(self, client):
        """Test registration with existing email"""
        client.post('/api/auth/register', json={
            'email': 'existing@example.com',
            'password': 'password123',
            'name': 'User'
        })
        response = client.post('/api/auth/register', json={
            'email': 'existing@example.com',
            'password': 'password456',
            'name': 'Another User'
        })
        assert response.status_code == 409
        data = json.loads(response.data)
        assert 'already registered' in data['error']

    def test_register_short_password(self, client):
        """Test registration with short password"""
        response = client.post('/api/auth/register', json={
            'email': 'test@example.com',
            'password': 'short',
            'name': 'User'
        })
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'at least 8 characters' in data['error']

    def test_login_success(self, client):
        """Test successful login"""
        # First register
        client.post('/api/auth/register', json={
            'email': 'login@example.com',
            'password': 'password123',
            'name': 'User'
        })
        # Then login
        response = client.post('/api/auth/login', json={
            'email': 'login@example.com',
            'password': 'password123'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'access_token' in data

    def test_login_wrong_password(self, client):
        """Test login with wrong password"""
        client.post('/api/auth/register', json={
            'email': 'test@example.com',
            'password': 'password123',
            'name': 'User'
        })
        response = client.post('/api/auth/login', json={
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user"""
        response = client.post('/api/auth/login', json={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        })
        assert response.status_code == 401

    def test_get_current_user(self, client, auth_headers):
        """Test getting current user"""
        response = client.get('/api/auth/me', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['email'] == 'test@example.com'

    def test_unauthorized_access(self, client):
        """Test accessing protected endpoint without auth"""
        response = client.get('/api/auth/me')
        assert response.status_code == 401

    def test_update_profile(self, client, auth_headers):
        """Test profile update"""
        response = client.put('/api/auth/update', json={
            'name': 'Updated Name'
        }, headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user']['name'] == 'Updated Name'


# ===========================================
# Dashboard Tests
# ===========================================

class TestDashboard:
    def test_get_dashboard_stats(self, client, auth_headers):
        """Test dashboard stats endpoint"""
        response = client.get('/api/dashboard/stats', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'user' in data
        assert 'stats' in data

    def test_get_usage_stats(self, client, auth_headers):
        """Test usage stats endpoint"""
        response = client.get('/api/dashboard/usage', headers=auth_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'usage_by_day' in data


# ===========================================
# Newsletter Tests
# ===========================================

class TestNewsletter:
    def test_subscribe_success(self, client):
        """Test newsletter subscription"""
        response = client.post('/api/newsletter/subscribe', json={
            'email': 'subscriber@example.com',
            'name': 'Subscriber',
            'source': 'test'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'subscribed' in data['message'].lower()

    def test_subscribe_duplicate(self, client):
        """Test duplicate subscription"""
        client.post('/api/newsletter/subscribe', json={
            'email': 'subscriber@example.com',
            'name': 'First'
        })
        response = client.post('/api/newsletter/subscribe', json={
            'email': 'subscriber@example.com',
            'name': 'Second'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'already' in data['message'].lower()

    def test_subscribe_missing_email(self, client):
        """Test subscription without email"""
        response = client.post('/api/newsletter/subscribe', json={
            'name': 'User'
        })
        assert response.status_code == 400


# ===========================================
# Contact Form Tests
# ===========================================

class TestContact:
    def test_submit_contact_success(self, client):
        """Test contact form submission"""
        response = client.post('/api/contact', json={
            'name': 'Test User',
            'email': 'test@example.com',
            'message': 'This is a test message',
            'company': 'Test Corp'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'success' in data['message'].lower()

    def test_submit_contact_missing_fields(self, client):
        """Test contact form with missing required fields"""
        response = client.post('/api/contact', json={
            'name': 'Test User',
            'email': 'test@example.com'
            # Missing message
        })
        assert response.status_code == 400


# ===========================================
# Affiliate Tests
# ===========================================

class TestAffiliate:
    def test_affiliate_signup_success(self, client):
        """Test affiliate signup"""
        response = client.post('/api/affiliate/signup', json={
            'name': 'Affiliate User',
            'email': 'affiliate@example.com',
            'website': 'https://example.com'
        })
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'referral_code' in data

    def test_affiliate_signup_duplicate(self, client):
        """Test duplicate affiliate signup"""
        client.post('/api/affiliate/signup', json={
            'name': 'First',
            'email': 'affiliate@example.com'
        })
        response = client.post('/api/affiliate/signup', json={
            'name': 'Second',
            'email': 'affiliate@example.com'
        })
        assert response.status_code == 409


# ===========================================
# Admin Tests
# ===========================================

class TestAdmin:
    def test_admin_stats_authorized(self, client, admin_headers):
        """Test admin stats with admin user"""
        response = client.get('/api/admin/stats', headers=admin_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'users' in data
        assert 'revenue' in data

    def test_admin_stats_unauthorized(self, client, auth_headers):
        """Test admin stats with regular user"""
        response = client.get('/api/admin/stats', headers=auth_headers)
        assert response.status_code == 403

    def test_admin_users_list(self, client, admin_headers):
        """Test admin users list"""
        response = client.get('/api/admin/users', headers=admin_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'users' in data
        assert 'total' in data

    def test_admin_contacts_list(self, client, admin_headers):
        """Test admin contacts list"""
        response = client.get('/api/admin/contacts', headers=admin_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'submissions' in data

    def test_admin_events_list(self, client, admin_headers):
        """Test admin events list"""
        response = client.get('/api/admin/events', headers=admin_headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'events' in data


# ===========================================
# Password Reset Tests
# ===========================================

class TestPasswordReset:
    def test_forgot_password_success(self, client):
        """Test forgot password request"""
        # First create a user
        client.post('/api/auth/register', json={
            'email': 'reset@example.com',
            'password': 'oldpassword123',
            'name': 'User'
        })

        response = client.post('/api/auth/forgot-password', json={
            'email': 'reset@example.com'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'link has been sent' in data['message']

    def test_forgot_password_nonexistent(self, client):
        """Test forgot password for non-existent user"""
        response = client.post('/api/auth/forgot-password', json={
            'email': 'nonexistent@example.com'
        })
        # Should still return 200 to prevent email enumeration
        assert response.status_code == 200

    def test_reset_password_invalid_token(self, client):
        """Test reset password with invalid token"""
        response = client.post('/api/auth/reset-password', json={
            'token': 'invalid-token',
            'password': 'newpassword123'
        })
        assert response.status_code == 400


# ===========================================
# Model Tests
# ===========================================

class TestModels:
    def test_user_password_hashing(self, client):
        """Test user password is hashed"""
        with app.app_context():
            user = User(email='hash@example.com', name='Test')
            user.set_password('mypassword')

            assert user.password_hash is not None
            assert user.password_hash != 'mypassword'
            assert user.check_password('mypassword')
            assert not user.check_password('wrongpassword')

    def test_user_to_dict(self, client):
        """Test user to_dict method"""
        with app.app_context():
            user = User(
                email='dict@example.com',
                name='Test User',
                subscription_status='trial',
                subscription_tier='founding'
            )
            db.session.add(user)
            db.session.commit()

            user_dict = user.to_dict()
            assert user_dict['email'] == 'dict@example.com'
            assert user_dict['name'] == 'Test User'
            assert 'password_hash' not in user_dict  # Should not expose password


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
