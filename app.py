#!/usr/bin/env python3
"""
BlackRoad OS - Complete Backend Application
Full-featured Flask API with authentication, database, and integrations
"""

import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

import stripe
import bcrypt
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

# Load environment variables
load_dotenv()

# ===========================================
# APP CONFIGURATION
# ===========================================
app = Flask(__name__)

# Core config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = os.environ.get('DEBUG', 'false').lower() == 'true'

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blackroad.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT config
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# CORS configuration
cors_origins = os.environ.get('CORS_ORIGINS', '*').split(',')
CORS(app, origins=cors_origins, supports_credentials=True)

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# SendGrid configuration
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
EMAIL_FROM = os.environ.get('EMAIL_FROM_ADDRESS', 'hello@blackroad.io')
EMAIL_FROM_NAME = os.environ.get('EMAIL_FROM_NAME', 'BlackRoad OS')


# ===========================================
# SECURITY HEADERS MIDDLEWARE
# ===========================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy (formerly feature policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Content Security Policy (relaxed for development, tighten in production)
    if not app.debug:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src https://js.stripe.com https://hooks.stripe.com; "
            "object-src 'none'; "
            "base-uri 'self';"
        )

    # HSTS (only in production with HTTPS)
    if not app.debug and os.environ.get('ENABLE_HSTS', 'false').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    return response


# ===========================================
# DATABASE MODELS
# ===========================================

class User(db.Model):
    """User account model"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    name = db.Column(db.String(255))

    # Stripe integration
    stripe_customer_id = db.Column(db.String(255), unique=True, index=True)
    subscription_status = db.Column(db.String(50), default='none')  # none, trial, active, canceled, past_due
    subscription_tier = db.Column(db.String(50), default='free')  # free, founding, pro, enterprise
    subscription_id = db.Column(db.String(255))

    # Status flags
    is_founding_member = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    trial_ends_at = db.Column(db.DateTime)

    # Usage tracking
    api_calls_count = db.Column(db.Integer, default=0)
    deployments_count = db.Column(db.Integer, default=0)

    # Relationships
    events = db.relationship('Event', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'subscription_status': self.subscription_status,
            'subscription_tier': self.subscription_tier,
            'is_founding_member': self.is_founding_member,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'trial_ends_at': self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            'api_calls_count': self.api_calls_count,
            'deployments_count': self.deployments_count
        }


class Event(db.Model):
    """Event logging model"""
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    event_type = db.Column(db.String(100), nullable=False, index=True)
    data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'event_type': self.event_type,
            'data': self.data,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class NewsletterSubscriber(db.Model):
    """Newsletter subscription model"""
    __tablename__ = 'newsletter_subscribers'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255))
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    source = db.Column(db.String(100))  # e.g., 'footer', 'newsletter_page', 'calculator'

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'subscribed_at': self.subscribed_at.isoformat() if self.subscribed_at else None,
            'is_active': self.is_active,
            'source': self.source
        }


class ContactSubmission(db.Model):
    """Contact form submissions"""
    __tablename__ = 'contact_submissions'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    company = db.Column(db.String(255))
    message = db.Column(db.Text, nullable=False)
    submission_type = db.Column(db.String(50), default='general')  # general, demo, support
    status = db.Column(db.String(50), default='new')  # new, read, replied, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'company': self.company,
            'message': self.message,
            'submission_type': self.submission_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AffiliateSignup(db.Model):
    """Affiliate program signups"""
    __tablename__ = 'affiliate_signups'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(500))
    social_links = db.Column(db.JSON)
    referral_code = db.Column(db.String(50), unique=True)
    status = db.Column(db.String(50), default='pending')  # pending, approved, rejected
    total_referrals = db.Column(db.Integer, default=0)
    total_earnings = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'website': self.website,
            'referral_code': self.referral_code,
            'status': self.status,
            'total_referrals': self.total_referrals,
            'total_earnings': self.total_earnings,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PasswordResetToken(db.Model):
    """Password reset tokens"""
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('reset_tokens', lazy='dynamic'))

    @classmethod
    def create_for_user(cls, user):
        """Create a new password reset token for a user"""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        reset_token = cls(user_id=user.id, token=token, expires_at=expires_at)
        db.session.add(reset_token)
        db.session.commit()
        return reset_token

    def is_valid(self):
        """Check if token is still valid"""
        return not self.used and datetime.utcnow() < self.expires_at


# ===========================================
# HELPER FUNCTIONS
# ===========================================

def log_event(event_type, data, user_id=None):
    """Log an event to the database"""
    event = Event(
        event_type=event_type,
        data=data,
        user_id=user_id
    )
    db.session.add(event)
    db.session.commit()
    return event


def send_email(to_email, subject, html_content, to_name=None):
    """Send email via SendGrid"""
    if not SENDGRID_API_KEY:
        print(f"[EMAIL] Would send to {to_email}: {subject}")
        log_event('email_skipped', {'to': to_email, 'subject': subject, 'reason': 'no_api_key'})
        return False

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        from_email = Email(EMAIL_FROM, EMAIL_FROM_NAME)
        to_email_obj = To(to_email, to_name)
        content = Content("text/html", html_content)
        mail = Mail(from_email, to_email_obj, subject, content)

        response = sg.send(mail)
        log_event('email_sent', {
            'to': to_email,
            'subject': subject,
            'status_code': response.status_code
        })
        return True
    except Exception as e:
        log_event('email_failed', {'to': to_email, 'subject': subject, 'error': str(e)})
        return False


def get_email_template(template_name, variables):
    """Load and render email template"""
    template_path = os.path.join(os.path.dirname(__file__), 'email-templates', f'{template_name}.html')
    try:
        with open(template_path, 'r') as f:
            template = f.read()
        for key, value in variables.items():
            template = template.replace(f'{{{{{key}}}}}', str(value))
        return template
    except FileNotFoundError:
        return None


def admin_required(fn):
    """Decorator to require admin access"""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper


# ===========================================
# AUTHENTICATION ENDPOINTS
# ===========================================

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    name = data.get('name', '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({'error': 'Email already registered'}), 409

    user = User(email=email, name=name)
    user.set_password(password)
    user.trial_ends_at = datetime.utcnow() + timedelta(days=14)
    user.subscription_status = 'trial'

    db.session.add(user)
    db.session.commit()

    log_event('user_registered', {'email': email}, user.id)

    # Send welcome email
    trial_end = user.trial_ends_at.strftime('%B %d, %Y')
    html_content = get_email_template('welcome-email', {
        'customer_name': name or 'there',
        'trial_end_date': trial_end,
        'unsubscribe_url': f'{os.environ.get("APP_URL", "https://app.blackroad.io")}/unsubscribe?id={user.id}'
    })
    if html_content:
        send_email(email, '🎉 Welcome to BlackRoad OS!', html_content, name)

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        'message': 'Registration successful',
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 201


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Login user"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').lower().strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        log_event('login_failed', {'email': email})
        return jsonify({'error': 'Invalid email or password'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 403

    user.last_login_at = datetime.utcnow()
    db.session.commit()

    log_event('user_login', {'email': email}, user.id)

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        'message': 'Login successful',
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token
    })


@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({'access_token': access_token})


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user info"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(user.to_dict())


@app.route('/api/auth/update', methods=['PUT'])
@jwt_required()
def update_user():
    """Update user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()

    if 'name' in data:
        user.name = data['name']

    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        user.set_password(data['password'])

    db.session.commit()
    log_event('user_updated', {'fields': list(data.keys())}, user.id)

    return jsonify({'message': 'Profile updated', 'user': user.to_dict()})


@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    """Request password reset"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').lower().strip()

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()

    # Always return success to prevent email enumeration
    if not user:
        log_event('password_reset_requested', {'email': email, 'found': False})
        return jsonify({'message': 'If an account exists, a reset link has been sent'})

    # Create reset token
    reset_token = PasswordResetToken.create_for_user(user)
    reset_url = f"{os.environ.get('APP_URL', 'https://app.blackroad.io')}/reset-password.html?token={reset_token.token}"

    # Send reset email
    html_content = f'''
    <h2>Reset Your Password</h2>
    <p>Hi {user.name or 'there'},</p>
    <p>We received a request to reset your BlackRoad OS password.</p>
    <p>Click the button below to reset your password. This link expires in 1 hour.</p>
    <p style="margin: 30px 0;">
        <a href="{reset_url}" style="background: #10b981; color: white; padding: 15px 30px; border-radius: 8px; text-decoration: none; font-weight: bold;">
            Reset Password
        </a>
    </p>
    <p>If you didn't request this, you can safely ignore this email.</p>
    <p>Best,<br>The BlackRoad Team</p>
    '''

    send_email(email, 'Reset Your BlackRoad OS Password', html_content, user.name)
    log_event('password_reset_requested', {'email': email, 'found': True}, user.id)

    return jsonify({'message': 'If an account exists, a reset link has been sent'})


@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    """Reset password with token"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    token = data.get('token', '')
    new_password = data.get('password', '')

    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400

    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    if not reset_token or not reset_token.is_valid():
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    user = reset_token.user
    user.set_password(new_password)
    reset_token.used = True
    db.session.commit()

    log_event('password_reset_completed', {'email': user.email}, user.id)

    # Send confirmation email
    send_email(
        user.email,
        'Password Changed - BlackRoad OS',
        f'''
        <h2>Password Changed Successfully</h2>
        <p>Hi {user.name or 'there'},</p>
        <p>Your BlackRoad OS password has been successfully changed.</p>
        <p>If you didn't make this change, please contact us immediately at blackroad.systems@gmail.com</p>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        user.name
    )

    return jsonify({'message': 'Password reset successfully'})


# ===========================================
# DASHBOARD API ENDPOINTS
# ===========================================

@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    """Get dashboard statistics for current user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Get recent events
    recent_events = Event.query.filter_by(user_id=user_id)\
        .order_by(Event.created_at.desc())\
        .limit(10).all()

    # Calculate days in trial or subscription
    if user.trial_ends_at:
        days_remaining = (user.trial_ends_at - datetime.utcnow()).days
    else:
        days_remaining = 0

    return jsonify({
        'user': user.to_dict(),
        'stats': {
            'api_calls': user.api_calls_count,
            'deployments': user.deployments_count,
            'days_remaining': max(0, days_remaining),
            'subscription_active': user.subscription_status in ['active', 'trial']
        },
        'recent_activity': [e.to_dict() for e in recent_events]
    })


@app.route('/api/dashboard/usage', methods=['GET'])
@jwt_required()
def get_usage_stats():
    """Get detailed usage statistics"""
    user_id = get_jwt_identity()

    # Get usage over time (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    events = Event.query.filter(
        Event.user_id == user_id,
        Event.created_at >= thirty_days_ago
    ).all()

    # Group by day
    usage_by_day = {}
    for event in events:
        day = event.created_at.strftime('%Y-%m-%d')
        if day not in usage_by_day:
            usage_by_day[day] = {'api_calls': 0, 'deployments': 0}
        if event.event_type == 'api_call':
            usage_by_day[day]['api_calls'] += 1
        elif event.event_type == 'deployment':
            usage_by_day[day]['deployments'] += 1

    return jsonify({
        'usage_by_day': usage_by_day,
        'total_events': len(events)
    })


# ===========================================
# FORM SUBMISSION ENDPOINTS
# ===========================================

@app.route('/api/newsletter/subscribe', methods=['POST'])
@limiter.limit("5 per minute")
def subscribe_newsletter():
    """Subscribe to newsletter"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').lower().strip()
    name = data.get('name', '')
    source = data.get('source', 'unknown')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    existing = NewsletterSubscriber.query.filter_by(email=email).first()
    if existing:
        if existing.is_active:
            return jsonify({'message': 'Already subscribed'}), 200
        else:
            existing.is_active = True
            existing.subscribed_at = datetime.utcnow()
            db.session.commit()
            return jsonify({'message': 'Subscription reactivated'}), 200

    subscriber = NewsletterSubscriber(email=email, name=name, source=source)
    db.session.add(subscriber)
    db.session.commit()

    log_event('newsletter_subscribed', {'email': email, 'source': source})

    # Send confirmation email
    send_email(
        email,
        '✅ Welcome to the BlackRoad Newsletter!',
        f'''
        <h2>You're on the list!</h2>
        <p>Hi {name or 'there'},</p>
        <p>Thanks for subscribing to the BlackRoad OS newsletter. You'll be the first to know about:</p>
        <ul>
            <li>New features and updates</li>
            <li>Tips and best practices</li>
            <li>Exclusive offers and discounts</li>
        </ul>
        <p>Stay awesome! 🚀</p>
        <p>The BlackRoad Team</p>
        ''',
        name
    )

    return jsonify({'message': 'Successfully subscribed!'}), 201


@app.route('/api/contact', methods=['POST'])
@limiter.limit("3 per minute")
def submit_contact():
    """Submit contact form"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    name = data.get('name', '').strip()
    email = data.get('email', '').lower().strip()
    message = data.get('message', '').strip()
    company = data.get('company', '').strip()
    submission_type = data.get('type', 'general')

    if not all([name, email, message]):
        return jsonify({'error': 'Name, email, and message are required'}), 400

    submission = ContactSubmission(
        name=name,
        email=email,
        company=company,
        message=message,
        submission_type=submission_type
    )
    db.session.add(submission)
    db.session.commit()

    log_event('contact_submitted', {
        'email': email,
        'type': submission_type
    })

    # Send notification to admin
    send_email(
        os.environ.get('EMAIL_FROM_ADDRESS', 'hello@blackroad.io'),
        f'📬 New Contact: {submission_type.upper()} from {name}',
        f'''
        <h2>New Contact Submission</h2>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Company:</strong> {company or 'N/A'}</p>
        <p><strong>Type:</strong> {submission_type}</p>
        <p><strong>Message:</strong></p>
        <blockquote>{message}</blockquote>
        '''
    )

    # Send confirmation to user
    send_email(
        email,
        '✅ We received your message!',
        f'''
        <h2>Thanks for reaching out!</h2>
        <p>Hi {name},</p>
        <p>We received your message and will get back to you within 24 hours.</p>
        <p>Here's a copy of your message:</p>
        <blockquote>{message}</blockquote>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        name
    )

    return jsonify({'message': 'Message sent successfully!'}), 201


@app.route('/api/affiliate/signup', methods=['POST'])
@limiter.limit("3 per minute")
def affiliate_signup():
    """Sign up for affiliate program"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    name = data.get('name', '').strip()
    email = data.get('email', '').lower().strip()
    website = data.get('website', '').strip()
    social_links = data.get('social_links', {})

    if not all([name, email]):
        return jsonify({'error': 'Name and email are required'}), 400

    existing = AffiliateSignup.query.filter_by(email=email).first()
    if existing:
        return jsonify({'error': 'Email already registered for affiliate program'}), 409

    # Generate unique referral code
    referral_code = f"BR{secrets.token_hex(4).upper()}"

    affiliate = AffiliateSignup(
        name=name,
        email=email,
        website=website,
        social_links=social_links,
        referral_code=referral_code
    )
    db.session.add(affiliate)
    db.session.commit()

    log_event('affiliate_signup', {'email': email, 'referral_code': referral_code})

    send_email(
        email,
        '🤝 Welcome to the BlackRoad Affiliate Program!',
        f'''
        <h2>Application Received!</h2>
        <p>Hi {name},</p>
        <p>Thanks for applying to the BlackRoad OS affiliate program.</p>
        <p>We'll review your application and get back to you within 48 hours.</p>
        <p>Your tentative referral code: <strong>{referral_code}</strong></p>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        name
    )

    return jsonify({
        'message': 'Application submitted successfully!',
        'referral_code': referral_code
    }), 201


# ===========================================
# BILLING & SUBSCRIPTION ENDPOINTS
# ===========================================

@app.route('/api/billing/portal', methods=['POST'])
@jwt_required()
def create_billing_portal():
    """Create a Stripe Customer Portal session"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Create Stripe customer if not exists
    if not user.stripe_customer_id:
        try:
            customer = stripe.Customer.create(
                email=user.email,
                name=user.name,
                metadata={'user_id': str(user.id)}
            )
            user.stripe_customer_id = customer.id
            db.session.commit()
        except stripe.error.StripeError as e:
            return jsonify({'error': f'Failed to create customer: {str(e)}'}), 500

    # Create billing portal session
    try:
        return_url = os.environ.get('APP_URL', 'https://app.blackroad.io') + '/settings.html#subscription'
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=return_url
        )
        log_event('billing_portal_opened', {}, user.id)
        return jsonify({'url': session.url})
    except stripe.error.StripeError as e:
        return jsonify({'error': f'Failed to create portal session: {str(e)}'}), 500


@app.route('/api/billing/cancel', methods=['POST'])
@jwt_required()
def cancel_subscription():
    """Cancel the user's subscription at period end"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.subscription_id:
        return jsonify({'error': 'No active subscription'}), 400

    try:
        # Cancel at period end (not immediately)
        subscription = stripe.Subscription.modify(
            user.subscription_id,
            cancel_at_period_end=True
        )

        user.subscription_status = 'canceling'
        db.session.commit()

        log_event('subscription_cancel_requested', {
            'subscription_id': user.subscription_id,
            'cancel_at': subscription.cancel_at
        }, user.id)

        # Send confirmation email
        send_email(
            user.email,
            'Subscription Cancellation Confirmed - BlackRoad OS',
            f'''
            <h2>Subscription Cancellation Confirmed</h2>
            <p>Hi {user.name or 'there'},</p>
            <p>Your BlackRoad OS subscription has been scheduled for cancellation.</p>
            <p>You'll continue to have access to all features until the end of your current billing period.</p>
            <p>We're sorry to see you go! If you have any feedback on how we could improve, please reply to this email.</p>
            <p>You can reactivate your subscription anytime from your account settings.</p>
            <p>Best,<br>The BlackRoad Team</p>
            ''',
            user.name
        )

        return jsonify({
            'message': 'Subscription scheduled for cancellation',
            'cancel_at': subscription.cancel_at
        })
    except stripe.error.StripeError as e:
        return jsonify({'error': f'Failed to cancel subscription: {str(e)}'}), 500


@app.route('/api/billing/reactivate', methods=['POST'])
@jwt_required()
def reactivate_subscription():
    """Reactivate a subscription that was scheduled for cancellation"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.subscription_id:
        return jsonify({'error': 'No subscription to reactivate'}), 400

    try:
        subscription = stripe.Subscription.modify(
            user.subscription_id,
            cancel_at_period_end=False
        )

        user.subscription_status = 'active'
        db.session.commit()

        log_event('subscription_reactivated', {
            'subscription_id': user.subscription_id
        }, user.id)

        return jsonify({
            'message': 'Subscription reactivated successfully',
            'subscription': {
                'status': subscription.status,
                'current_period_end': subscription.current_period_end
            }
        })
    except stripe.error.StripeError as e:
        return jsonify({'error': f'Failed to reactivate subscription: {str(e)}'}), 500


@app.route('/api/billing/invoices', methods=['GET'])
@jwt_required()
def get_invoices():
    """Get user's invoice history"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.stripe_customer_id:
        return jsonify({'invoices': []})

    try:
        invoices = stripe.Invoice.list(
            customer=user.stripe_customer_id,
            limit=20
        )

        invoice_list = [{
            'id': inv.id,
            'number': inv.number,
            'amount': inv.amount_paid / 100,
            'currency': inv.currency.upper(),
            'status': inv.status,
            'date': inv.created,
            'pdf_url': inv.invoice_pdf,
            'hosted_url': inv.hosted_invoice_url
        } for inv in invoices.data]

        return jsonify({'invoices': invoice_list})
    except stripe.error.StripeError as e:
        return jsonify({'error': f'Failed to fetch invoices: {str(e)}'}), 500


@app.route('/api/billing/subscription', methods=['GET'])
@jwt_required()
def get_subscription():
    """Get current subscription details"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    subscription_data = {
        'status': user.subscription_status,
        'tier': user.subscription_tier,
        'is_founding_member': user.is_founding_member
    }

    if user.subscription_id:
        try:
            subscription = stripe.Subscription.retrieve(user.subscription_id)
            subscription_data.update({
                'current_period_end': subscription.current_period_end,
                'cancel_at_period_end': subscription.cancel_at_period_end,
                'cancel_at': subscription.cancel_at
            })
        except stripe.error.StripeError:
            pass

    return jsonify({'subscription': subscription_data})


@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change password for authenticated user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')

    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password are required'}), 400

    if not user.check_password(current_password):
        return jsonify({'error': 'Current password is incorrect'}), 401

    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400

    user.set_password(new_password)
    db.session.commit()

    log_event('password_changed', {}, user.id)

    send_email(
        user.email,
        'Password Changed - BlackRoad OS',
        f'''
        <h2>Password Changed</h2>
        <p>Hi {user.name or 'there'},</p>
        <p>Your BlackRoad OS password was just changed.</p>
        <p>If you didn't make this change, please contact us immediately.</p>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        user.name
    )

    return jsonify({'message': 'Password changed successfully'})


@app.route('/api/auth/account', methods=['DELETE'])
@jwt_required()
def delete_account():
    """Delete user account and all associated data"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Cancel any active subscription first
    if user.subscription_id:
        try:
            stripe.Subscription.delete(user.subscription_id)
        except stripe.error.StripeError:
            pass

    # Delete user events
    Event.query.filter_by(user_id=user.id).delete()

    # Store email for confirmation
    email = user.email
    name = user.name

    # Delete user
    db.session.delete(user)
    db.session.commit()

    log_event('account_deleted', {'email': email})

    # Send farewell email
    send_email(
        email,
        'Account Deleted - BlackRoad OS',
        f'''
        <h2>Account Deleted</h2>
        <p>Hi {name or 'there'},</p>
        <p>Your BlackRoad OS account has been permanently deleted.</p>
        <p>All your data has been removed from our systems.</p>
        <p>We're sorry to see you go. If you ever want to come back, you're always welcome!</p>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        name
    )

    return jsonify({'message': 'Account deleted successfully'})


# ===========================================
# TEAM MANAGEMENT ENDPOINTS
# ===========================================

class TeamMember(db.Model):
    """Team member model for organization management"""
    __tablename__ = 'team_members'

    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='member')  # owner, admin, member, viewer
    status = db.Column(db.String(50), default='pending')  # pending, active
    invite_token = db.Column(db.String(255), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


@app.route('/api/team/members', methods=['GET'])
@jwt_required()
def get_team_members():
    """Get all team members"""
    user_id = get_jwt_identity()
    members = TeamMember.query.filter_by(team_id=user_id).all()
    return jsonify({'members': [m.to_dict() for m in members]})


@app.route('/api/team/invite', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def invite_team_member():
    """Invite a new team member"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    email = data.get('email', '').lower().strip()
    role = data.get('role', 'member')
    message = data.get('message', '')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    if role not in ['admin', 'member', 'viewer']:
        return jsonify({'error': 'Invalid role'}), 400

    # Check if already invited
    existing = TeamMember.query.filter_by(team_id=user_id, email=email).first()
    if existing:
        return jsonify({'error': 'User already invited'}), 400

    # Create invite
    invite_token = secrets.token_urlsafe(32)
    member = TeamMember(
        team_id=user_id,
        email=email,
        role=role,
        invite_token=invite_token
    )
    db.session.add(member)
    db.session.commit()

    # Send invite email
    invite_url = f"{os.environ.get('APP_URL', 'https://app.blackroad.io')}/join?token={invite_token}"
    send_email(
        email,
        f"You're invited to join {user.name}'s team on BlackRoad OS",
        f'''
        <h2>Team Invitation</h2>
        <p>Hi there,</p>
        <p>{user.name or user.email} has invited you to join their team on BlackRoad OS as a {role}.</p>
        {f'<p>"{message}"</p>' if message else ''}
        <p style="margin: 30px 0;">
            <a href="{invite_url}" style="background: #667eea; color: white; padding: 15px 30px; border-radius: 8px; text-decoration: none; font-weight: bold;">
                Accept Invitation
            </a>
        </p>
        <p>Best,<br>The BlackRoad Team</p>
        ''',
        None
    )

    log_event('team_invite_sent', {'email': email, 'role': role}, user_id)

    return jsonify({'message': 'Invite sent', 'member': member.to_dict()}), 201


@app.route('/api/team/members/<int:member_id>', methods=['PUT'])
@jwt_required()
def update_team_member(member_id):
    """Update team member role"""
    user_id = get_jwt_identity()
    member = TeamMember.query.filter_by(id=member_id, team_id=user_id).first()

    if not member:
        return jsonify({'error': 'Member not found'}), 404

    data = request.get_json()
    if data.get('role') in ['admin', 'member', 'viewer']:
        member.role = data['role']
        db.session.commit()
        log_event('team_member_updated', {'member_id': member_id, 'role': data['role']}, user_id)

    return jsonify({'message': 'Member updated', 'member': member.to_dict()})


@app.route('/api/team/members/<int:member_id>', methods=['DELETE'])
@jwt_required()
def remove_team_member(member_id):
    """Remove team member"""
    user_id = get_jwt_identity()
    member = TeamMember.query.filter_by(id=member_id, team_id=user_id).first()

    if not member:
        return jsonify({'error': 'Member not found'}), 404

    db.session.delete(member)
    db.session.commit()
    log_event('team_member_removed', {'member_id': member_id}, user_id)

    return jsonify({'message': 'Member removed'})


# ===========================================
# WEBHOOK MANAGEMENT ENDPOINTS
# ===========================================

class Webhook(db.Model):
    """Webhook configuration model"""
    __tablename__ = 'webhooks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(255))
    secret = db.Column(db.String(255))
    events = db.Column(db.JSON)  # List of event types to subscribe to
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_triggered_at = db.Column(db.DateTime)
    success_count = db.Column(db.Integer, default=0)
    failure_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'description': self.description,
            'events': self.events,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_triggered_at': self.last_triggered_at.isoformat() if self.last_triggered_at else None,
            'success_count': self.success_count,
            'failure_count': self.failure_count
        }


class WebhookDelivery(db.Model):
    """Webhook delivery log"""
    __tablename__ = 'webhook_deliveries'

    id = db.Column(db.Integer, primary_key=True)
    webhook_id = db.Column(db.Integer, db.ForeignKey('webhooks.id'), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    payload = db.Column(db.JSON)
    response_code = db.Column(db.Integer)
    response_body = db.Column(db.Text)
    response_time_ms = db.Column(db.Integer)
    success = db.Column(db.Boolean)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'response_code': self.response_code,
            'response_time_ms': self.response_time_ms,
            'success': self.success,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


@app.route('/api/webhooks', methods=['GET'])
@jwt_required()
def get_webhooks():
    """Get all webhooks for user"""
    user_id = get_jwt_identity()
    webhooks = Webhook.query.filter_by(user_id=user_id).all()
    return jsonify({'webhooks': [w.to_dict() for w in webhooks]})


@app.route('/api/webhooks', methods=['POST'])
@jwt_required()
def create_webhook():
    """Create a new webhook"""
    user_id = get_jwt_identity()
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    webhook = Webhook(
        user_id=user_id,
        url=url,
        description=data.get('description', ''),
        secret=data.get('secret', secrets.token_urlsafe(32)),
        events=data.get('events', ['deployment.completed', 'deployment.failed'])
    )
    db.session.add(webhook)
    db.session.commit()

    log_event('webhook_created', {'webhook_id': webhook.id}, user_id)

    return jsonify({'message': 'Webhook created', 'webhook': webhook.to_dict()}), 201


@app.route('/api/webhooks/<int:webhook_id>', methods=['PUT'])
@jwt_required()
def update_webhook(webhook_id):
    """Update webhook configuration"""
    user_id = get_jwt_identity()
    webhook = Webhook.query.filter_by(id=webhook_id, user_id=user_id).first()

    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404

    data = request.get_json()

    if 'url' in data:
        webhook.url = data['url']
    if 'description' in data:
        webhook.description = data['description']
    if 'events' in data:
        webhook.events = data['events']
    if 'is_active' in data:
        webhook.is_active = data['is_active']

    db.session.commit()
    log_event('webhook_updated', {'webhook_id': webhook_id}, user_id)

    return jsonify({'message': 'Webhook updated', 'webhook': webhook.to_dict()})


@app.route('/api/webhooks/<int:webhook_id>', methods=['DELETE'])
@jwt_required()
def delete_webhook(webhook_id):
    """Delete a webhook"""
    user_id = get_jwt_identity()
    webhook = Webhook.query.filter_by(id=webhook_id, user_id=user_id).first()

    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404

    # Delete deliveries first
    WebhookDelivery.query.filter_by(webhook_id=webhook_id).delete()
    db.session.delete(webhook)
    db.session.commit()

    log_event('webhook_deleted', {'webhook_id': webhook_id}, user_id)

    return jsonify({'message': 'Webhook deleted'})


@app.route('/api/webhooks/<int:webhook_id>/test', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def test_webhook(webhook_id):
    """Send a test webhook"""
    import requests as http_requests

    user_id = get_jwt_identity()
    webhook = Webhook.query.filter_by(id=webhook_id, user_id=user_id).first()

    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404

    data = request.get_json() or {}
    event_type = data.get('event_type', 'test.ping')
    payload = data.get('payload', {
        'id': f'evt_test_{secrets.token_hex(8)}',
        'type': event_type,
        'data': {'test': True},
        'created_at': datetime.utcnow().isoformat()
    })

    # Send test webhook
    start_time = datetime.utcnow()
    try:
        response = http_requests.post(
            webhook.url,
            json=payload,
            headers={
                'Content-Type': 'application/json',
                'X-BlackRoad-Signature': secrets.token_hex(32),
                'X-BlackRoad-Event': event_type
            },
            timeout=10
        )
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Log delivery
        delivery = WebhookDelivery(
            webhook_id=webhook_id,
            event_type=event_type,
            payload=payload,
            response_code=response.status_code,
            response_body=response.text[:1000],
            response_time_ms=response_time,
            success=200 <= response.status_code < 300
        )
        db.session.add(delivery)

        if delivery.success:
            webhook.success_count += 1
        else:
            webhook.failure_count += 1
        webhook.last_triggered_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'success': delivery.success,
            'response_code': response.status_code,
            'response_time_ms': response_time,
            'response_body': response.text[:500]
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/webhooks/<int:webhook_id>/deliveries', methods=['GET'])
@jwt_required()
def get_webhook_deliveries(webhook_id):
    """Get webhook delivery history"""
    user_id = get_jwt_identity()
    webhook = Webhook.query.filter_by(id=webhook_id, user_id=user_id).first()

    if not webhook:
        return jsonify({'error': 'Webhook not found'}), 404

    deliveries = WebhookDelivery.query.filter_by(webhook_id=webhook_id)\
        .order_by(WebhookDelivery.created_at.desc())\
        .limit(50).all()

    return jsonify({'deliveries': [d.to_dict() for d in deliveries]})


# ===========================================
# ANALYTICS ENDPOINTS
# ===========================================

@app.route('/api/analytics/overview', methods=['GET'])
@jwt_required()
def get_analytics_overview():
    """Get analytics overview for dashboard"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # Get date range from query params
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    # Count events
    events = Event.query.filter(
        Event.user_id == user_id,
        Event.created_at >= start_date
    ).all()

    # Group by type
    event_counts = {}
    for event in events:
        event_type = event.event_type
        if event_type not in event_counts:
            event_counts[event_type] = 0
        event_counts[event_type] += 1

    # Group by day
    daily_counts = {}
    for event in events:
        day = event.created_at.strftime('%Y-%m-%d')
        if day not in daily_counts:
            daily_counts[day] = 0
        daily_counts[day] += 1

    return jsonify({
        'total_events': len(events),
        'event_counts': event_counts,
        'daily_counts': daily_counts,
        'api_calls': user.api_calls_count,
        'deployments': user.deployments_count
    })


@app.route('/api/analytics/events', methods=['GET'])
@jwt_required()
def get_analytics_events():
    """Get recent events for analytics"""
    user_id = get_jwt_identity()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    events = Event.query.filter_by(user_id=user_id)\
        .order_by(Event.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'events': [e.to_dict() for e in events.items],
        'total': events.total,
        'pages': events.pages,
        'current_page': page
    })


@app.route('/api/events/track', methods=['POST'])
@limiter.limit("100 per minute")
def track_event():
    """Track anonymous event (for calculator, etc.)"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No data provided'}), 400

    event_type = data.get('event', 'unknown')
    event_data = data.get('data', {})

    log_event(event_type, event_data)

    return jsonify({'success': True})


# ===========================================
# STRIPE WEBHOOK HANDLER
# ===========================================

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    """Handle incoming Stripe webhook events"""
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    if not STRIPE_WEBHOOK_SECRET:
        return jsonify({'error': 'Webhook secret not configured'}), 500

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    event_type = event['type']
    data = event['data']['object']

    log_event(f'stripe_{event_type}', {'stripe_event_id': event['id']})

    if event_type == 'checkout.session.completed':
        handle_checkout_completed(data)
    elif event_type == 'customer.subscription.created':
        handle_subscription_created(data)
    elif event_type == 'customer.subscription.updated':
        handle_subscription_updated(data)
    elif event_type == 'customer.subscription.deleted':
        handle_subscription_deleted(data)
    elif event_type == 'invoice.payment_succeeded':
        handle_payment_succeeded(data)
    elif event_type == 'invoice.payment_failed':
        handle_payment_failed(data)

    return jsonify({'status': 'success'}), 200


def handle_checkout_completed(session):
    """Handle successful checkout"""
    customer_id = session.get('customer')
    customer_email = session.get('customer_email')
    subscription_id = session.get('subscription')

    # Get or create user
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    if not user:
        user = User.query.filter_by(email=customer_email).first()

    if not user:
        user = User(
            email=customer_email,
            stripe_customer_id=customer_id
        )
        db.session.add(user)
    else:
        user.stripe_customer_id = customer_id

    user.subscription_id = subscription_id
    user.subscription_status = 'active'

    # Check if founding member ($29)
    if subscription_id:
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            for item in subscription['items']['data']:
                if item['price']['unit_amount'] == 2900:
                    user.is_founding_member = True
                    user.subscription_tier = 'founding'
                    break
                elif item['price']['unit_amount'] == 5800:
                    user.subscription_tier = 'pro'
                elif item['price']['unit_amount'] == 19900:
                    user.subscription_tier = 'enterprise'
        except Exception as e:
            log_event('stripe_error', {'error': str(e), 'action': 'get_subscription'})

    db.session.commit()

    log_event('checkout_completed', {
        'customer_id': customer_id,
        'email': customer_email,
        'tier': user.subscription_tier
    }, user.id)

    # Get customer name from Stripe
    try:
        customer = stripe.Customer.retrieve(customer_id)
        user.name = customer.get('name')
        db.session.commit()
    except Exception:
        pass

    # Send welcome email
    trial_end = (datetime.utcnow() + timedelta(days=14)).strftime('%B %d, %Y')
    html_content = get_email_template('welcome-email', {
        'customer_name': user.name or 'there',
        'trial_end_date': trial_end,
        'unsubscribe_url': f'{os.environ.get("APP_URL", "https://app.blackroad.io")}/unsubscribe?id={user.id}'
    })
    if html_content:
        send_email(customer_email, '🎉 Welcome to BlackRoad OS!', html_content, user.name)


def handle_subscription_created(subscription):
    """Handle subscription creation"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if user:
        user.subscription_id = subscription['id']
        user.subscription_status = subscription['status']
        db.session.commit()
        log_event('subscription_created', {'subscription_id': subscription['id']}, user.id)


def handle_subscription_updated(subscription):
    """Handle subscription update"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if user:
        user.subscription_status = subscription['status']

        if subscription.get('cancel_at_period_end'):
            send_email(
                user.email,
                '😢 We\'re sorry to see you go',
                f'''
                <h2>Subscription Cancellation</h2>
                <p>Hi {user.name or 'there'},</p>
                <p>Your BlackRoad OS subscription has been canceled.</p>
                <p>You'll continue to have access until the end of your billing period.</p>
                <p>If you change your mind, you can reactivate anytime from your dashboard.</p>
                <p>We'd love to hear your feedback - reply to this email to let us know how we can improve.</p>
                <p>Best,<br>The BlackRoad Team</p>
                ''',
                user.name
            )

        db.session.commit()
        log_event('subscription_updated', {
            'subscription_id': subscription['id'],
            'status': subscription['status']
        }, user.id)


def handle_subscription_deleted(subscription):
    """Handle subscription deletion"""
    customer_id = subscription['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if user:
        user.subscription_status = 'canceled'
        user.is_active = False
        db.session.commit()
        log_event('subscription_deleted', {'subscription_id': subscription['id']}, user.id)


def handle_payment_succeeded(invoice):
    """Handle successful payment"""
    customer_id = invoice['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if user:
        user.subscription_status = 'active'
        user.is_active = True
        db.session.commit()
        log_event('payment_succeeded', {
            'amount': invoice['amount_paid'] / 100,
            'invoice_id': invoice['id']
        }, user.id)


def handle_payment_failed(invoice):
    """Handle failed payment"""
    customer_id = invoice['customer']
    user = User.query.filter_by(stripe_customer_id=customer_id).first()

    if user:
        user.subscription_status = 'past_due'
        db.session.commit()

        send_email(
            user.email,
            '⚠️ Payment Failed - Action Required',
            f'''
            <h2>Payment Failed</h2>
            <p>Hi {user.name or 'there'},</p>
            <p>We couldn't process your payment for BlackRoad OS.</p>
            <p>Please update your payment method to continue using the service:</p>
            <p><a href="{os.environ.get('APP_URL', 'https://app.blackroad.io')}/dashboard/billing">Update Payment Method</a></p>
            <p>If you need help, just reply to this email.</p>
            <p>Best,<br>The BlackRoad Team</p>
            ''',
            user.name
        )

        log_event('payment_failed', {'invoice_id': invoice['id']}, user.id)


# ===========================================
# ADMIN ENDPOINTS
# ===========================================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_stats():
    """Get admin dashboard statistics"""
    total_users = User.query.count()
    active_subscriptions = User.query.filter(User.subscription_status.in_(['active', 'trial'])).count()
    founding_members = User.query.filter_by(is_founding_member=True).count()
    newsletter_subs = NewsletterSubscriber.query.filter_by(is_active=True).count()
    contact_submissions = ContactSubmission.query.filter_by(status='new').count()

    # Revenue calculation (simplified)
    founding_revenue = founding_members * 29
    pro_users = User.query.filter_by(subscription_tier='pro', subscription_status='active').count()
    pro_revenue = pro_users * 58
    enterprise_users = User.query.filter_by(subscription_tier='enterprise', subscription_status='active').count()
    enterprise_revenue = enterprise_users * 199

    return jsonify({
        'users': {
            'total': total_users,
            'active_subscriptions': active_subscriptions,
            'founding_members': founding_members,
            'by_tier': {
                'free': User.query.filter_by(subscription_tier='free').count(),
                'founding': founding_members,
                'pro': pro_users,
                'enterprise': enterprise_users
            }
        },
        'newsletter': {
            'subscribers': newsletter_subs
        },
        'contact': {
            'new_submissions': contact_submissions
        },
        'revenue': {
            'mrr': founding_revenue + pro_revenue + enterprise_revenue,
            'by_tier': {
                'founding': founding_revenue,
                'pro': pro_revenue,
                'enterprise': enterprise_revenue
            }
        }
    })


@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_users():
    """Get all users (paginated)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)

    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'users': [u.to_dict() for u in users.items],
        'total': users.total,
        'pages': users.pages,
        'current_page': page
    })


@app.route('/api/admin/contacts', methods=['GET'])
@admin_required
def admin_contacts():
    """Get contact submissions"""
    status = request.args.get('status', 'new')
    submissions = ContactSubmission.query.filter_by(status=status)\
        .order_by(ContactSubmission.created_at.desc()).all()

    return jsonify({
        'submissions': [s.to_dict() for s in submissions]
    })


@app.route('/api/admin/events', methods=['GET'])
@admin_required
def admin_events():
    """Get recent events"""
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('type')

    query = Event.query.order_by(Event.created_at.desc())
    if event_type:
        query = query.filter_by(event_type=event_type)

    events = query.limit(limit).all()

    return jsonify({
        'events': [e.to_dict() for e in events]
    })


# ===========================================
# HEALTH & UTILITY ENDPOINTS
# ===========================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'blackroad-api',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })


@app.route('/api/status', methods=['GET'])
def api_status():
    """API status endpoint"""
    return jsonify({
        'status': 'operational',
        'services': {
            'database': 'connected',
            'stripe': 'configured' if stripe.api_key else 'not_configured',
            'email': 'configured' if SENDGRID_API_KEY else 'not_configured'
        }
    })


# ===========================================
# ERROR HANDLERS
# ===========================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


# ===========================================
# DATABASE INITIALIZATION
# ===========================================

@app.cli.command('init-db')
def init_db():
    """Initialize the database"""
    db.create_all()
    print('Database initialized!')


@app.cli.command('create-admin')
def create_admin():
    """Create an admin user"""
    import getpass
    email = input('Admin email: ')
    password = getpass.getpass('Password: ')
    name = input('Name: ')

    user = User(email=email, name=name, is_admin=True)
    user.set_password(password)
    user.subscription_status = 'active'
    user.subscription_tier = 'enterprise'

    db.session.add(user)
    db.session.commit()
    print(f'Admin user {email} created!')


# ===========================================
# MAIN ENTRY POINT
# ===========================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    print("🚀 Starting BlackRoad OS API Server...")
    print(f"📊 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"🔐 Stripe: {'Configured' if stripe.api_key else 'Not configured'}")
    print(f"📧 Email: {'Configured' if SENDGRID_API_KEY else 'Not configured'}")

    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
