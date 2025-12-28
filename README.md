# BlackRoad OS - Complete SaaS Platform

**Status:** LIVE & REVENUE-READY (Now with Full Backend!)

**Live URL:** https://app.blackroad.io

---

## What's New in v2.0

- **Full Flask Backend** with SQLAlchemy database
- **User Authentication** (JWT-based)
- **Real API Endpoints** for all forms
- **SendGrid Email Integration**
- **Admin Dashboard** with metrics
- **Frontend SDK** connecting pages to API
- **Security Headers & Rate Limiting**

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | HTML5, CSS3, Vanilla JS |
| Backend | Python 3, Flask |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Auth | JWT (flask-jwt-extended) |
| Payments | Stripe |
| Email | SendGrid |
| Hosting | Cloudflare Pages (frontend), Railway/Heroku (backend) |

---

## Project Structure

```
blackroad-simple-launch/
├── app.py                        # Main Flask application
├── stripe-webhook-handler.py     # Legacy webhook handler
├── setup-stripe.py               # Stripe product creator
├── create-promo-codes.py         # Promotional codes
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment template
│
├── js/
│   └── blackroad-sdk.js          # Frontend JavaScript SDK
│
├── css/
│   └── styles.css                # Global stylesheet
│
├── email-templates/
│   └── welcome-email.html        # Email templates
│
├── Pages (16 total)
│   ├── index.html                # Landing page
│   ├── pricing.html              # Pricing comparison
│   ├── features.html             # Feature showcase
│   ├── dashboard.html            # User dashboard
│   ├── login.html                # Auth page
│   ├── success.html              # Payment success
│   ├── calculator.html           # ROI calculator
│   ├── faq.html                  # FAQ accordion
│   ├── testimonials.html         # Social proof
│   ├── affiliates.html           # Affiliate program
│   ├── contact.html              # Contact form
│   ├── newsletter.html           # Newsletter signup
│   ├── compare.html              # Competitor comparison
│   ├── changelog.html            # Version history
│   ├── producthunt.html          # Product Hunt launch
│   ├── startups.html             # Startup features
│   └── 404.html                  # Error page
│
└── sitemap.xml                   # SEO sitemap
```

---

## Quick Start

### 1. Clone & Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/blackroad-simple-launch
cd blackroad-simple-launch

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` with your settings:

```bash
# Stripe
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# Database
DATABASE_URL=sqlite:///blackroad.db

# Email
SENDGRID_API_KEY=SG.xxx

# App
SECRET_KEY=your-secret-key
DEBUG=true
```

### 3. Initialize Database

```bash
# Using Flask CLI
flask init-db

# Or run directly
python app.py
# Database auto-creates on first run
```

### 4. Run Development Server

```bash
python app.py
# API running at http://localhost:5000
```

### 5. Deploy Frontend

```bash
# Deploy to Cloudflare Pages
npx wrangler pages deploy . --project-name=app-blackroad-io
```

---

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Create new account |
| `/api/auth/login` | POST | Login user |
| `/api/auth/refresh` | POST | Refresh access token |
| `/api/auth/me` | GET | Get current user |
| `/api/auth/update` | PUT | Update profile |

### Dashboard

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard/stats` | GET | Get user statistics |
| `/api/dashboard/usage` | GET | Get usage over time |

### Forms

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/newsletter/subscribe` | POST | Subscribe to newsletter |
| `/api/contact` | POST | Submit contact form |
| `/api/affiliate/signup` | POST | Join affiliate program |

### Admin (requires admin role)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/stats` | GET | Platform statistics |
| `/api/admin/users` | GET | List all users |
| `/api/admin/contacts` | GET | Contact submissions |
| `/api/admin/events` | GET | Event log |

### Webhooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook/stripe` | POST | Stripe webhook handler |

### Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/status` | GET | Service status |

---

## Frontend SDK

The SDK (`js/blackroad-sdk.js`) handles:

- **Token Management** - JWT storage & refresh
- **API Requests** - Authenticated HTTP calls
- **Form Handlers** - Auto-binds to `data-form` attributes
- **UI Helpers** - Notifications, loading states
- **Dashboard** - Fetches & renders user data

### Usage

Add to any HTML page:

```html
<script>window.BLACKROAD_API_URL = 'https://api.blackroad.io';</script>
<script src="/js/blackroad-sdk.js"></script>
```

### Form Binding

```html
<!-- Newsletter form -->
<form data-form="newsletter" data-source="footer">
    <input name="email" type="email" required>
    <button type="submit">Subscribe</button>
</form>

<!-- Contact form -->
<form data-form="contact" data-type="demo">
    <input name="name" required>
    <input name="email" required>
    <textarea name="message" required></textarea>
    <button type="submit">Send</button>
</form>
```

---

## Database Models

### User
```python
- id, email, password_hash, name
- stripe_customer_id, subscription_status, subscription_tier
- is_founding_member, is_admin, is_active
- api_calls_count, deployments_count
- created_at, updated_at, last_login_at
```

### Event
```python
- id, user_id, event_type, data, created_at
```

### NewsletterSubscriber
```python
- id, email, name, source, is_active, subscribed_at
```

### ContactSubmission
```python
- id, name, email, company, message, type, status, created_at
```

### AffiliateSignup
```python
- id, email, name, website, referral_code, status
- total_referrals, total_earnings, created_at
```

---

## CLI Commands

```bash
# Initialize database
flask init-db

# Create admin user
flask create-admin

# Run production server
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## Deployment

### Frontend (Cloudflare Pages)

```bash
npx wrangler pages deploy . --project-name=app-blackroad-io
```

### Backend (Railway)

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

### Backend (Heroku)

```bash
heroku create blackroad-api
heroku config:set STRIPE_SECRET_KEY=sk_live_xxx
git push heroku main
```

### Configure Stripe Webhooks

1. Go to Stripe Dashboard → Developers → Webhooks
2. Add endpoint: `https://api.blackroad.io/webhook/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
4. Copy webhook secret to `.env`

---

## Security Features

- **JWT Authentication** with refresh tokens
- **Password Hashing** using bcrypt
- **Rate Limiting** (200/day, 50/hour default)
- **CORS** configuration
- **Webhook Signature Verification**
- **Input Validation** on all endpoints
- **Admin Role Protection**

---

## Pricing Tiers

| Tier | Price | Features |
|------|-------|----------|
| Founding Member | $29/mo | 50% OFF forever, all Pro features |
| Pro | $58/mo | Unlimited deployments, priority support |
| Enterprise | $199/mo | Custom SLAs, dedicated support |

### Payment Links

- **Founding Member:** https://buy.stripe.com/9B6cN4fOr6bYbvi8xD
- **Pro:** https://buy.stripe.com/dRm9AS8lZ0REbviaFL
- **Enterprise:** https://buy.stripe.com/00w8wOeKn1VI7f215b

### Promo Codes

| Code | Discount |
|------|----------|
| PRODUCTHUNT | 100% off first month |
| LAUNCH50 | 50% off 3 months |
| TWITTER20 | 20% off first month |
| FRIEND25 | 25% off forever |
| BLACKFRIDAY | 60% off 12 months |
| STUDENT50 | 50% off forever |
| WELCOME10 | 10% off first month |

---

## Environment Variables

```bash
# Required
STRIPE_SECRET_KEY=sk_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
SECRET_KEY=your-secret-key

# Optional but recommended
SENDGRID_API_KEY=SG.xxx
DATABASE_URL=postgresql://...

# Defaults
DEBUG=false
FLASK_ENV=production
```

---

## Troubleshooting

### Database Issues
```bash
# Reset database
rm blackroad.db
flask init-db
```

### Auth Issues
```bash
# Check JWT token
curl -H "Authorization: Bearer <token>" http://localhost:5000/api/auth/me
```

### Stripe Webhook Issues
```bash
# Test locally
stripe listen --forward-to localhost:5000/webhook/stripe
```

---

## Development Roadmap

- [ ] OAuth (Google, GitHub)
- [ ] Two-factor authentication
- [ ] Real-time notifications (WebSocket)
- [ ] Usage analytics dashboard
- [ ] API key management
- [ ] Team/organization support
- [ ] Billing portal integration
- [ ] Mobile app

---

## Support

- **Email:** blackroad.systems@gmail.com
- **Discord:** https://discord.gg/blackroad
- **Twitter:** @blackroad_os

---

## License

MIT License - See LICENSE file

---

**Built with Claude AI**
