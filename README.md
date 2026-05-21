# Secure Document Vault

A secure web-based document management system built with Flask and SQLAlchemy.

## Features
- JWT Authentication + bcrypt password hashing
- Password policy enforcement
- Role-Based Access Control (Admin / Manager / User)
- OAuth login (GitHub & Google)
- Two-Factor Authentication (2FA) via TOTP
- AES-256 document encryption
- RSA digital signatures & SHA-256 integrity verification
- Full audit logging
- HTTPS support

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create .env file
cp .env.example .env
# Edit .env with your actual values

# 3. Run the app
python run.py
```

## First Run
- First registered user automatically becomes **Admin**
- Visit http://localhost:5000/auth/register to create your account
- Login at http://localhost:5000/auth/login

## HTTPS Setup (for production)
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
Then update run.py:
```python
app.run(ssl_context=('cert.pem', 'key.pem'))
```

## Project Structure
```
secure_vault/
├── run.py              # Entry point
├── config.py           # Configuration
├── requirements.txt    # Dependencies
└── app/
    ├── __init__.py     # App factory
    ├── models.py       # Database models
    ├── routes/         # Blueprints
    │   ├── auth.py     # Auth + OAuth + 2FA
    │   ├── dashboard.py
    │   ├── documents.py # Upload/Download/Verify
    │   ├── admin.py    # Admin panel
    │   └── api.py      # JWT API endpoints
    ├── utils/
    │   └── crypto.py   # AES-256 + RSA + SHA-256
    └── templates/      # HTML pages
```

## API Endpoints (JWT)
```
POST /auth/token          - Get JWT token
GET  /api/me              - Current user info
GET  /api/documents       - List documents
GET  /api/documents/:id/verify - Verify document
```
