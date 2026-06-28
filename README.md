# Secure Login System

A production-ready Flask web application featuring secure user authentication, account lockout protection, rate limiting, optional two-factor authentication (TOTP), and a modern glassmorphism UI with dark mode support.

## Features

### Authentication
- User registration and login
- Secure logout with session cleanup
- Remember Me functionality
- Session timeout after inactivity
- Protected routes via Flask-Login
- Post-login dashboard

### Password Security
- Bcrypt password hashing (never stored in plain text)
- Password policy enforcement (8–64 chars, upper, lower, digit, special)
- Change password with current password verification

### Security
- CSRF protection (Flask-WTF)
- SQL injection protection (SQLAlchemy ORM)
- XSS mitigation (input sanitization, security headers)
- Secure, HttpOnly, SameSite cookies
- Brute force protection (5 failed attempts → 15-minute lockout)
- Rate limiting on login and registration endpoints
- Environment-based configuration (no hardcoded secrets)

### Two-Factor Authentication
- Google Authenticator compatible TOTP
- QR code setup
- Enable/disable from profile page
- OTP verification step after password login

### Additional
- Forgot password page (mocked email flow)
- Profile management (update name, username, email)
- Account deletion
- Custom 404 and 500 error pages
- Responsive Bootstrap 5 UI with glassmorphism design

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.12+, Flask |
| Database | SQLite (dev), MySQL (configurable) |
| ORM | SQLAlchemy |
| Auth | Flask-Login |
| Hashing | Flask-Bcrypt |
| Forms | Flask-WTF |
| Rate Limiting | Flask-Limiter |
| 2FA | pyotp, qrcode |
| Frontend | HTML5, CSS3, JavaScript, Bootstrap 5, Font Awesome |

## Project Structure

```
Secure-Login-System/
├── app.py                 # Application entry point & factory
├── config.py              # Configuration classes
├── extensions.py          # Shared Flask extensions
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
├── database/              # Database initialization
├── models/                # SQLAlchemy models
├── routes/                # Blueprint routes
├── utils/                 # Validators, security, OTP helpers
├── templates/             # Jinja2 HTML templates
└── static/                # CSS, JavaScript, images
```

## Quick Start

### 1. Clone and enter the project

```bash
cd Secure-Login-System
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment

```bash
copy .env.example .env   # Windows
# cp .env.example .env   # macOS/Linux
```

Edit `.env` and set a strong `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Run the application

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

## MySQL Configuration

Set the following in your `.env` file:

```env
DB_TYPE=mysql
MYSQL_USER=your_user
MYSQL_PASSWORD=your_password
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DATABASE=secure_login
```

Ensure the MySQL database exists before starting the app. Tables are created automatically on first run.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key (required) | — |
| `FLASK_ENV` | `development` or `production` | `development` |
| `DB_TYPE` | `sqlite` or `mysql` | `sqlite` |
| `DATABASE_URL` | SQLite connection string | `sqlite:///secure_login.db` |
| `SESSION_COOKIE_SECURE` | HTTPS-only cookies | `False` |
| `PERMANENT_SESSION_LIFETIME` | Session timeout (seconds) | `1800` |
| `REMEMBER_COOKIE_DURATION` | Remember me duration (seconds) | `2592000` |
| `LOGIN_RATE_LIMIT` | Login rate limit | `10 per minute` |
| `REGISTER_RATE_LIMIT` | Registration rate limit | `5 per minute` |

## Security Notes

- Always use a strong, unique `SECRET_KEY` in production.
- Set `FLASK_ENV=production` and `SESSION_COOKIE_SECURE=True` when serving over HTTPS.
- Use a persistent rate limit storage backend (e.g., Redis) in production instead of `memory://`.
- The forgot-password feature uses a mocked email flow; integrate a real mail provider for production use.

## License

MIT License — use freely for learning and production deployments.
