# VulnScan Lite

VulnScan Lite is a passive web security posture scanner.

## Main Features

- Security header analysis
- SSL/TLS inspection
- Passive CMS detection
- Security score
- Security grade
- Remediation suggestions
- Celery background jobs
- Redis queue
- React dashboard
- SQLite scan history
- PDF reports
- User login
- Safe public-target validation

## Scanner Checks

### Security Headers

The scanner checks:

- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security

Each present header receives +10 points.

Missing headers receive -10 points.

### HTTPS

HTTPS is checked using Python SSL/TLS libraries.

The scanner examines:

- TLS protocol
- Certificate
- Expiration date
- Cipher
- Cipher strength

### CMS

The scanner passively detects CMS fingerprints such as:

- WordPress
- Drupal

It examines:

- HTML generator meta tags
- X-Powered-By
- Common HTML fingerprints

## Run Backend

Create virtual environment:

python -m venv .venv

Activate Windows:

.venv\Scripts\Activate.ps1

Install packages:

pip install -r requirements.txt

Start Redis:

docker run --name vulnscan-redis -p 6379:6379 -d redis:7-alpine

Start Celery:

celery -A celery_app.celery worker --loglevel=INFO --pool=solo

Start Flask:

python app.py

## Run Frontend

cd frontend

npm install

npm run dev

Open:

http://localhost:5173

## Demo Login

Email:

demo@vulnscan.local

Password:

Demo123!

## Disclaimer

Only scan websites you own or have explicit permission to assess.

This project performs passive analysis only.