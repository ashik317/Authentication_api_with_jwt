# Django DRF Auth API
JWT login, registration, change password, password reset via email.

## Stack
- Django, DRF
- SimpleJWT
- Postgres/SQLite
- Email backend (SMTP)

## Quickstart
```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver
