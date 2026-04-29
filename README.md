# Online Notes Sharing Website

Flask-based web application where students can register, upload notes, search, and download materials, while admins can manage users, subjects, and note moderation.

## Tech Stack
- Python + Flask
- SQLite
- HTML, CSS, Bootstrap

## Setup
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Copy environment template:
   ```bash
   copy .env.example .env
   ```
4. Update admin credentials and secret key in `.env`.
5. Run the app:
   ```bash
   python app.py
   ```

The app will auto-create `database.db`, seed default subjects, and seed an admin user if `ADMIN_EMAIL` + `ADMIN_PASSWORD` are present.

## Main Routes
- `/`, `/register`, `/login`, `/logout`
- `/upload`, `/notes`, `/download/<note_id>`
- `/admin`, `/admin/users`, `/admin/subjects`, `/admin/notes`
- `/health`

## Security Notes
- Passwords are hashed with Werkzeug.
- CSRF protection enabled via Flask-WTF.
- File uploads restricted by extension and max size.
- Admin actions are logged in `admin_logs`.
