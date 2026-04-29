import os
import re
import sqlite3
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "jpg", "jpeg", "png"}
DEFAULT_PAGE_SIZE = 8

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_BYTES", str(16 * 1024 * 1024)))
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
csrf = CSRFProtect(app)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            college TEXT NOT NULL,
            course TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student', 'admin')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject_id INTEGER NOT NULL,
            description TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT,
            download_count INTEGER NOT NULL DEFAULT 0,
            user_id INTEGER NOT NULL,
            is_visible INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE RESTRICT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(admin_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()


def seed_admin():
    db = get_db()
    count = db.execute("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").fetchone()["c"]
    if count > 0:
        return

    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_name = os.getenv("ADMIN_NAME", "Administrator")
    admin_college = os.getenv("ADMIN_COLLEGE", "System")
    admin_course = os.getenv("ADMIN_COURSE", "Administration")

    if not admin_email or not admin_password:
        return

    db.execute(
        """
        INSERT INTO users (name, email, password_hash, college, course, role, is_active)
        VALUES (?, ?, ?, ?, ?, 'admin', 1)
        """,
        (
            admin_name,
            admin_email.strip().lower(),
            generate_password_hash(admin_password),
            admin_college,
            admin_course,
        ),
    )
    db.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def log_admin_action(admin_id, action, target_type, target_id):
    db = get_db()
    db.execute(
        "INSERT INTO admin_logs (admin_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
        (admin_id, action, target_type, target_id),
    )
    db.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)

    return wrapper


@app.before_request
def load_current_user():
    g.user = None
    user_id = session.get("user_id")
    if not user_id:
        return
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not user["is_active"]:
        session.clear()
        return
    g.user = user


@app.context_processor
def inject_helpers():
    return {"now_year": datetime.now().year}


@app.route("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"}, 200


@app.route("/")
def index():
    db = get_db()
    stats = db.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM notes WHERE is_visible = 1) AS notes_count,
            (SELECT COUNT(*) FROM users WHERE role = 'student' AND is_active = 1) AS students_count,
            (SELECT COUNT(*) FROM subjects WHERE is_active = 1) AS subjects_count
        """
    ).fetchone()
    latest_notes = db.execute(
        """
        SELECT n.id, n.title, n.created_at, s.name AS subject_name, u.name AS uploader
        FROM notes n
        JOIN subjects s ON s.id = n.subject_id
        JOIN users u ON u.id = n.user_id
        WHERE n.is_visible = 1
        ORDER BY n.created_at DESC
        LIMIT 6
        """
    ).fetchall()
    return render_template("index.html", stats=stats, latest_notes=latest_notes)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        college = request.form.get("college", "").strip()
        course = request.form.get("course", "").strip()

        errors = []
        if not name or not college or not course:
            errors.append("Name, college, and course are required.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            errors.append("Please provide a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            errors.append("This email is already registered.")

        if errors:
            for item in errors:
                flash(item, "danger")
            return render_template("register.html")

        db.execute(
            """
            INSERT INTO users (name, email, password_hash, college, course, role, is_active)
            VALUES (?, ?, ?, ?, ?, 'student', 1)
            """,
            (name, email, generate_password_hash(password), college, course),
        )
        db.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")
        if not user["is_active"]:
            flash("Your account is deactivated. Contact admin.", "warning")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        flash("Welcome back!", "success")
        next_path = request.args.get("next")
        if next_path and next_path.startswith("/"):
            return redirect(next_path)
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_note():
    db = get_db()
    subjects = db.execute("SELECT * FROM subjects WHERE is_active = 1 ORDER BY name").fetchall()

    if g.user["role"] != "student":
        flash("Only students can upload notes.", "warning")
        return redirect(url_for("index"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        subject_id = request.form.get("subject_id", "").strip()
        description = request.form.get("description", "").strip()
        file = request.files.get("file")

        errors = []
        if not title:
            errors.append("Title is required.")
        if not description:
            errors.append("Description is required.")
        if not subject_id.isdigit():
            errors.append("Please select a valid subject.")
        if not file or not file.filename:
            errors.append("Please upload a file.")
        elif not allowed_file(file.filename):
            errors.append("Invalid file type.")

        if subject_id.isdigit():
            subject = db.execute(
                "SELECT id FROM subjects WHERE id = ? AND is_active = 1", (subject_id,)
            ).fetchone()
            if not subject:
                errors.append("Selected subject is not available.")

        if errors:
            for item in errors:
                flash(item, "danger")
            return render_template("upload.html", subjects=subjects)

        safe_name = secure_filename(file.filename)
        ext = safe_name.rsplit(".", 1)[1].lower()
        stored_filename = f"{uuid.uuid4().hex}.{ext}"
        full_path = UPLOAD_DIR / stored_filename
        file.save(full_path)

        db.execute(
            """
            INSERT INTO notes
            (title, subject_id, description, stored_filename, original_filename, file_size, mime_type, user_id, is_visible)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                title,
                int(subject_id),
                description,
                stored_filename,
                safe_name,
                full_path.stat().st_size,
                file.mimetype,
                g.user["id"],
            ),
        )
        db.commit()
        flash("Your note was uploaded successfully.", "success")
        return redirect(url_for("notes"))

    return render_template("upload.html", subjects=subjects)


@app.route("/notes")
def notes():
    db = get_db()
    subject_id = request.args.get("subject", "").strip()
    title_q = request.args.get("title", "").strip()
    keyword_q = request.args.get("keyword", "").strip()
    page = request.args.get("page", "1").strip()
    page_num = int(page) if page.isdigit() and int(page) > 0 else 1
    offset = (page_num - 1) * DEFAULT_PAGE_SIZE

    filters = ["n.is_visible = 1"]
    params = []

    if subject_id.isdigit():
        filters.append("n.subject_id = ?")
        params.append(int(subject_id))
    if title_q:
        filters.append("LOWER(n.title) LIKE ?")
        params.append(f"%{title_q.lower()}%")
    if keyword_q:
        filters.append("(LOWER(n.title) LIKE ? OR LOWER(n.description) LIKE ?)")
        keyword = f"%{keyword_q.lower()}%"
        params.extend([keyword, keyword])

    where_clause = " AND ".join(filters)

    total = db.execute(
        f"SELECT COUNT(*) AS c FROM notes n WHERE {where_clause}", params
    ).fetchone()["c"]
    page_count = max(1, (total + DEFAULT_PAGE_SIZE - 1) // DEFAULT_PAGE_SIZE)
    if page_num > page_count:
        page_num = page_count
        offset = (page_num - 1) * DEFAULT_PAGE_SIZE

    rows = db.execute(
        f"""
        SELECT n.*, s.name AS subject_name, u.name AS uploader
        FROM notes n
        JOIN subjects s ON s.id = n.subject_id
        JOIN users u ON u.id = n.user_id
        WHERE {where_clause}
        ORDER BY n.created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, DEFAULT_PAGE_SIZE, offset],
    ).fetchall()
    subjects = db.execute("SELECT id, name FROM subjects WHERE is_active = 1 ORDER BY name").fetchall()
    return render_template(
        "notes.html",
        notes=rows,
        subjects=subjects,
        filters={"subject": subject_id, "title": title_q, "keyword": keyword_q},
        page=page_num,
        page_count=page_count,
        total=total,
    )


@app.route("/download/<int:note_id>")
@login_required
def download_note(note_id):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note or not note["is_visible"]:
        abort(404)

    file_path = UPLOAD_DIR / note["stored_filename"]
    if not file_path.exists():
        flash("The requested file is missing from storage.", "danger")
        return redirect(url_for("notes"))

    db.execute("UPDATE notes SET download_count = download_count + 1 WHERE id = ?", (note_id,))
    db.commit()
    return send_from_directory(app.config["UPLOAD_FOLDER"], note["stored_filename"], as_attachment=True)


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = db.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM users WHERE role = 'student') AS users_count,
            (SELECT COUNT(*) FROM notes) AS notes_count,
            (SELECT COUNT(*) FROM subjects WHERE is_active = 1) AS subjects_count
        """
    ).fetchone()
    recent_notes = db.execute(
        """
        SELECT n.id, n.title, n.created_at, n.is_visible, s.name AS subject_name, u.name AS uploader
        FROM notes n
        JOIN users u ON u.id = n.user_id
        JOIN subjects s ON s.id = n.subject_id
        ORDER BY n.created_at DESC
        LIMIT 8
        """
    ).fetchall()
    return render_template("admin_dashboard.html", stats=stats, recent_notes=recent_notes)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_db().execute(
        "SELECT id, name, email, college, course, role, is_active, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404)
    if user["role"] == "admin":
        flash("Admin accounts cannot be deactivated here.", "warning")
        return redirect(url_for("admin_users"))

    new_state = 0 if user["is_active"] else 1
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_state, user_id))
    db.commit()
    log_admin_action(g.user["id"], "toggle_user", "user", user_id)
    flash("User status updated.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404)
    if user["id"] == g.user["id"] or user["role"] == "admin":
        flash("This user cannot be deleted.", "warning")
        return redirect(url_for("admin_users"))

    notes = db.execute("SELECT stored_filename FROM notes WHERE user_id = ?", (user_id,)).fetchall()
    for n in notes:
        path = UPLOAD_DIR / n["stored_filename"]
        if path.exists():
            path.unlink()

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    log_admin_action(g.user["id"], "delete_user", "user", user_id)
    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/subjects", methods=["GET", "POST"])
@admin_required
def admin_subjects():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Subject name is required.", "danger")
            return redirect(url_for("admin_subjects"))
        try:
            db.execute("INSERT INTO subjects (name, is_active) VALUES (?, 1)", (name,))
            subject_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            db.commit()
            log_admin_action(g.user["id"], "create_subject", "subject", subject_id)
            flash("Subject created.", "success")
        except sqlite3.IntegrityError:
            flash("Subject already exists.", "warning")
        return redirect(url_for("admin_subjects"))

    subjects = db.execute(
        """
        SELECT s.*, (SELECT COUNT(*) FROM notes n WHERE n.subject_id = s.id) AS notes_count
        FROM subjects s
        ORDER BY s.name
        """
    ).fetchall()
    return render_template("admin_subjects.html", subjects=subjects)


@app.route("/admin/subjects/<int:subject_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_subject(subject_id):
    db = get_db()
    subject = db.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()
    if not subject:
        abort(404)
    db.execute("UPDATE subjects SET is_active = ? WHERE id = ?", (0 if subject["is_active"] else 1, subject_id))
    db.commit()
    log_admin_action(g.user["id"], "toggle_subject", "subject", subject_id)
    flash("Subject status updated.", "success")
    return redirect(url_for("admin_subjects"))


@app.route("/admin/subjects/<int:subject_id>/edit", methods=["POST"])
@admin_required
def admin_edit_subject(subject_id):
    db = get_db()
    subject = db.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()
    if not subject:
        abort(404)
    name = request.form.get("name", "").strip()
    if not name:
        flash("Subject name cannot be empty.", "danger")
        return redirect(url_for("admin_subjects"))
    try:
        db.execute("UPDATE subjects SET name = ? WHERE id = ?", (name, subject_id))
        db.commit()
        log_admin_action(g.user["id"], "edit_subject", "subject", subject_id)
        flash("Subject updated.", "success")
    except sqlite3.IntegrityError:
        flash("A subject with that name already exists.", "warning")
    return redirect(url_for("admin_subjects"))


@app.route("/admin/notes")
@admin_required
def admin_notes():
    rows = get_db().execute(
        """
        SELECT n.*, s.name AS subject_name, u.name AS uploader
        FROM notes n
        JOIN users u ON u.id = n.user_id
        JOIN subjects s ON s.id = n.subject_id
        ORDER BY n.created_at DESC
        """
    ).fetchall()
    return render_template("admin_notes.html", notes=rows)


@app.route("/admin/notes/<int:note_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_note(note_id):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        abort(404)
    db.execute("UPDATE notes SET is_visible = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (0 if note["is_visible"] else 1, note_id))
    db.commit()
    log_admin_action(g.user["id"], "toggle_note", "note", note_id)
    flash("Note visibility updated.", "success")
    return redirect(url_for("admin_notes"))


@app.route("/admin/notes/<int:note_id>/delete", methods=["POST"])
@admin_required
def admin_delete_note(note_id):
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        abort(404)

    file_path = UPLOAD_DIR / note["stored_filename"]
    if file_path.exists():
        file_path.unlink()

    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    log_admin_action(g.user["id"], "delete_note", "note", note_id)
    flash("Note deleted.", "success")
    return redirect(url_for("admin_notes"))


@app.errorhandler(403)
def forbidden(_exc):
    return render_template("error.html", code=403, message="You are not authorized to view this page."), 403


@app.errorhandler(404)
def not_found(_exc):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404


@app.errorhandler(413)
def too_large(_exc):
    flash("Uploaded file is too large.", "danger")
    return redirect(request.referrer or url_for("upload_note"))


def seed_default_subjects():
    db = get_db()
    existing = db.execute("SELECT COUNT(*) AS c FROM subjects").fetchone()["c"]
    if existing > 0:
        return
    subjects = ["Mathematics", "Physics", "Chemistry", "Computer Science", "English"]
    db.executemany("INSERT INTO subjects (name, is_active) VALUES (?, 1)", [(s,) for s in subjects])
    db.commit()


with app.app_context():
    init_db()
    seed_default_subjects()
    seed_admin()


if __name__ == "__main__":
    app.run(debug=True)
