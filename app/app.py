
import hashlib
import hmac
import html
import json
import posixpath
import secrets
import sqlite3
import re

from contextlib import contextmanager
from http.cookies import CookieError, SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


# =========================================================
# PATH CONFIGURATION
# =========================================================

APP_DIR = Path(__file__).resolve().parent


def find_html_root(start_dir):
    """Locate the HTML directory by finding the actual login page."""

    candidates = [
        start_dir / "HTML",
        start_dir.parent / "HTML",
        start_dir / "app" / "HTML",
        start_dir.parent / "app" / "HTML",
    ]

    for folder in candidates:
        login_page = folder / "Login&Signup_HTML" / "index.html"

        if login_page.is_file():
            return folder.resolve()

    search_roots = [start_dir, start_dir.parent]
    visited = set()

    for root in search_roots:
        if not root.exists():
            continue

        try:
            for login_page in root.rglob("index.html"):
                try:
                    if not login_page.is_file():
                        continue

                    if login_page.parent.name.casefold() != "login&signup_html":
                        continue

                    html_root = login_page.parent.parent

                    present_folders = {
                        item.name.casefold()
                        for item in html_root.iterdir()
                        if item.is_dir()
                    }

                    if (
                        "admin_html" in present_folders
                        and "developer_html" in present_folders
                    ):
                        return html_root.resolve()

                    if html_root not in visited:
                        visited.add(html_root)
                        return html_root.resolve()

                except (OSError, PermissionError):
                    continue

        except (OSError, PermissionError):
            continue

    raise FileNotFoundError(
        "Could not locate the login page.\n"
        "Expected: HTML/Login&Signup_HTML/index.html\n"
        f"Search started from: {start_dir}\n"
        f"Also searched parent: {start_dir.parent}"
    )


HTML_DIR = find_html_root(APP_DIR)
PROJECT_ROOT = HTML_DIR.parent

LOGIN_DIR = HTML_DIR / "Login&Signup_HTML"
ADMIN_DIR = HTML_DIR / "Admin_HTML"
DEVELOPER_DIR = HTML_DIR / "Developer_HTML"
USER_DIR = HTML_DIR / "Normal_User_HTML"
WORKER_DIR = HTML_DIR / "Worker_HTML"

database_candidates = [
    APP_DIR / "users.db",
    PROJECT_ROOT / "users.db",
]

DATABASE_PATH = next(
    (path for path in database_candidates if path.is_file()),
    APP_DIR / "users.db",
)

schema_candidates = [
    APP_DIR / "schema.sql",
    PROJECT_ROOT / "schema.sql",
]

SCHEMA_PATH = next(
    (path for path in schema_candidates if path.is_file()),
    APP_DIR / "schema.sql",
)

HOST = "127.0.0.1"
PORT = 8000

PASSWORD_HASH_ITERATIONS = 600_000
MAX_FORM_BYTES = 16_384

# Existing static Super Admin login.
# This remains separate from database-based Gmail accounts.
SUPER_ADMIN_LOGIN_ID = "123"
SUPER_ADMIN_PASSWORD = "qwe123"

# Session token -> database user ID.
SESSIONS = {}

# Admin session token -> role.
# Roles: "super_admin" or "admin".
ADMIN_SESSIONS = {}

# Worker session token -> database user ID.
# Staff accounts use the Worker dashboard.
WORKER_SESSIONS = {}


# =========================================================
# DATABASE
# =========================================================

@contextmanager
def database_connection():
    """Open and safely close a SQLite connection."""

    connection = sqlite3.connect(DATABASE_PATH, timeout=10)

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    """Verify the User table and its required columns."""

    if not DATABASE_PATH.is_file() and not SCHEMA_PATH.is_file():
        raise FileNotFoundError(
            "Database and schema were not found.\n"
            f"Database: {DATABASE_PATH}\n"
            f"Schema: {SCHEMA_PATH}"
        )

    with database_connection() as connection:
        if SCHEMA_PATH.is_file():
            connection.executescript(
                SCHEMA_PATH.read_text(encoding="utf-8")
            )

        tables = {
            row[0].casefold()
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }

        if "user" not in tables:
            raise RuntimeError('Missing database table: "User"')

        columns = {
            row[1].casefold()
            for row in connection.execute(
                'PRAGMA table_info("User")'
            ).fetchall()
        }

        required_columns = {
            "u_id",
            "u_type",
            "u_mail",
            "u_pass",
            "u_status",
        }

        missing_columns = required_columns - columns

        if missing_columns:
            raise RuntimeError(
                'The "User" table is missing columns: '
                + ", ".join(sorted(missing_columns))
                + ". Back up the database and migrate the old column names."
            )

    print("Database initialized.")
    print("Database path:", DATABASE_PATH)
    print('Verified "User" table with U_Mail and U_Type.')


# =========================================================
# EMAIL VALIDATION
# =========================================================

def is_valid_gmail(email):
    """Validate the format of a Gmail address."""

    if not email or len(email) > 254:
        return False

    return bool(
        re.fullmatch(
            r"[a-zA-Z0-9._%+-]+@gmail\.com",
            email,
            flags=re.IGNORECASE,
        )
    )


# =========================================================
# PASSWORD HELPERS
# =========================================================

def hash_password(password):
    """Hash a password using PBKDF2-HMAC-SHA256."""

    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )

    return (
        f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}"
        f"${salt.hex()}${digest.hex()}"
    )


def verify_password(password, stored_hash):
    """Verify a password against its stored hash."""

    try:
        algorithm, iterations_text, salt_text, expected = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_text)

        if iterations < 1 or len(salt) != 16:
            return False

        if len(expected) != 64:
            return False

    except (ValueError, TypeError, AttributeError):
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    ).hex()

    return hmac.compare_digest(digest, expected)


# =========================================================
# HTTP HANDLER
# =========================================================

class PortalHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            directory=str(PROJECT_ROOT),
            **kwargs,
        )

    # -----------------------------------------------------
    # GET ROUTES
    # -----------------------------------------------------

    def do_GET(self):
        requested_path = urlsplit(self.path).path

        for _ in range(5):
            decoded_path = unquote(requested_path)

            if decoded_path == requested_path:
                break

            requested_path = decoded_path

        requested_path = posixpath.normpath(requested_path)
        route = requested_path.casefold()

        if route in {"/", "/index.html", "/login"}:
            self._serve_html_file(LOGIN_DIR, "index.html")
            return

        if route in {"/register", "/register.html"}:
            self._serve_html_file(LOGIN_DIR, "register.html")
            return

        if route in {"/admin", "/admin.html"}:
            self._show_admin()
            return

        if route in {"/worker", "/worker.html"}:
            self._show_worker()
            return

        if route in {"/super-admin", "/super_admin", "/super_admin.html"}:
            self._show_super_admin()
            return

        if route in {"/landuser", "/landuser.html", "/dashboard"}:
            self._show_landuser()
            return

        if route in {"/worker", "/worker.html"}:
            self._show_worker()
            return

        if route == "/api/admin-data":
            self._get_admin_data()
            return

        if route == "/api/staff":
            self._get_staff()
            return

        if route == "/api/grantees":
            self._get_grantees()
            return

        if route == "/logout":
            self._logout()
            return

        if route == "/admin-logout":
            self._admin_logout()
            return

        if route in {"/users.db", "/schema.sql", "/app.py"}:
            self.send_error(404, "Page not found")
            return

        super().do_GET()

    # -----------------------------------------------------
    # POST ROUTES
    # -----------------------------------------------------

    def do_POST(self):
        route = urlsplit(self.path).path.casefold()

        allowed_routes = {
            "/login",
            "/register",
            "/logout",
            "/admin-logout",
            "/worker-logout",
            "/api/add-admin",
            "/api/staff/add",
            "/api/staff",
        }

        if route not in allowed_routes:
            self.send_error(404, "Page not found")
            return

        if route == "/logout":
            self._logout()
            return

        if route == "/worker-logout":
            self._worker_logout()
            return

        if route == "/admin-logout":
            self._admin_logout()
            return

        form = self._read_form()

        if form is None:
            return

        if route == "/login":
            self._login(form)

        elif route == "/register":
            self._register(form)

        elif route == "/api/add-admin":
            self._add_admin(form)

        elif route in {"/api/staff/add", "/api/staff"}:
            self._add_staff(form)

    # -----------------------------------------------------
    # FORM HELPERS
    # -----------------------------------------------------

    def _read_form(self):
        """Read JSON or URL-encoded form data."""

        content_type = self.headers.get_content_type()

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Invalid form length")
            return None

        if length <= 0 or length > MAX_FORM_BYTES:
            self.send_error(400, "Invalid form length")
            return None

        try:
            body = self.rfile.read(length).decode("utf-8")

            if content_type == "application/json":
                data = json.loads(body)

                if not isinstance(data, dict):
                    self.send_error(400, "Expected a JSON object")
                    return None

                # Keep compatibility with the existing _field() method.
                return {
                    key: [str(value) if value is not None else ""]
                    for key, value in data.items()
                }

            elif content_type == "application/x-www-form-urlencoded":
                return parse_qs(
                    body,
                    keep_blank_values=True,
                    max_num_fields=100,
                )

            else:
                self.send_error(
                    415,
                    "Expected JSON or URL-encoded form data",
                )
                return None

        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self.send_error(400, "Invalid form data")
            return None

    @staticmethod
    def _field(form, name):
        values = form.get(name, [])
        return values[0] if values else ""

    # -----------------------------------------------------
    # COOKIE AND SESSION HELPERS
    # -----------------------------------------------------

    def _cookie_value(self, name):
        cookie = SimpleCookie()

        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None

        morsel = cookie.get(name)
        return morsel.value if morsel else None

    def _admin_role(self):
        token = self._cookie_value("portal_admin")
        return ADMIN_SESSIONS.get(token or "")

    def _is_authenticated_admin(self):
        return self._admin_role() in {"super_admin", "admin"}

    def _is_super_admin(self):
        return self._admin_role() == "super_admin"

    # -----------------------------------------------------
    # RESPONSE HELPERS
    # -----------------------------------------------------

    def _redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _send_html(self, page):
        content = page.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(content)

    def _send_json(self, data, status=200):
        content = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(content)

    # -----------------------------------------------------
    # SERVE HTML
    # -----------------------------------------------------

    def _serve_html_file(self, folder, filename):
        page_path = folder / filename

        if not page_path.is_file():
            print("HTML file not found:", page_path)
            self.send_error(404, f"Page not found: {page_path}")
            return

        page = page_path.read_text(encoding="utf-8")
        self._send_html(page)

    # -----------------------------------------------------
    # LOGIN
    # -----------------------------------------------------


    def _login(self, form):
        # Accept Gmail or the older username field.
        login_id = (
            self._field(form, "email")
            or self._field(form, "username")
        ).strip()

        password = self._field(form, "password")

        if not login_id or not password:
            self._redirect("/?error=invalid")
            return

        if len(login_id) > 254 or len(password) > 256:
            self._redirect("/?error=invalid")
            return

        # 1. Check the static Super Admin credentials.
        if (
            hmac.compare_digest(login_id, SUPER_ADMIN_LOGIN_ID)
            and hmac.compare_digest(password, SUPER_ADMIN_PASSWORD)
        ):
            self._create_admin_session("super_admin")
            return

        # 2. Find the account in the database.
        try:
            with database_connection() as connection:
                row = connection.execute(
                    """
                    SELECT U_ID, U_Pass, U_Type, U_Status
                    FROM "User"
                    WHERE LOWER(U_Mail) = LOWER(?)
                    LIMIT 1
                    """,
                    (login_id.lower(),),
                ).fetchone()

        except sqlite3.Error as error:
            print("Login database error:", error)
            self._redirect("/?error=invalid")
            return

        if row is None:
            self._redirect("/?error=invalid")
            return

        user_id, stored_password, user_type, user_status = row

        # 3. Reject inactive accounts.
        if str(user_status or "").strip().casefold() != "active":
            self._redirect("/?error=invalid")
            return

        # 4. Verify the password.
        if not verify_password(password, stored_password):
            self._redirect("/?error=invalid")
            return

        account_type = str(user_type or "").strip().casefold()

        # 5. Admin accounts open the Admin dashboard.
        if account_type in {"admin", "administrator"}:
            self._create_admin_session("admin")
            return

        # 6. Staff accounts open the Worker dashboard.
        if account_type in {"staff", "worker"}:
            self._create_worker_session(user_id)
            return

        # 7. Regular User accounts open the User dashboard.
        if account_type == "user":
            self._create_user_session(user_id)
            return

        # Reject unknown account types.
        self._redirect("/?error=invalid")


    # -----------------------------------------------------
    # CREATE ADMIN SESSION
    # -----------------------------------------------------

    def _create_admin_session(self, role):
        if role not in {"super_admin", "admin"}:
            self._redirect("/")
            return

        old_admin_token = self._cookie_value("portal_admin")

        if old_admin_token:
            ADMIN_SESSIONS.pop(old_admin_token, None)

        old_student_token = self._cookie_value("portal_session")

        if old_student_token:
            SESSIONS.pop(old_student_token, None)

        token = secrets.token_urlsafe(32)
        ADMIN_SESSIONS[token] = role

        destination = "/super-admin" if role == "super_admin" else "/admin"

        self.send_response(303)
        self.send_header("Location", destination)
        self.send_header(
            "Set-Cookie",
            f"portal_admin={token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.send_header(
            "Set-Cookie",
            "portal_session=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.end_headers()


    # -----------------------------------------------------
    # CREATE WORKER SESSION
    # -----------------------------------------------------

    def _create_worker_session(self, user_id):
        # Remove the previous worker session.
        old_worker_token = self._cookie_value("portal_worker")
        if old_worker_token:
            WORKER_SESSIONS.pop(old_worker_token, None)

        # Remove any previous user session.
        old_user_token = self._cookie_value("portal_session")
        if old_user_token:
            SESSIONS.pop(old_user_token, None)

        # Remove any previous admin session.
        old_admin_token = self._cookie_value("portal_admin")
        if old_admin_token:
            ADMIN_SESSIONS.pop(old_admin_token, None)

        token = secrets.token_urlsafe(32)
        WORKER_SESSIONS[token] = user_id

        self.send_response(303)
        self.send_header("Location", "/worker")
        self.send_header(
            "Set-Cookie",
            f"portal_worker={token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.send_header(
            "Set-Cookie",
            "portal_session=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.send_header(
            "Set-Cookie",
            "portal_admin=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # -----------------------------------------------------
    # VERIFY WORKER SESSION
    # -----------------------------------------------------

    def _is_authenticated_worker(self):
        token = self._cookie_value("portal_worker")
        user_id = WORKER_SESSIONS.get(token or "")

        if user_id is None:
            return False

        try:
            with database_connection() as connection:
                row = connection.execute(
                    """
                    SELECT U_Type, U_Status
                    FROM "User"
                    WHERE U_ID = ?
                    """,
                    (user_id,),
                ).fetchone()

        except sqlite3.Error as error:
            print("Worker authentication database error:", error)
            return False

        if row is None:
            WORKER_SESSIONS.pop(token or "", None)
            return False

        account_type = str(row[0] or "").strip().casefold()
        status = str(row[1] or "").strip().casefold()

        return account_type in {"staff", "worker"} and status == "active"


    # -----------------------------------------------------
    # REGISTER NORMAL USER
    # -----------------------------------------------------

    def _register(self, form):
        email = self._field(form, "email").strip().lower()
        password = self._field(form, "password")
        confirmation = self._field(form, "confirm_password")

        if (
            not is_valid_gmail(email)
            or not password
            or len(password) > 256
            or password != confirmation
        ):
            self._redirect("/register?error=invalid")
            return

        if hmac.compare_digest(email, SUPER_ADMIN_LOGIN_ID):
            self._redirect("/register?error=exists")
            return

        try:
            with database_connection() as connection:
                existing = connection.execute(
                    """
                    SELECT U_ID
                    FROM "User"
                    WHERE LOWER(U_Mail) = LOWER(?)
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()

                if existing:
                    self._redirect("/register?error=exists")
                    return

                connection.execute(
                    """
                    INSERT INTO "User" (
                        U_Type,
                        U_Mail,
                        U_Pass,
                        U_Status
                    )
                    VALUES ('User', ?, ?, 'Active')
                    """,
                    (email, hash_password(password)),
                )

        except sqlite3.Error as error:
            print("Registration database error:", error)
            self._redirect("/register?error=invalid")
            return

        self._redirect("/?registered=1")

    # -----------------------------------------------------
    # ADD ADMIN USING GMAIL
    # -----------------------------------------------------

    def _add_admin(self, form):
        """Create an administrator account using a Gmail address."""

        if not self._is_super_admin():
            self._send_json(
                {"error": "Unauthorized. Super Admin access required."},
                401,
            )
            return

        email = (self._field(form, "email") or "").strip().lower()
        password = self._field(form, "password") or ""

        # Validate required fields.
        if not email or not password.strip():
            self._send_json(
                {"error": "Enter a valid Gmail address and password."},
                400,
            )
            return

        # Validate Gmail format on the server.
        import re

        if not re.fullmatch(
                r"[a-zA-Z0-9._%+-]+@gmail\.com",
                email,
                re.IGNORECASE,
        ):
            self._send_json(
                {"error": "Enter a valid Gmail address ending in @gmail.com."},
                400,
            )
            return

        if len(email) > 254 or len(password) > 256:
            self._send_json(
                {"error": "The Gmail address or password exceeds the allowed length."},
                400,
            )
            return

        # Use your existing password hashing function.
        password_hash = hash_password(password)

        try:
            with database_connection() as connection:

                # Prevent duplicate email addresses.
                existing = connection.execute(
                    """
                    SELECT U_ID
                    FROM "User"
                    WHERE LOWER(U_Mail) = LOWER(?)
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()

                if existing:
                    self._send_json(
                        {"error": "That Gmail address is already registered."},
                        409,
                    )
                    return

                # Create the administrator account.
                cursor = connection.execute(
                    """
                    INSERT INTO "User" (
                        U_Type,
                        U_Mail,
                        U_Pass,
                        U_Status
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    ("Admin", email, password_hash, "Active"),
                )

                admin_id = cursor.lastrowid

            self._send_json(
                {
                    "success": True,
                    "message": "Administrator account created successfully.",
                    "admin": {
                        "id": admin_id,
                        "email": email,
                        "role": "Admin",
                        "status": "Active",
                    },
                },
                201,
            )

        except sqlite3.Error as error:
            print(f"Add admin database error: {error}")

            self._send_json(
                {"error": "Could not save the administrator account. Check the server log."},
                500,
            )

    # -----------------------------------------------------
    # STAFF DATA API
    # -----------------------------------------------------



    def _get_staff(self):
        """Return Staff accounts and their count as JSON."""

        if not self._is_authenticated_admin():
            self._send_json(
                {"error": "Unauthorized. Admin access required."},
                401,
            )
            return

        try:
            with database_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT U_ID, U_Mail, U_Status
                    FROM "User"
                    WHERE LOWER(TRIM(U_Type)) = 'staff'
                    ORDER BY U_ID DESC
                    """
                ).fetchall()

            staff_members = [
                {
                    "id": row[0],
                    "email": row[1],
                    "status": row[2] or "Active",
                }
                for row in rows
            ]

            self._send_json(
                {
                    "staff": staff_members,
                    "totalStaff": len(staff_members),
                }
            )

        except sqlite3.Error as error:
            print("Staff data database error:", error)

            self._send_json(
                {"error": "Could not retrieve staff accounts."},
                500,
            )


    def _get_grantees(self):
        """Return grantee records to authenticated Admin and Worker accounts."""

        is_admin = self._is_authenticated_admin()

        worker_token = self._cookie_value("portal_worker")
        worker_user_id = WORKER_SESSIONS.get(worker_token or "")

        is_worker = (
            worker_user_id is not None
            and self._is_authenticated_worker()
        )

        if not is_admin and not is_worker:
            self._send_json(
                {"error": "Unauthorized. Admin or Worker access required."},
                401,
            )
            return

        try:
            with database_connection() as connection:
                # Check which tables actually exist.
                tables = connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    ORDER BY name
                    """
                ).fetchall()

                table_names = {
                    row[0].casefold(): row[0]
                    for row in tables
                }

                if "grantee" not in table_names:
                    available_tables = [
                        row[0] for row in tables
                    ]

                    print(
                        "Grantee table not found. Available tables:",
                        available_tables,
                    )

                    self._send_json(
                        {
                            "error": (
                                "The Grantee table does not exist "
                                "in the configured database."
                            ),
                            "availableTables": available_tables,
                        },
                        500,
                    )
                    return

                # Use the actual table name returned by SQLite.
                table_name = table_names["grantee"]

                # The table name comes from sqlite_master, not user input.
                quoted_table = '"' + table_name.replace('"', '""') + '"'

                cursor = connection.execute(
                    f"SELECT * FROM {quoted_table} ORDER BY 1 DESC"
                )

                columns = [
                    description[0]
                    for description in cursor.description
                ]

                rows = cursor.fetchall()

            grantees = [
                dict(zip(columns, row))
                for row in rows
            ]

            # Handle common capitalization variations in column names.
            def get_value(record, *names):
                normalized = {
                    str(key).casefold(): value
                    for key, value in record.items()
                }

                for name in names:
                    if name.casefold() in normalized:
                        return normalized[name.casefold()]

                return ""

            approved_count = sum(
                1 for record in grantees
                if str(
                    get_value(record, "Status", "U_Status")
                ).strip().casefold() == "approved"
            )

            pending_count = sum(
                1 for record in grantees
                if str(
                    get_value(record, "Status", "U_Status")
                ).strip().casefold()
                in {"pending", "pending review"}
            )

            self._send_json(
                {
                    "grantees": grantees,
                    "totalGrantees": len(grantees),
                    "approved": approved_count,
                    "pending": pending_count,
                }
            )

        except sqlite3.Error as error:
            print("Grantees API database error:", error)

            self._send_json(
                {
                    "error": "Could not retrieve grantee records.",
                    "details": str(error),
                },
                500,
            )


    # -----------------------------------------------------
    # ADD STAFF ACCOUNT
    # -----------------------------------------------------

    def _add_staff(self, form):
        """Create a Staff account using Gmail and password only."""

        if not self._is_authenticated_admin():
            self._send_json(
                {"error": "Unauthorized. Admin access required."},
                401,
            )
            return

        email = self._field(form, "email").strip().lower()
        password = self._field(form, "password")

        if not is_valid_gmail(email):
            self._send_json(
                {
                    "error":
                    "Enter a valid Gmail address ending in @gmail.com."
                },
                400,
            )
            return

        if not password or not password.strip():
            self._send_json(
                {"error": "Password is required."},
                400,
            )
            return

        if len(password) > 256:
            self._send_json(
                {"error": "Password must not exceed 256 characters."},
                400,
            )
            return

        try:
            with database_connection() as connection:
                existing = connection.execute(
                    """
                    SELECT U_ID
                    FROM "User"
                    WHERE LOWER(U_Mail) = LOWER(?)
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()

                if existing:
                    self._send_json(
                        {
                            "error":
                            "That Gmail address is already registered."
                        },
                        409,
                    )
                    return

                cursor = connection.execute(
                    """
                    INSERT INTO "User" (
                        U_Type,
                        U_Mail,
                        U_Pass,
                        U_Status
                    )
                    VALUES ('Staff', ?, ?, 'Active')
                    """,
                    (email, hash_password(password)),
                )

                staff_id = cursor.lastrowid

            self._send_json(
                {
                    "success": True,
                    "message": "Staff account created successfully.",
                    "staff": {
                        "id": staff_id,
                        "email": email,
                        "status": "Active",
                    },
                },
                201,
            )

        except sqlite3.Error as error:
            print("Add staff database error:", error)

            self._send_json(
                {"error": "Could not save the staff account."},
                500,
            )

    # -----------------------------------------------------
    # SUPER ADMIN DATA API
    # -----------------------------------------------------

    def _get_admin_data(self):
        if not self._is_super_admin():
            self._send_json(
                {
                    "error": (
                        "Unauthorized. Super Admin access required."
                    )
                },
                401,
            )
            return

        try:
            with database_connection() as connection:
                admins = connection.execute(
                    """
                    SELECT U_ID, U_Mail, U_Status
                    FROM "User"
                    WHERE LOWER(U_Type) = 'admin'
                    ORDER BY U_ID DESC
                    """
                ).fetchall()

                user_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM "User"
                    WHERE LOWER(U_Type) = 'user'
                    """
                ).fetchone()[0]

            self._send_json(
                {
                    "admins": [
                        {
                            "id": row[0],
                            "email": row[1],
                            "role": "Admin",
                            "status": row[2] or "Active",
                        }
                        for row in admins
                    ],
                    "totalAdmins": len(admins),
                    "totalUsers": user_count,
                }
            )

        except sqlite3.Error as error:
            print("Admin data database error:", error)

            self._send_json(
                {"error": "Could not retrieve dashboard data."},
                500,
            )


    # -----------------------------------------------------
    # REGULAR ADMIN DASHBOARD
    # -----------------------------------------------------

    def _show_admin(self):
        role = self._admin_role()

        if role != "admin":
            if role == "super_admin":
                self._redirect("/super-admin")
            else:
                self._redirect("/")
            return

        self._serve_html_file(ADMIN_DIR, "admin.html")

    # -----------------------------------------------------
    # SUPER ADMIN DASHBOARD
    # -----------------------------------------------------

    def _show_super_admin(self):
        role = self._admin_role()

        if role != "super_admin":
            if role == "admin":
                self._redirect("/admin")
            else:
                self._redirect("/")
            return

        self._serve_html_file(DEVELOPER_DIR, "super_admin.html")

    # -----------------------------------------------------
    # NORMAL USER DASHBOARD
    # -----------------------------------------------------

    def _show_landuser(self):
        token = self._cookie_value("portal_session")
        user_id = SESSIONS.get(token or "")

        if user_id is None:
            self._redirect("/")
            return

        try:
            with database_connection() as connection:
                user = connection.execute(
                    """
                    SELECT U_Mail, U_Type, U_Status
                    FROM "User"
                    WHERE U_ID = ?
                    """,
                    (user_id,),
                ).fetchone()

        except sqlite3.Error as error:
            print("User dashboard database error:", error)
            self._redirect("/")
            return

        if user is None:
            SESSIONS.pop(token or "", None)
            self._redirect("/")
            return

        account_type = user[1].strip().casefold() if user[1] else ""
        status = user[2].strip().casefold() if user[2] else ""

        if account_type != "user" or status != "active":
            SESSIONS.pop(token or "", None)
            self._redirect("/")
            return

        self._serve_html_file(USER_DIR, "landuser.html")

    # -----------------------------------------------------
    # WORKER PAGE
    # -----------------------------------------------------

    def _show_worker(self):
        if not self._is_authenticated_worker():
            self._redirect("/")
            return

        self._serve_html_file(WORKER_DIR, "worker.html")


    # -----------------------------------------------------
    # CREATE REGULAR USER SESSION
    # -----------------------------------------------------

    def _create_user_session(self, user_id):
        old_user_token = self._cookie_value("portal_session")
        if old_user_token:
            SESSIONS.pop(old_user_token, None)

        old_worker_token = self._cookie_value("portal_worker")
        if old_worker_token:
            WORKER_SESSIONS.pop(old_worker_token, None)

        old_admin_token = self._cookie_value("portal_admin")
        if old_admin_token:
            ADMIN_SESSIONS.pop(old_admin_token, None)

        token = secrets.token_urlsafe(32)
        SESSIONS[token] = user_id

        self.send_response(303)
        self.send_header("Location", "/landuser")
        self.send_header(
            "Set-Cookie",
            f"portal_session={token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.send_header(
            "Set-Cookie",
            "portal_worker=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        )
        self.send_header(
            "Set-Cookie",
            "portal_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


    # -----------------------------------------------------
    # STUDENT LOGOUT
    # -----------------------------------------------------

    def _logout(self):
        token = self._cookie_value("portal_session")

        if token:
            SESSIONS.pop(token, None)

        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            "portal_session=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.end_headers()

    # -----------------------------------------------------
    # ADMIN LOGOUT
    # -----------------------------------------------------

    def _admin_logout(self):
        token = self._cookie_value("portal_admin")

        if token:
            ADMIN_SESSIONS.pop(token, None)

        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            "portal_admin=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.end_headers()

    # -----------------------------------------------------
    # SERVER LOGGING
    # -----------------------------------------------------

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")


    # -----------------------------------------------------
    # WORKER LOGOUT
    # -----------------------------------------------------

    def _worker_logout(self):
        token = self._cookie_value("portal_worker")

        if token:
            WORKER_SESSIONS.pop(token, None)

        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            "portal_worker=; Path=/; HttpOnly; "
            "SameSite=Lax; Max-Age=0",
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()



# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("St. Cecilia's College Portal")
    print("Application directory:", APP_DIR)
    print("Project root:", PROJECT_ROOT)
    print("HTML directory:", HTML_DIR)
    print("Login page:", LOGIN_DIR / "index.html")
    print("Registration page:", LOGIN_DIR / "register.html")
    print("Admin page:", ADMIN_DIR / "admin.html")
    print("Super Admin page:", DEVELOPER_DIR / "super_admin.html")
    print("Normal User page:", USER_DIR / "landuser.html")
    print("Worker page:", WORKER_DIR / "worker.html")
    print("Database:", DATABASE_PATH)
    print("=" * 60)

    initialize_database()

    server = ThreadingHTTPServer((HOST, PORT), PortalHandler)

    print(f"Portal URL: http://{HOST}:{PORT}/")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nShutting down the portal server...")

    finally:
        server.server_close()
