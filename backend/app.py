import io
import json
import os

from dotenv import load_dotenv

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_file,
)

from flask_cors import CORS

from werkzeug.security import check_password_hash

from celery_app import celery

from db import (
    init_db,
    create_user,
    get_user,
    create_scan,
    get_scan,
    list_scans,
)

from tasks import run_scan

from pdf_report import make_pdf


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


app.secret_key = os.getenv(
    "SECRET_KEY",
    "dev-only-secret",
)


# ============================================================
# SESSION CONFIGURATION
# Required for Vercel frontend -> Railway backend cookies
# ============================================================

app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "http://localhost:5173",
).strip().rstrip("/")


allowed_origins = [
    frontend_origin,
]


# Allow local Vite development in addition to production
if "http://localhost:5173" not in allowed_origins:
    allowed_origins.append("http://localhost:5173")


CORS(
    app,
    supports_credentials=True,
    origins=allowed_origins,
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

init_db()


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return jsonify(
        {
            "ok": True,
            "service": "VulnScan Lite",
            "message": "Backend is running",
        }
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health():

    return jsonify(
        {
            "ok": True,
            "service": "VulnScan Lite",
        }
    )


# ============================================================
# CURRENT USER
# ============================================================

def current_user():

    return session.get("user_id")


# ============================================================
# REGISTER
# ============================================================

@app.post("/api/auth/register")
def register():

    data = (
        request.get_json(silent=True)
        or {}
    )

    email = (
        data.get("email", "")
        .strip()
        .lower()
    )

    password = data.get(
        "password",
        "",
    )

    if (
        "@" not in email
        or len(password) < 8
    ):

        return jsonify(
            {
                "error": (
                    "Enter a valid email "
                    "and password of at least "
                    "8 characters."
                )
            }
        ), 400

    try:

        user_id = create_user(
            email,
            password,
        )

    except Exception as exc:

        print(
            "REGISTER ERROR:",
            repr(exc),
        )

        return jsonify(
            {
                "error": (
                    "Email already registered."
                )
            }
        ), 409

    session["user_id"] = user_id

    return jsonify(
        {
            "user": {
                "id": user_id,
                "email": email,
            }
        }
    ), 201


# ============================================================
# LOGIN
# ============================================================

@app.post("/api/auth/login")
def login():

    data = (
        request.get_json(silent=True)
        or {}
    )

    email = (
        data.get("email", "")
        .strip()
        .lower()
    )

    password = data.get(
        "password",
        "",
    )

    if not email or not password:

        return jsonify(
            {
                "error": "Email and password are required."
            }
        ), 400

    try:

        user = get_user(email)

    except Exception as exc:

        print(
            "LOGIN DATABASE ERROR:",
            repr(exc),
        )

        return jsonify(
            {
                "error": "Database connection error."
            }
        ), 500

    if (
        not user
        or not check_password_hash(
            user["password_hash"],
            password,
        )
    ):

        return jsonify(
            {
                "error": "Invalid credentials."
            }
        ), 401

    # Create authenticated session
    session["user_id"] = user["id"]

    return jsonify(
        {
            "user": {
                "id": user["id"],
                "email": user["email"],
            }
        }
    )


# ============================================================
# LOGOUT
# ============================================================

@app.post("/api/auth/logout")
def logout():

    session.clear()

    return jsonify(
        {
            "ok": True,
        }
    )


# ============================================================
# AUTHENTICATED USER
# ============================================================

@app.get("/api/auth/me")
def me():

    user_id = current_user()

    if not user_id:

        return jsonify(
            {
                "user": None,
            }
        )

    user = None

    try:

        # Get complete user information
        with_user = None

        # get_user expects email, so we only return
        # the authenticated user ID here.
        user = {
            "id": user_id,
        }

    except Exception:
        user = {
            "id": user_id,
        }

    return jsonify(
        {
            "user": user,
        }
    )


# ============================================================
# START SCAN
# ============================================================

@app.post("/api/scan")
def start_scan():

    user_id = current_user()

    if not user_id:

        return jsonify(
            {
                "error": "Login required.",
            }
        ), 401

    data = (
        request.get_json(silent=True)
        or {}
    )

    url = (
        data.get("url", "")
        .strip()
    )

    if not url:

        return jsonify(
            {
                "error": "URL is required.",
            }
        ), 400

    try:

        scan_id = create_scan(
            user_id,
            url,
        )

        task = run_scan.delay(
            scan_id,
            url,
        )

    except Exception as exc:

        print(
            "SCAN START ERROR:",
            repr(exc),
        )

        return jsonify(
            {
                "error": (
                    "Unable to start scan."
                )
            }
        ), 500

    return jsonify(
        {
            "scan_id": scan_id,
            "task_id": task.id,
            "status": "QUEUED",
        }
    ), 202


# ============================================================
# SCAN STATUS
# ============================================================

@app.get(
    "/api/scan/<int:scan_id>/status"
)
def scan_status(scan_id):

    user_id = current_user()

    if not user_id:

        return jsonify(
            {
                "error": "Login required.",
            }
        ), 401

    try:

        scan = get_scan(
            scan_id,
            user_id,
        )

    except Exception as exc:

        print(
            "SCAN STATUS DATABASE ERROR:",
            repr(exc),
        )

        return jsonify(
            {
                "error": "Database connection error.",
            }
        ), 500

    if not scan:

        return jsonify(
            {
                "error": "Scan not found.",
            }
        ), 404

    response = {
        "id": scan["id"],
        "url": scan["url"],
        "status": scan["status"],
        "score": scan["score"],
        "grade": scan["grade"],
        "error": scan["error"],
    }

    if (
        scan["status"] == "COMPLETED"
        and scan["result_json"]
    ):

        try:

            response["result"] = json.loads(
                scan["result_json"]
            )

        except Exception:

            response["result"] = {}

    return jsonify(response)


# ============================================================
# SCAN HISTORY
# ============================================================

@app.get("/api/history")
def history():

    user_id = current_user()

    if not user_id:

        return jsonify(
            {
                "error": "Login required.",
            }
        ), 401

    try:

        scans = list_scans(
            user_id
        )

    except Exception as exc:

        print(
            "HISTORY DATABASE ERROR:",
            repr(exc),
        )

        return jsonify(
            {
                "error": "Database connection error.",
            }
        ), 500

    return jsonify(
        {
            "scans": scans,
        }
    )


# ============================================================
# PDF REPORT
# ============================================================

@app.route("/api/scan/<int:scan_id>/pdf", methods=["GET"])
def scan_pdf(scan_id):
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    scan = get_scan(scan_id, user_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if scan["status"] != "COMPLETED":
        return jsonify({
            "error": "Scan is not completed yet"
        }), 400

    try:
        pdf_data = make_pdf(scan)

        return send_file(
            io.BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"vulnscan-report-{scan_id}.pdf"
        )

    except Exception as e:
        print("PDF GENERATION ERROR:", str(e))
        return jsonify({
            "error": "Failed to generate PDF",
            "details": str(e)
        }), 500
        
# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )