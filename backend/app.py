import io
import json
import os

from flask import Flask, jsonify, request, session, send_file
from flask_cors import CORS
from werkzeug.security import check_password_hash

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
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "change-this-secret-key-in-production"
)


# ============================================================
# SESSION CONFIGURATION
# ============================================================

app.config.update(
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,
)


# ============================================================
# CORS
# ============================================================

frontend_origin = os.getenv(
    "FRONTEND_ORIGIN",
    "http://localhost:5173"
).strip().rstrip("/")

allowed_origins = [frontend_origin]

if "http://localhost:5173" not in allowed_origins:
    allowed_origins.append("http://localhost:5173")


CORS(
    app,
    supports_credentials=True,
    origins=allowed_origins
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

try:
    init_db()
except Exception as e:
    print("DATABASE INITIALIZATION ERROR:", e)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "service": "VulnScan Lite",
        "description": "On-Demand Web Vulnerability Scanner",
        "mode": "Passive security analysis",
        "status": "online",
        "disclaimer": (
            "Only scan websites you own or are authorized to assess. "
            "This tool performs passive analysis only."
        )
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/api/health")
def health():
    return jsonify({
        "ok": True,
        "service": "VulnScan Lite"
    })


# ============================================================
# REGISTER
# ============================================================

@app.route("/api/auth/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "error": "Password must contain at least 6 characters"
        }), 400

    try:
        user_id = create_user(email, password)

        return jsonify({
            "message": "Registration successful",
            "user": {
                "id": user_id,
                "email": email
            }
        }), 201

    except Exception as e:

        print("REGISTER ERROR:", e)

        return jsonify({
            "error": "Email may already be registered"
        }), 400


# ============================================================
# LOGIN
# ============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    try:

        user = get_user(email)

        if not user:
            return jsonify({
                "error": "Invalid email or password"
            }), 401

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            return jsonify({
                "error": "Invalid email or password"
            }), 401

        session.clear()

        session["user_id"] = user["id"]
        session["user_email"] = user["email"]

        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user["id"],
                "email": user["email"]
            }
        })

    except Exception as e:

        print("LOGIN ERROR:", e)

        return jsonify({
            "error": "Login failed"
        }), 500


# ============================================================
# LOGOUT
# ============================================================

@app.route("/api/auth/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "message": "Logged out successfully"
    })


# ============================================================
# CURRENT USER
# ============================================================

@app.route("/api/auth/me")
def current_user():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "user": None
        })

    return jsonify({
        "user": {
            "id": user_id,
            "email": session.get("user_email")
        }
    })


# ============================================================
# START SCAN
# ============================================================

@app.route("/api/scan", methods=["POST"])
def start_scan():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    data = request.get_json(silent=True) or {}

    url = str(data.get("url", "")).strip()

    if not url:
        return jsonify({
            "error": "URL is required"
        }), 400

    # Basic URL validation.
    if not (
        url.startswith("http://")
        or url.startswith("https://")
    ):
        url = "https://" + url

    try:

        scan_id = create_scan(
            user_id,
            url
        )

        # Queue asynchronous scan.
        task = run_scan.delay(
            scan_id,
            url
        )

        return jsonify({
            "scan_id": scan_id,
            "status": "QUEUED",
            "task_id": task.id,
            "message": "Scan queued successfully"
        }), 202

    except Exception as e:

        print("SCAN START ERROR:", e)

        return jsonify({
            "error": "Unable to start scan",
            "details": str(e)
        }), 500


# ============================================================
# SCAN STATUS
# Frontend polls this endpoint every 2 seconds.
# ============================================================

@app.route("/api/scan/<int:scan_id>/status")
def scan_status(scan_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    try:

        scan = get_scan(
            scan_id,
            user_id
        )

        if not scan:
            return jsonify({
                "error": "Scan not found"
            }), 404

        response = {
            "id": scan["id"],
            "url": scan["url"],
            "status": scan["status"],
            "score": scan.get("score"),
            "grade": scan.get("grade"),
            "error": scan.get("error")
        }

        # Only return detailed result when complete.
        if scan["status"] == "COMPLETED":

            result_json = scan.get("result_json")

            if result_json:

                try:
                    response["result"] = json.loads(
                        result_json
                    )
                except Exception:
                    response["result"] = {}

        return jsonify(response)

    except Exception as e:

        print("SCAN STATUS ERROR:", e)

        return jsonify({
            "error": "Unable to retrieve scan status",
            "details": str(e)
        }), 500


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/api/history")
def history():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    try:

        scans = list_scans(
            user_id,
            limit=50
        )

        # Convert datetime objects if PostgreSQL returns them.
        for scan in scans:

            if hasattr(
                scan.get("created_at"),
                "isoformat"
            ):
                scan["created_at"] = (
                    scan["created_at"].isoformat()
                )

        return jsonify({
            "scans": scans
        })

    except Exception as e:

        print("HISTORY ERROR:", e)

        return jsonify({
            "error": "Unable to retrieve scan history"
        }), 500


# ============================================================
# PDF REPORT
# ============================================================

@app.route("/api/scan/<int:scan_id>/pdf")
def scan_pdf(scan_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Unauthorized"
        }), 401

    try:

        scan = get_scan(
            scan_id,
            user_id
        )

        if not scan:
            return jsonify({
                "error": "Scan not found"
            }), 404

        if scan["status"] != "COMPLETED":
            return jsonify({
                "error": "Scan is not completed yet"
            }), 400

        # Pass the COMPLETE scan record.
        pdf_data = make_pdf(scan)

        return send_file(
            io.BytesIO(pdf_data),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=(
                f"vulnscan-report-{scan_id}.pdf"
            )
        )

    except Exception as e:

        print("PDF GENERATION ERROR:", e)

        return jsonify({
            "error": "Failed to generate PDF",
            "details": str(e)
        }), 500


# ============================================================
# RUN LOCALLY
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv("PORT", 5000)
        ),
        debug=True
    )