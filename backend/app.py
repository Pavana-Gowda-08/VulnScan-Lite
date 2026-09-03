import io
import json
import os

from dotenv import load_dotenv

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_file
)

from flask_cors import CORS

from werkzeug.security import (
    check_password_hash
)

from celery_app import celery

from db import (
    init_db,
    create_user,
    get_user,
    create_scan,
    get_scan,
    list_scans
)

from tasks import run_scan

from pdf_report import make_pdf


load_dotenv()


app = Flask(__name__)


app.secret_key = os.getenv(
    "SECRET_KEY",
    "dev-only-secret"
)

@app.get("/")
def home():
    return jsonify({
        "ok": True,
        "service": "VulnScan Lite",
        "message": "Backend is running"
    })

CORS(

    app,

    supports_credentials=True,

    origins=[
        os.getenv(
            "FRONTEND_ORIGIN",
            "http://localhost:5173"
        )
    ]
)


init_db()


def current_user():

    return session.get(
        "user_id"
    )


@app.get("/api/health")
def health():

    return jsonify({

        "ok":
            True,

        "service":
            "VulnScan Lite"
    })


@app.post("/api/auth/register")
def register():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    email = (
        data.get(
            "email",
            ""
        )
        .strip()
    )

    password = data.get(
        "password",
        ""
    )

    if (
        "@" not in email
        or len(password) < 8
    ):

        return jsonify({

            "error":
                "Enter a valid email "
                "and password of at least "
                "8 characters."
        }), 400

    try:

        user_id = create_user(
            email,
            password
        )

    except Exception:

        return jsonify({

            "error":
                "Email already registered."
        }), 409

    session[
        "user_id"
    ] = user_id

    return jsonify({

        "user": {

            "id":
                user_id,

            "email":
                email
        }

    }), 201


@app.post("/api/auth/login")
def login():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    email = data.get(
        "email",
        ""
    )

    password = data.get(
        "password",
        ""
    )

    user = get_user(
        email
    )

    if (
        not user
        or not check_password_hash(
            user["password_hash"],
            password
        )
    ):

        return jsonify({

            "error":
                "Invalid credentials."
        }), 401

    session[
        "user_id"
    ] = user["id"]

    return jsonify({

        "user": {

            "id":
                user["id"],

            "email":
                user["email"]
        }
    })


@app.post("/api/auth/logout")
def logout():

    session.clear()

    return jsonify({
        "ok": True
    })


@app.get("/api/auth/me")
def me():

    user_id = current_user()

    if not user_id:

        return jsonify({
            "user": None
        })

    return jsonify({

        "user": {

            "id":
                user_id
        }
    })


@app.post("/api/scan")
def start_scan():

    user_id = current_user()

    if not user_id:

        return jsonify({

            "error":
                "Login required."
        }), 401

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    url = (
        data.get(
            "url",
            ""
        )
        .strip()
    )

    if not url:

        return jsonify({

            "error":
                "URL is required."
        }), 400

    scan_id = create_scan(
        user_id,
        url
    )

    task = run_scan.delay(
        scan_id,
        url
    )

    return jsonify({

        "scan_id":
            scan_id,

        "task_id":
            task.id,

        "status":
            "QUEUED"
    }), 202


@app.get(
    "/api/scan/<int:scan_id>/status"
)
def scan_status(scan_id):

    user_id = current_user()

    if not user_id:

        return jsonify({

            "error":
                "Login required."
        }), 401

    scan = get_scan(
        scan_id,
        user_id
    )

    if not scan:

        return jsonify({

            "error":
                "Scan not found."
        }), 404

    response = {

        "id":
            scan["id"],

        "url":
            scan["url"],

        "status":
            scan["status"],

        "score":
            scan["score"],

        "grade":
            scan["grade"],

        "error":
            scan["error"]
    }

    if (
        scan["status"]
        == "COMPLETED"
        and scan["result_json"]
    ):

        response["result"] = json.loads(
            scan["result_json"]
        )

    return jsonify(
        response
    )


@app.get("/api/history")
def history():

    user_id = current_user()

    if not user_id:

        return jsonify({

            "error":
                "Login required."
        }), 401

    return jsonify({

        "scans":
            list_scans(
                user_id
            )
    })


@app.get(
    "/api/scan/<int:scan_id>/pdf"
)
def pdf(scan_id):

    user_id = current_user()

    if not user_id:

        return jsonify({

            "error":
                "Login required."
        }), 401

    scan = get_scan(
        scan_id,
        user_id
    )

    if (
        not scan
        or scan["status"]
        != "COMPLETED"
    ):

        return jsonify({

            "error":
                "Completed scan required."
        }), 400

    result = json.loads(
        scan["result_json"]
    )

    pdf_data = make_pdf(
        result
    )

    return send_file(

        io.BytesIO(
            pdf_data
        ),

        mimetype="application/pdf",

        as_attachment=True,

        download_name=(
            f"vulnscan-{scan_id}.pdf"
        )
    )


if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True
    )