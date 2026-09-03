import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://127.0.0.1:6379/0"
)

celery = Celery(
    "vulnscan",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks"]
)

# Configure TLS for Upstash Redis
if REDIS_URL.startswith("rediss://"):
    celery.conf.broker_use_ssl = {
        "ssl_cert_reqs": "CERT_REQUIRED"
    }

    celery.conf.redis_backend_use_ssl = {
        "ssl_cert_reqs": "CERT_REQUIRED"
    }

celery.conf.update(
    task_track_started=True,
    result_expires=3600,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json"
)