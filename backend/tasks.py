import json

from celery_app import celery
from db import set_scan
from scanner.engine import scan


@celery.task(bind=True)
def run_scan(self, scan_id, url):

    set_scan(
        scan_id,
        status="RUNNING",
        error=None
    )

    try:
        result = scan(url)

        set_scan(
            scan_id,
            status="COMPLETED",
            score=result["score"],
            grade=result["grade"],
            result_json=json.dumps(result)
        )

        return result

    except Exception as error:

        set_scan(
            scan_id,
            status="FAILED",
            error=str(error)
        )

        raise