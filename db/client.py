import os
import json
import asyncpg
from logger import get_logger

log = get_logger("db")

async def save_scan(scan_id: str, url: str, status: str, report: dict, raw_results: dict):
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        log.warning("DATABASE_URL not set — skipping DB save")
        return

    try:
        log.info(f"Saving scan {scan_id} to Neon DB...")
        conn = await asyncpg.connect(db_url)
        await conn.execute(
            """
            INSERT INTO scans (scan_id, url, status, overall_severity, score, report, raw_results)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            scan_id,
            url,
            status,
            report.get("overall_severity") if report else None,
            report.get("score") if report else None,
            json.dumps(report),
            json.dumps(raw_results),
        )
        await conn.close()
        log.info(f"Scan {scan_id} saved to DB successfully")
    except Exception as e:
        log.error(f"DB save failed for scan {scan_id}: {e}")