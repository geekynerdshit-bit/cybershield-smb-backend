from fastapi import APIRouter, HTTPException
from models.scan import ScanRequest, ScanResponse
from agents.orchestrator import scan_graph
from db.client import save_scan
from logger import get_logger
from datetime import datetime
import uuid
import time

router = APIRouter(prefix="/api", tags=["scan"])
log = get_logger("route")


@router.get("/health")
async def health():
    return {"status": "ok", "service": "CyberShield SMB API"}


@router.post("/scan", response_model=ScanResponse)
async def run_scan(body: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    log.info(f"═══ New scan request [{scan_id}] — URL: {body.url} ═══")
    start = time.time()

    try:
        result = await scan_graph.ainvoke({"url": body.url})

        elapsed = round(time.time() - start, 2)
        report = result.get("report")
        raw_results = {
            "ssl": result.get("ssl_result"),
            "headers": result.get("header_result"),
            "malware": result.get("malware_result"),
            "cve": result.get("cve_result"),
            "breaches": result.get("breach_result"),
        }

        log.info(f"═══ Scan [{scan_id}] complete in {elapsed}s — severity={report.get('overall_severity')} | score={report.get('score')} ═══")

        # Save to Neon DB (non-blocking — won't fail the request if DB is down)
        await save_scan(
            scan_id=scan_id,
            url=body.url,
            status="completed",
            report=report,
            raw_results=raw_results,
        )

        return ScanResponse(
            scan_id=scan_id,
            url=body.url,
            status="completed",
            report=report,
            raw_results=raw_results,
            scanned_at=datetime.utcnow(),
        )

    except Exception as e:
        log.error(f"Scan [{scan_id}] FAILED: {e}")
        raise HTTPException(status_code=500, detail=str(e))