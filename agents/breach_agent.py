import httpx
import time
from logger import get_logger

log = get_logger("breach_agent")

async def breach_agent(state: dict) -> dict:
    url = state["url"]
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    log.info(f"Checking HaveIBeenPwned for domain: {domain}")

    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                params={"domain": domain},
                headers={"User-Agent": "CyberShield-SMB-Scanner"},
            )
            elapsed = round(time.time() - start, 2)
            log.info(f"HIBP response: HTTP {response.status_code} in {elapsed}s")

            if response.status_code == 404:
                log.info(f"HIBP: No breaches found for {domain}")
                return {**state, "breach_result": {
                    "status": "ok",
                    "breach_count": 0,
                    "breaches": [],
                    "issues": [],
                    "severity": "good",
                }}

            if response.status_code == 401:
                log.warning("HIBP: API key required for this domain lookup")
                return {**state, "breach_result": {
                    "status": "skipped",
                    "issues": ["Breach check requires HIBP API key for this domain"],
                    "severity": "unknown",
                }}

            breaches = response.json() if response.status_code == 200 else []
            if not isinstance(breaches, list):
                breaches = []

            log.info(f"HIBP: Found {len(breaches)} breach(es) for {domain}")

            issues = []
            severity = "good"

            if breaches:
                severity = "critical" if len(breaches) >= 3 else "warning"
                breach_names = [b.get("Name", "Unknown") for b in breaches[:3]]
                log.warning(f"Breaches found: {breach_names}")
                total = len(breaches)
                issues.append(
                    f"Domain found in {total} known data breach{'es' if total > 1 else ''}: "
                    f"{', '.join(breach_names)}"
                    + (" and more" if total > 3 else "")
                )
                for breach in breaches[:3]:
                    if breach.get("PwnCount", 0) > 1_000_000:
                        issues.append(
                            f"{breach['Name']} exposed {breach['PwnCount']:,} accounts"
                        )

            return {**state, "breach_result": {
                "status": "ok",
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": b.get("DataClasses", [])[:4],
                    }
                    for b in breaches[:5]
                ],
                "issues": issues,
                "severity": severity,
            }}

    except Exception as e:
        log.error(f"Breach scan failed: {e}")
        return {**state, "breach_result": {
            "status": "error",
            "issues": [f"Breach scan failed: {str(e)}"],
            "severity": "unknown",
        }}