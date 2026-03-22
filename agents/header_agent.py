import httpx
import time
from logger import get_logger

log = get_logger("header_agent")

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "Forces browsers to use HTTPS — missing means users can be redirected to HTTP",
        "severity": "high",
    },
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "description": "Prevents XSS attacks by restricting what scripts can run on your page",
        "severity": "high",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents your site from being embedded in iframes — stops clickjacking attacks",
        "severity": "medium",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Stops browsers from guessing file types — prevents MIME sniffing attacks",
        "severity": "medium",
    },
    "referrer-policy": {
        "name": "Referrer Policy",
        "description": "Controls how much URL info is shared when users click links from your site",
        "severity": "low",
    },
    "permissions-policy": {
        "name": "Permissions Policy",
        "description": "Controls which browser features (camera, mic, location) your site can access",
        "severity": "low",
    },
}

async def header_agent(state: dict) -> dict:
    url = state["url"]
    if not url.startswith("http"):
        url = "https://" + url

    log.info(f"Scanning HTTP security headers for: {url}")
    start = time.time()

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (CyberShield Security Scanner)"}
        ) as client:
            response = await client.get(url)
            elapsed = round(time.time() - start, 2)
            log.info(f"HTTP {response.status_code} received in {elapsed}s")
            headers = {k.lower(): v for k, v in response.headers.items()}

        missing = []
        present = []
        issues = []

        for header_key, meta in SECURITY_HEADERS.items():
            if header_key not in headers:
                missing.append({
                    "header": meta["name"],
                    "severity": meta["severity"],
                    "description": meta["description"],
                })
                if meta["severity"] == "high":
                    issues.append(f"Missing {meta['name']}: {meta['description']}")
            else:
                present.append(meta["name"])

        leaking = []
        for leak_header in ["server", "x-powered-by", "x-aspnet-version"]:
            if leak_header in headers:
                leaking.append(f"'{leak_header}: {headers[leak_header]}' reveals your server technology to attackers")

        log.info(f"Headers present={len(present)}/{len(SECURITY_HEADERS)} | missing={len(missing)} | leaking={len(leaking)}")

        if missing:
            log.warning(f"Missing headers: {[m['header'] for m in missing]}")
        if leaking:
            log.warning(f"Info leakage detected: {leaking}")

        severity = "good"
        if any(m["severity"] == "high" for m in missing):
            severity = "warning"
        if len(missing) >= 4:
            severity = "critical"

        log.info(f"Header scan complete — score={len(present)}/{len(SECURITY_HEADERS)} | severity={severity}")

        return {**state, "header_result": {
            "status": "ok",
            "missing_headers": missing,
            "present_headers": present,
            "info_leakage": leaking,
            "issues": issues + leaking,
            "severity": severity,
            "score": f"{len(present)}/{len(SECURITY_HEADERS)}",
        }}

    except Exception as e:
        log.error(f"Header scan failed: {e}")
        return {**state, "header_result": {
            "status": "error",
            "issues": [f"Header scan failed: {str(e)}"],
            "severity": "unknown",
        }}