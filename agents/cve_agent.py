import httpx
import time
from logger import get_logger

log = get_logger("cve_agent")

TECH_SIGNATURES = {
    "wordpress": ["wp-content", "wp-includes", "WordPress"],
    "joomla": ["Joomla!", "/components/com_"],
    "drupal": ["Drupal.settings", "/sites/default/files/"],
    "woocommerce": ["woocommerce", "wc-api"],
    "magento": ["Mage.Cookies", "magento"],
    "shopify": ["cdn.shopify.com", "Shopify.theme"],
    "laravel": ["laravel_session", "X-Powered-By: PHP"],
}

async def detect_technologies(url: str) -> list[str]:
    if not url.startswith("http"):
        url = "https://" + url
    detected = []
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            r = await client.get(url)
            body = r.text.lower()
            headers_str = str(r.headers).lower()
            combined = body + headers_str
            for tech, sigs in TECH_SIGNATURES.items():
                if any(s.lower() in combined for s in sigs):
                    detected.append(tech)
    except Exception as e:
        log.warning(f"Tech detection failed: {e}")
    return detected

async def lookup_cves(tech: str) -> list[dict]:
    log.info(f"Querying NIST NVD for CVEs related to: {tech}")
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": tech, "resultsPerPage": 3, "noRejected": ""},
                headers={"User-Agent": "CyberShield-Scanner/1.0"},
            )
            elapsed = round(time.time() - start, 2)
            data = r.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "Unknown")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
                metrics = cve.get("metrics", {})
                score = None
                for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_key in metrics:
                        score = metrics[metric_key][0]["cvssData"].get("baseScore")
                        break
                cves.append({"id": cve_id, "description": desc[:200], "score": score})
            log.info(f"NVD returned {len(cves)} CVEs for '{tech}' in {elapsed}s")
            return cves
    except Exception as e:
        log.error(f"NVD CVE lookup failed for {tech}: {e}")
        return []

async def cve_agent(state: dict) -> dict:
    url = state["url"]
    log.info(f"Starting CVE scan for: {url}")

    try:
        log.info("Fingerprinting technologies from page source...")
        techs = await detect_technologies(url)

        if techs:
            log.info(f"Detected technologies: {techs}")
        else:
            log.info("No known CMS/tech stack detected")

        all_cves = []
        for tech in techs:
            cves = await lookup_cves(tech)
            for cve in cves:
                cve["tech"] = tech
                all_cves.append(cve)

        issues = []
        severity = "good"

        critical_cves = [c for c in all_cves if c.get("score") and c["score"] >= 9.0]
        high_cves = [c for c in all_cves if c.get("score") and 7.0 <= c["score"] < 9.0]

        if critical_cves:
            severity = "critical"
            log.warning(f"CRITICAL CVEs found: {[c['id'] for c in critical_cves]}")
            for cve in critical_cves[:2]:
                issues.append(
                    f"CRITICAL CVE {cve['id']} in {cve['tech'].title()} "
                    f"(score: {cve['score']}) — {cve['description'][:120]}"
                )
        elif high_cves:
            severity = "warning"
            log.warning(f"High CVEs found: {[c['id'] for c in high_cves]}")
            for cve in high_cves[:2]:
                issues.append(
                    f"High severity CVE {cve['id']} in {cve['tech'].title()} (score: {cve['score']})"
                )
        else:
            log.info(f"CVE scan clean — {len(all_cves)} CVEs found, none critical/high")

        log.info(f"CVE scan complete — techs={techs} | total_cves={len(all_cves)} | severity={severity}")

        return {**state, "cve_result": {
            "status": "ok",
            "detected_technologies": techs,
            "cves_found": all_cves[:5],
            "issues": issues,
            "severity": severity,
        }}

    except Exception as e:
        log.error(f"CVE scan failed: {e}")
        return {**state, "cve_result": {
            "status": "error",
            "issues": [f"CVE scan failed: {str(e)}"],
            "severity": "unknown",
        }}