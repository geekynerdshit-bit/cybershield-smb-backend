import ssl
import socket
import time
import datetime
from logger import get_logger

log = get_logger("ssl_agent")


def get_ssl_grade(protocol: str, cert: dict, cipher_name: str) -> tuple[str, list[str]]:
    """
    Derives a simple grade from protocol version + cert validity + cipher.
    Returns (grade, issues_list)
    """
    issues = []
    score = 100

    # Protocol scoring
    if protocol == "TLSv1.3":
        pass  # best possible
    elif protocol == "TLSv1.2":
        issues.append("Using TLS 1.2 — consider upgrading to TLS 1.3 for best security")
        score -= 10
    elif protocol in ("TLSv1.1", "TLSv1"):
        issues.append(f"Outdated protocol {protocol} in use — TLS 1.0/1.1 are deprecated and insecure")
        score -= 40
    else:
        issues.append(f"Unknown or very old protocol detected: {protocol}")
        score -= 60

    # Certificate expiry check
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            if days_left < 0:
                issues.append("SSL certificate has EXPIRED — browsers will show a security warning to all visitors")
                score -= 50
            elif days_left < 14:
                issues.append(f"SSL certificate expires in {days_left} days — renew immediately")
                score -= 30
            elif days_left < 30:
                issues.append(f"SSL certificate expires in {days_left} days — renew soon")
                score -= 10
            else:
                log.info(f"Certificate valid for {days_left} more days (expires {expiry.strftime('%Y-%m-%d')})")
        except Exception:
            pass

    # Weak cipher detection
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
    if any(w in cipher_name.upper() for w in weak_ciphers):
        issues.append(f"Weak cipher suite in use: {cipher_name} — vulnerable to decryption attacks")
        score -= 30

    # Grade mapping
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "A-"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return grade, issues


async def ssl_agent(state: dict) -> dict:
    url = state["url"]
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    log.info(f"Starting direct TLS check for: {domain}")

    start = time.time()
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((domain, 443), timeout=10)
        tls = ctx.wrap_socket(sock, server_hostname=domain)

        cert = tls.getpeercert()
        cipher = tls.cipher()       # (name, protocol, bits)
        protocol = tls.version()    # e.g. "TLSv1.3"
        cipher_name = cipher[0] if cipher else "Unknown"

        tls.close()
        sock.close()

        elapsed = round(time.time() - start, 2)
        log.info(f"TLS handshake done in {elapsed}s — protocol={protocol} | cipher={cipher_name}")

        grade, issues = get_ssl_grade(protocol, cert, cipher_name)
        severity = "critical" if grade == "F" else "warning" if grade in ("B", "C", "D", "A-") else "good"

        log.info(f"SSL result — grade={grade} | severity={severity} | issues={len(issues)}")
        if issues:
            log.warning(f"SSL issues: {issues}")

        return {**state, "ssl_result": {
            "status": "ok",
            "grade": grade,
            "protocol": protocol,
            "cipher": cipher_name,
            "domain": domain,
            "issues": issues,
            "severity": severity,
        }}

    except ssl.SSLCertVerificationError as e:
        elapsed = round(time.time() - start, 2)
        log.error(f"Certificate verification FAILED in {elapsed}s: {e}")
        return {**state, "ssl_result": {
            "status": "ok",
            "grade": "F",
            "domain": domain,
            "issues": ["SSL certificate is invalid or untrusted — browsers will show a security warning to all visitors"],
            "severity": "critical",
        }}

    except ssl.SSLError as e:
        elapsed = round(time.time() - start, 2)
        log.error(f"SSL error in {elapsed}s: {e}")
        return {**state, "ssl_result": {
            "status": "ok",
            "grade": "F",
            "domain": domain,
            "issues": [f"SSL connection failed — site may not support HTTPS properly: {str(e)}"],
            "severity": "critical",
        }}

    except ConnectionRefusedError:
        log.error(f"Port 443 refused on {domain} — HTTPS not enabled")
        return {**state, "ssl_result": {
            "status": "ok",
            "grade": "F",
            "domain": domain,
            "issues": ["HTTPS is not enabled — all visitor traffic is unencrypted"],
            "severity": "critical",
        }}

    except Exception as e:
        elapsed = round(time.time() - start, 2)
        log.error(f"SSL scan failed in {elapsed}s: {e}")
        return {**state, "ssl_result": {
            "status": "error",
            "grade": "Unknown",
            "domain": domain,
            "issues": [f"SSL scan could not complete: {str(e)}"],
            "severity": "unknown",
        }}