import asyncio
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
import os
import time

from agents.ssl_agent import ssl_agent
from agents.header_agent import header_agent
from agents.malware_agent import malware_agent
from agents.cve_agent import cve_agent
from agents.breach_agent import breach_agent
from logger import get_logger

log = get_logger("orchestrator")

# ── State schema ──────────────────────────────────────────────────────────────

class ScanState(TypedDict):
    url: str
    ssl_result: Optional[dict]
    header_result: Optional[dict]
    malware_result: Optional[dict]
    cve_result: Optional[dict]
    breach_result: Optional[dict]
    report: Optional[dict]

# ── Parallel scan node ────────────────────────────────────────────────────────

async def parallel_scan_node(state: ScanState) -> ScanState:
    url = state["url"]
    log.info(f"Starting parallel scan for: {url}")
    log.info("Launching 5 agents simultaneously...")

    start = time.time()

    results = await asyncio.gather(
        ssl_agent(state),
        header_agent(state),
        malware_agent(state),
        cve_agent(state),
        breach_agent(state),
        return_exceptions=True,
    )

    elapsed = round(time.time() - start, 2)
    log.info(f"All agents completed in {elapsed}s")

    merged = dict(state)
    agent_names = ["ssl", "header", "malware", "cve", "breach"]
    for name, result in zip(agent_names, results):
        if isinstance(result, Exception):
            log.error(f"[{name}_agent] raised exception: {result}")
        elif isinstance(result, dict):
            agent_result = result.get(f"{name}_result", {})
            status = agent_result.get("status", "unknown")
            severity = agent_result.get("severity", "unknown")
            issues_count = len(agent_result.get("issues", []))
            log.info(f"[{name}_agent] status={status} | severity={severity} | issues={issues_count}")
            merged.update(result)

    return merged

# ── Reporter node ─────────────────────────────────────────────────────────────

REPORTER_PROMPT = """
You are a friendly cybersecurity advisor helping a small business owner understand 
their website security. Analyze the scan results below and write a clear, 
non-technical report.

SCAN RESULTS:
{scan_data}

Write your response as valid JSON with this exact structure:
{{
  "overall_severity": "critical|warning|good",
  "summary": "2-3 sentence plain English overview of the security posture",
  "score": <number 0-100>,
  "findings": [
    {{
      "title": "Short issue title",
      "severity": "critical|warning|good",
      "plain_explanation": "What this means for the business owner in simple terms",
      "fix_steps": ["Step 1", "Step 2", "Step 3"]
    }}
  ],
  "top_priority": "The single most important thing to fix right now"
}}

SCORING RUBRIC — you MUST follow this to calculate the score:
- Start at 100
- SSL grade F or expired cert: -40
- SSL grade B/C/D or TLS 1.2: -10
- SSL grade A or A-: -0
- Each MISSING high-severity header (HSTS, CSP): -12 each
- Each MISSING medium-severity header (X-Frame-Options, X-Content-Type-Options): -6 each
- Each MISSING low-severity header: -3 each
- Server info leakage (server header exposed): -5
- Malware detected: -40
- Data breaches found: -15 per breach (max -30)
- Critical CVE found: -20
- High CVE found: -10
- Minimum score is 5 (never return 0 unless every single check failed)
- A site with only missing headers but clean SSL, no malware, no breaches should score 30-55

Rules:
- Use simple language — no technical jargon
- Be specific about fix steps (name the actual header, setting, or service)
- Only include findings with actual issues — do NOT list things that passed
- Limit to max 5 findings
- Return ONLY the JSON object, no markdown fences, no explanation outside JSON
"""

async def reporter_node(state: ScanState) -> ScanState:
    scan_data = {
        "ssl": state.get("ssl_result", {}),
        "headers": state.get("header_result", {}),
        "malware": state.get("malware_result", {}),
        "cve": state.get("cve_result", {}),
        "breaches": state.get("breach_result", {}),
    }

    issues_only = {
        k: v for k, v in scan_data.items()
        if isinstance(v, dict) and v.get("issues")
    }

    if not issues_only:
        log.info("[reporter] No issues found — skipping LLM call")
        return {**state, "report": {
            "overall_severity": "good",
            "summary": "Great news! No significant security issues were found on your website.",
            "score": 95,
            "findings": [],
            "top_priority": "Keep your SSL certificate renewed and monitor regularly.",
        }}

    log.info(f"[reporter] Calling Gemini 2.5 Flash — {len(issues_only)} issue categories: {list(issues_only.keys())}")

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=os.getenv("GEMINI_API_KEY"),
        temperature=0.2,
    )

    prompt = REPORTER_PROMPT.format(scan_data=str(issues_only))
    llm_start = time.time()

    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        llm_elapsed = round(time.time() - llm_start, 2)
        log.info(f"[reporter] Gemini responded in {llm_elapsed}s | response={len(response.content)} chars")

        import json
        text = response.content.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        report = json.loads(text.strip())
        log.info(f"[reporter] severity={report.get('overall_severity')} | score={report.get('score')} | findings={len(report.get('findings', []))}")

    except Exception as e:
        log.error(f"[reporter] Gemini call FAILED: {e}")
        report = {
            "overall_severity": "warning",
            "summary": "Scan completed but report generation encountered an error.",
            "score": 50,
            "findings": [{
                "title": "Report generation failed",
                "severity": "warning",
                "plain_explanation": str(e),
                "fix_steps": ["Please try scanning again"],
            }],
            "top_priority": "Retry the scan.",
        }

    return {**state, "report": report}

# ── Build graph ───────────────────────────────────────────────────────────────

def build_scan_graph():
    graph = StateGraph(ScanState)
    graph.add_node("scan", parallel_scan_node)
    graph.add_node("reporter", reporter_node)
    graph.set_entry_point("scan")
    graph.add_edge("scan", "reporter")
    graph.add_edge("reporter", END)
    return graph.compile()

scan_graph = build_scan_graph()