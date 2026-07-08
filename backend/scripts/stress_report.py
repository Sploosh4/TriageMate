#!/usr/bin/env python3
"""
Stress test report generator for TriageMate.

Usage:
    python scripts/stress_report.py <path_to_db>

Produces a terminal report and writes a Markdown file at
backend/reports/stress/{run_id}.md
"""

import json
import math
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime


def _fmt(s: str) -> str:
    """Format a section header."""
    return s


def _pct(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{100.0 * part / total:.1f}%"


def _load_results(db_path: str) -> dict:
    """Load test run and results from the stress DB."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    run = conn.execute("SELECT * FROM test_runs").fetchone()
    if not run:
        print(f"ERROR: No test run found in {db_path}")
        sys.exit(1)
    results = conn.execute("SELECT * FROM results ORDER BY seq").fetchall()
    conn.close()
    return {"run": run, "results": results}


def _parse_trace(trace_str: str) -> dict:
    """Safely parse trace JSON string."""
    try:
        return json.loads(trace_str) if trace_str else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _compute_percentiles(values: list[float], percentiles: list[int]) -> dict:
    """Compute selected percentiles from a list of values."""
    if not values:
        return {p: 0.0 for p in percentiles}
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    result = {}
    for p in percentiles:
        idx = max(0, min(n - 1, int(math.ceil(p / 100.0 * n) - 1)))
        result[p] = round(sorted_vals[idx], 2)
    return result


def generate_report(db_path: str) -> str:
    """Generate the report and return the output file path."""
    data = _load_results(db_path)
    run = data["run"]
    results = data["results"]
    run_id = run["id"]

    # ── Summary stats ────────────────────────────────────────────────────
    total = run["total_requests"] or len(results)
    successful = run["successful"] or sum(
        1 for r in results if r["status"] == "success"
    )
    failed = run["failed"] or sum(1 for r in results if r["status"] != "success")
    error_rate = (failed / total * 100) if total > 0 else 0.0

    started = run["started_at"]
    ended = run["ended_at"] or ""
    duration_str = ""
    dur = 0.0
    if started and ended:
        try:
            t_start = datetime.fromisoformat(started)
            t_end = datetime.fromisoformat(ended)
            dur = (t_end - t_start).total_seconds()
            duration_str = f"{dur:.0f}s"
        except (ValueError, TypeError):
            duration_str = "N/A"

    throughput = total / dur if (dur and dur > 0) else 0.0

    # ── Tier routing ─────────────────────────────────────────────────────
    t0_auto = sum(
        1
        for r in results
        if _parse_trace(r["trace"]).get("tier_0", {}).get("routing") == "auto_resolved"
    )
    t0_esc = sum(
        1
        for r in results
        if _parse_trace(r["trace"]).get("tier_0", {}).get("routing") == "escalated"
    )
    t1_auto = sum(
        1
        for r in results
        if _parse_trace(r["trace"]).get("tier_1")
        and _parse_trace(r["trace"])["tier_1"].get("routing") == "auto_resolved"
    )
    t1_esc = sum(
        1
        for r in results
        if _parse_trace(r["trace"]).get("tier_1")
        and _parse_trace(r["trace"])["tier_1"].get("routing") == "escalated"
    )
    t2_called = sum(1 for r in results if r["tier_2_called"])
    t2_skipped = total - t2_called

    # Tier 3 flagged (extract from trace tier_2 rag_result)
    tier3_flagged = 0
    for r in results:
        trace = _parse_trace(r["trace"])
        t2 = trace.get("tier_2", {})
        if isinstance(t2, dict) and t2.get("rag_result") in ("UNCERTAIN",):
            tier3_flagged += 1

    # ── Accuracy (KEV recall) ────────────────────────────────────────────
    # Load the KEV cache to cross-reference
    _data_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"
    )
    kev_path = os.path.join(_data_dir, "kev_cache.json")
    kev_set = set()
    if os.path.exists(kev_path):
        with open(kev_path) as f:
            kev_data = json.load(f)
        kev_set = set(kev_data.keys())

    kev_in_test = [r for r in results if r["cve_id"] in kev_set]
    kev_auto_resolved = sum(
        1
        for r in kev_in_test
        if _parse_trace(r["trace"]).get("tier_0", {}).get("routing") == "auto_resolved"
    )
    kev_recall = (kev_auto_resolved / len(kev_in_test) * 100) if kev_in_test else 0.0

    # Low-severity precision: % of Tier 0 auto-resolved that were actually low severity
    # (Approximated by checking trace tier_0 routing reason — not yet fully populated)
    pass

    # Score separation
    kev_scores = [
        r["priority_score"]
        for r in results
        if r["cve_id"] in kev_set and r["priority_score"] is not None
    ]
    non_kev_scores = [
        r["priority_score"]
        for r in results
        if r["cve_id"] not in kev_set and r["priority_score"] is not None
    ]
    mean_kev = sum(kev_scores) / len(kev_scores) if kev_scores else 0
    mean_non_kev = sum(non_kev_scores) / len(non_kev_scores) if non_kev_scores else 0

    # ── Latency ──────────────────────────────────────────────────────────
    latencies = [
        r["total_latency_ms"] for r in results if r["total_latency_ms"] is not None
    ]
    latency_pct = _compute_percentiles(latencies, [50, 95, 99])

    # Per-tier latencies
    pre_tier_lats = []
    tier_0_lats = []
    tier_1_lats = []
    tier_2_lats = []
    for r in results:
        trace = _parse_trace(r["trace"])
        if "pre_tier" in trace:
            pre_tier_lats.append(trace["pre_tier"].get("latency_ms", 0))
        if "tier_0" in trace:
            tier_0_lats.append(trace["tier_0"].get("latency_ms", 0))
        t1 = trace.get("tier_1")
        if t1:
            tier_1_lats.append(t1.get("latency_ms", 0))
        t2 = trace.get("tier_2")
        if isinstance(t2, dict) and t2.get("called"):
            tier_2_lats.append(t2.get("latency_ms", 0))

    # ── LLM Cost ─────────────────────────────────────────────────────────
    total_llm_calls = t2_called
    total_tokens_in = 0
    total_tokens_out = 0
    total_cost = 0.0
    for r in results:
        trace = _parse_trace(r["trace"])
        t2 = trace.get("tier_2")
        if isinstance(t2, dict) and t2.get("called"):
            total_tokens_in += t2.get("tokens_in", 0)
            total_tokens_out += t2.get("tokens_out", 0)
            total_cost += t2.get("cost_usd", 0.0)
    avg_cost = total_cost / total_llm_calls if total_llm_calls > 0 else 0.0

    # ── Risk Distribution ────────────────────────────────────────────────
    band_counts = Counter(r["risk_band"] for r in results if r["risk_band"])
    score_histogram = {
        "0-25": sum(
            1
            for r in results
            if r["priority_score"] is not None and 0 <= r["priority_score"] <= 25
        ),
        "26-50": sum(
            1
            for r in results
            if r["priority_score"] is not None and 26 <= r["priority_score"] <= 50
        ),
        "51-75": sum(
            1
            for r in results
            if r["priority_score"] is not None and 51 <= r["priority_score"] <= 75
        ),
        "76-100": sum(
            1
            for r in results
            if r["priority_score"] is not None and 76 <= r["priority_score"] <= 100
        ),
    }

    # ── Failures ─────────────────────────────────────────────────────────
    failures = [r for r in results if r["status"] != "success"]
    error_count = len(failures)
    error_rate_pct = (error_count / total * 100) if total > 0 else 0.0
    top_cve_fails = Counter(r["cve_id"] for r in failures).most_common(5)
    top_host_fails = Counter(r["hostname"] for r in failures).most_common(5)

    # ── Build Report ─────────────────────────────────────────────────────
    lines = []
    lines.append("╔══════════════════════════════════════════════════╗")
    lines.append("║     TriageMate Stress Test Report               ║")
    lines.append(f"║     Run: {run_id:<39}║")
    lines.append("╠══════════════════════════════════════════════════╣")

    # 1. Summary
    lines.append("║ SUMMARY                                          ║")
    lines.append(
        f"║   Duration: {duration_str:<12}  Requests: {total:<6}  Throughput: {throughput:.1f}/s   ║"
    )
    lines.append(
        f"║   Successful: {successful} ({_pct(successful, total)})  Failed: {failed} ({_pct(failed, total)})  ║"
    )
    lines.append("╠══════════════════════════════════════════════════╣")

    # 2. Tier Routing
    lines.append("║ TIER ROUTING                                     ║")
    lines.append(
        f"║   Tier 0 auto-resolved:  {t0_auto:<5} ({_pct(t0_auto, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 0 escalated:      {t0_esc:<5} ({_pct(t0_esc, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 1 auto-resolved:  {t1_auto:<5} ({_pct(t1_auto, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 1 escalated:      {t1_esc:<5} ({_pct(t1_esc, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 2 called:         {t2_called:<5} ({_pct(t2_called, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 2 skipped:        {t2_skipped:<5} ({_pct(t2_skipped, total):>6})                        ║"
    )
    lines.append(
        f"║   Tier 3 flagged:        {tier3_flagged:<5} ({_pct(tier3_flagged, total):>6})                        ║"
    )
    lines.append("╠══════════════════════════════════════════════════╣")

    # 3. Accuracy
    lines.append("║ ACCURACY                                         ║")
    lines.append(
        f"║   KEV recall:               {kev_recall:.1f}%                               ║"
    )
    lines.append(
        f"║   KEV in test:              {len(kev_in_test)}                                     ║"
    )
    lines.append(
        f"║   KEV auto-resolved:        {kev_auto_resolved}                                     ║"
    )
    lines.append(
        f"║   Mean score (KEV):         {mean_kev:.1f}                                   ║"
    )
    lines.append(
        f"║   Mean score (non-KEV):     {mean_non_kev:.1f}                                   ║"
    )
    lines.append(
        f"║   Score separation:         {mean_kev - mean_non_kev:.1f} pts                              ║"
    )
    lines.append("╠══════════════════════════════════════════════════╣")

    # 4. Latency
    lines.append("║ LATENCY (ms)                                     ║")
    lines.append("║   Total ingest:                                  ║")
    lines.append(
        f"║     p50: {latency_pct.get(50, 0):>8.2f}  p95: {latency_pct.get(95, 0):>8.2f}  p99: {latency_pct.get(99, 0):>8.2f}                  ║"
    )
    pct_pre = _compute_percentiles(pre_tier_lats, [50, 95, 99])
    pct_t0 = _compute_percentiles(tier_0_lats, [50, 95, 99])
    pct_t1 = _compute_percentiles(tier_1_lats, [50, 95, 99])
    pct_t2 = _compute_percentiles(tier_2_lats, [50, 95, 99])
    lines.append(
        f"║   Pre-Tier p50:  {pct_pre.get(50, 0):>8.2f}  p95: {pct_pre.get(95, 0):>8.2f}                   ║"
    )
    lines.append(
        f"║   Tier 0  p50:  {pct_t0.get(50, 0):>8.2f}  p95: {pct_t0.get(95, 0):>8.2f}                   ║"
    )
    lines.append(
        f"║   Tier 1  p50:  {pct_t1.get(50, 0):>8.2f}  p95: {pct_t1.get(95, 0):>8.2f}                   ║"
    )
    lines.append(
        f"║   Tier 2  p50:  {pct_t2.get(50, 0):>8.2f}  p95: {pct_t2.get(95, 0):>8.2f}                   ║"
    )
    lines.append("╠══════════════════════════════════════════════════╣")

    # 5. LLM Cost
    lines.append("║ LLM COST                                         ║")
    lines.append(
        f"║   Total calls:           {total_llm_calls:<6}                              ║"
    )
    lines.append(
        f"║   Total tokens in:       {total_tokens_in:<8}                          ║"
    )
    lines.append(
        f"║   Total tokens out:      {total_tokens_out:<8}                          ║"
    )
    lines.append(
        f"║   Total cost:            ${total_cost:<8.6f}                      ║"
    )
    lines.append(f"║   Avg cost per call:     ${avg_cost:<8.6f}                      ║")
    lines.append("╠══════════════════════════════════════════════════╣")

    # 6. Risk Distribution
    lines.append("║ RISK DISTRIBUTION                                ║")
    for band in ["Very Critical", "Critical", "Medium", "Low"]:
        count = band_counts.get(band, 0)
        pct = _pct(count, total)
        lines.append(f"║   {band:<19} {count:<5} ({pct:>6})                    ║")
    lines.append("║   Score histogram:                                ║")
    for bucket, count in sorted(score_histogram.items()):
        pct = _pct(count, total)
        bar_len = max(1, int(count / max(total, 1) * 20))
        bar = "█" * bar_len
        lines.append(f"║     {bucket:<8} {count:<5} ({pct:>6}) {bar:<20} ║")
    lines.append("╠══════════════════════════════════════════════════╣")

    # 7. Failures
    lines.append("║ FAILURES                                         ║")
    lines.append(
        f"║   Error count:    {error_count:<6}                                      ║"
    )
    lines.append(
        f"║   Error rate:     {error_rate_pct:.1f}%                                    ║"
    )
    lines.append("║   Top 5 CVEs by failure:                        ║")
    for cve, cnt in top_cve_fails:
        lines.append(f"║     {cve:<20} {cnt}                                      ║")
    if not top_cve_fails:
        lines.append("║     (none)                                          ║")
    lines.append("║   Top 5 hostnames by failure:                    ║")
    for host, cnt in top_host_fails:
        lines.append(f"║     {host:<30} {cnt}                               ║")
    if not top_host_fails:
        lines.append("║     (none)                                          ║")
    lines.append("╚══════════════════════════════════════════════════╝")

    report_text = "\n".join(lines)
    print(report_text)

    # ── Write Markdown file ─────────────────────────────────────────────
    md_lines = [
        f"# TriageMate Stress Test Report — `{run_id}`",
        "",
        f"**Generated:** {datetime.now().isoformat()}",
        "",
        "## 1. Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Duration | {duration_str} |",
        f"| Total Requests | {total} |",
        f"| Successful | {successful} ({_pct(successful, total)}) |",
        f"| Failed | {failed} ({_pct(failed, total)}) |",
        f"| Error Rate | {error_rate:.1f}% |",
        f"| Throughput | {throughput:.1f} req/s |",
        "",
        "## 2. Tier Routing",
        "",
        "| Decision | Count | % |",
        "|----------|-------|---|",
        f"| Tier 0 auto-resolved | {t0_auto} | {_pct(t0_auto, total)} |",
        f"| Tier 0 escalated | {t0_esc} | {_pct(t0_esc, total)} |",
        f"| Tier 1 auto-resolved | {t1_auto} | {_pct(t1_auto, total)} |",
        f"| Tier 1 escalated | {t1_esc} | {_pct(t1_esc, total)} |",
        f"| Tier 2 called | {t2_called} | {_pct(t2_called, total)} |",
        f"| Tier 2 skipped | {t2_skipped} | {_pct(t2_skipped, total)} |",
        f"| Tier 3 flagged | {tier3_flagged} | {_pct(tier3_flagged, total)} |",
        "",
        "## 3. Accuracy",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| KEV recall | {kev_recall:.1f}% |",
        f"| KEV in test set | {len(kev_in_test)} |",
        f"| KEV auto-resolved at Tier 0 | {kev_auto_resolved} |",
        f"| Mean score (KEV) | {mean_kev:.1f} |",
        f"| Mean score (non-KEV) | {mean_non_kev:.1f} |",
        f"| Score separation | {mean_kev - mean_non_kev:.1f} pts |",
        "",
        "## 4. Latency (ms)",
        "",
        "| Metric | p50 | p95 | p99 |",
        "|--------|-----|-----|-----|",
        f"| Total ingest | {latency_pct.get(50, 0)} | {latency_pct.get(95, 0)} | {latency_pct.get(99, 0)} |",
        f"| Pre-Tier | {pct_pre.get(50, 0)} | {pct_pre.get(95, 0)} | {pct_pre.get(99, 0)} |",
        f"| Tier 0 | {pct_t0.get(50, 0)} | {pct_t0.get(95, 0)} | {pct_t0.get(99, 0)} |",
        f"| Tier 1 | {pct_t1.get(50, 0)} | {pct_t1.get(95, 0)} | {pct_t1.get(99, 0)} |",
        f"| Tier 2 | {pct_t2.get(50, 0)} | {pct_t2.get(95, 0)} | {pct_t2.get(99, 0)} |",
        "",
        "## 5. LLM Cost",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total calls | {total_llm_calls} |",
        f"| Total tokens in | {total_tokens_in} |",
        f"| Total tokens out | {total_tokens_out} |",
        f"| Total cost (USD) | ${total_cost:.6f} |",
        f"| Avg cost/call (USD) | ${avg_cost:.6f} |",
        "",
        "## 6. Risk Distribution",
        "",
        "| Band | Count | % |",
        "|------|-------|---|",
    ]
    for band in ["Very Critical", "Critical", "Medium", "Low"]:
        count = band_counts.get(band, 0)
        md_lines.append(f"| {band} | {count} | {_pct(count, total)} |")
    md_lines.extend(
        [
            "",
            "### Score Histogram",
            "",
            "| Bucket | Count | % |",
            "|--------|-------|---|",
        ]
    )
    for bucket, count in sorted(score_histogram.items()):
        md_lines.append(f"| {bucket} | {count} | {_pct(count, total)} |")
    md_lines.extend(
        [
            "",
            "## 7. Failures",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Error count | {error_count} |",
            f"| Error rate | {error_rate_pct:.1f}% |",
            "",
        ]
    )
    if top_cve_fails:
        md_lines.extend(["Top 5 CVEs by failure count:", ""])
        for cve, cnt in top_cve_fails:
            md_lines.append(f"- {cve}: {cnt} failures")
    if top_host_fails:
        md_lines.extend(["", "Top 5 hostnames by failure count:", ""])
        for host, cnt in top_host_fails:
            md_lines.append(f"- {host}: {cnt} failures")

    # Write markdown
    reports_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports",
        "stress",
    )
    os.makedirs(reports_dir, exist_ok=True)
    md_path = os.path.join(reports_dir, f"{run_id}.md")
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines) + "\n")
    print(f"\nReport written to: {md_path}")
    return md_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/stress_report.py <path_to_db>")
        sys.exit(1)
    db_path = sys.argv[1]
    if not os.path.isfile(db_path):
        print(f"ERROR: File not found: {db_path}")
        sys.exit(1)
    generate_report(db_path)


if __name__ == "__main__":
    main()
