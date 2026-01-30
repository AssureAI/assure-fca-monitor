import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Optional


# -----------------------------
# UTILITIES
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def count_cluster_hits(text: str, clusters: List[List[str]]) -> int:
    """
    Counts how many clusters are satisfied.
    A cluster is satisfied if ANY phrase in that cluster appears in the text.
    """
    hits = 0
    for cluster in clusters or []:
        for phrase in cluster or []:
            if phrase and phrase.lower() in text:
                hits += 1
                break
    return hits


def count_phrase_hits(text: str, phrases: List[str]) -> int:
    phrases = phrases or []
    return sum(1 for p in phrases if p and p.lower() in text)


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> str:
    """
    Returns: "OK", "POTENTIAL_ISSUE", or "NOT_ASSESSED"
    """
    applies_when = rule.get("applies_when", {}) or {}

    # Applicability check (strict by design)
    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return "NOT_ASSESSED"

    evidence = rule.get("evidence", {}) or {}
    decision = rule.get("decision_logic", {}) or {}
    ok_if = decision.get("ok_if", {}) or {}

    text_norm = normalise(text)
    counts: Dict[str, int] = {}

    # Build evidence counts
    for evidence_type, patterns in evidence.items():
        if evidence_type.endswith("_clusters"):
            counts[evidence_type] = count_cluster_hits(text_norm, patterns)
        else:
            counts[evidence_type] = count_phrase_hits(text_norm, patterns)

    # Apply decision conditions
    for key, condition in ok_if.items():
        if key not in counts:
            continue

        value = counts[key]
        condition = str(condition).strip()

        if condition.startswith(">="):
            if value < int(condition[2:]):
                return "POTENTIAL_ISSUE"
        elif condition.startswith("=="):
            if value != int(condition[2:]):
                return "POTENTIAL_ISSUE"
        elif condition.startswith("<="):
            if value > int(condition[2:]):
                return "POTENTIAL_ISSUE"

    return "OK"


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str = "rules/cobs-suitability-v1.yaml"
) -> Dict[str, Any]:

    with open(rules_path, "r", encoding="utf-8") as f:
        ruleset = yaml.safe_load(f)

    # Expect: top-level keys: ruleset, rules
    meta = ruleset.get("ruleset", {})
    rules = ruleset.get("rules", []) or []

    results = []
    for rule in rules:
        status = evaluate_rule(rule, document_text, context)
        results.append({
            "rule_id": rule.get("id", ""),
            "status": status,
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", "")  # ✅ add this
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED")
    }

    return {
        "ruleset_id": meta.get("id", ""),
        "ruleset_version": meta.get("version", ""),
        "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "summary": summary,
        "results": results
    }
