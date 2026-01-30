import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

# -----------------------------
# UTILITIES
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()

def extract_snippet(text: str, phrase: str, window: int = 80) -> Optional[str]:
    idx = text.lower().find(phrase.lower())
    if idx == -1:
        return None
    start = max(0, idx - window)
    end = min(len(text), idx + len(phrase) + window)
    return text[start:end].strip()

def count_cluster_hits(text: str, clusters: List[List[str]]) -> Dict[str, Any]:
    """
    Returns:
      {
        hits: int,
        matched_phrases: [str],
        snippets: [str]
      }
    """
    hits = 0
    matched = []
    snippets = []

    for cluster in clusters:
        for phrase in cluster:
            if phrase.lower() in text:
                hits += 1
                matched.append(phrase)
                snippet = extract_snippet(text, phrase)
                if snippet:
                    snippets.append(snippet)
                break

    return {
        "hits": hits,
        "matched_phrases": matched,
        "snippets": snippets
    }

def count_phrase_hits(text: str, phrases: List[str]) -> int:
    return sum(1 for p in phrases if isinstance(p, str) and p.lower() in text)

# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})

    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return {
                "status": "NOT_ASSESSED",
                "evidence": {}
            }

    text_norm = normalise(text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {}).get("ok_if", [])

    counts = {}
    evidence_out = {}

    for ev_type, clusters in evidence.items():
        if ev_type.endswith("_clusters"):
            result = count_cluster_hits(text_norm, clusters)
            counts[ev_type] = result["hits"]
            evidence_out[ev_type] = result
        else:
            counts[ev_type] = count_phrase_hits(text_norm, clusters)

    for condition in decision:
        if condition.startswith(">="):
            needed, key = condition[2:].split(" ", 1)
            if counts.get(key.strip(), 0) < int(needed):
                return {
                    "status": "POTENTIAL_ISSUE",
                    "evidence": evidence_out
                }

    return {
        "status": "OK",
        "evidence": evidence_out
    }

# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    results = []

    for rule in ruleset["rules"]:
        outcome = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule["id"],
            "section": rule.get("section"),
            "status": outcome["status"],
            "citation": rule["citation"],
            "source_url": rule.get("source_url"),
            "evidence": outcome.get("evidence", {})
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results
    }
