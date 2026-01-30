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


def evaluate_clusters(text: str, clusters: List[List[str]]) -> Dict[str, Any]:
    hits = 0
    matched_phrases = []
    snippets = []

    for cluster in clusters:
        if not isinstance(cluster, list):
            continue

        for phrase in cluster:
            if not isinstance(phrase, str):
                continue

            if phrase.lower() in text:
                hits += 1
                matched_phrases.append(phrase)
                snippet = extract_snippet(text, phrase)
                if snippet:
                    snippets.append(snippet)
                break

    return {
        "hits": hits,
        "matched_phrases": matched_phrases,
        "snippets": snippets,
    }


def evaluate_flat_phrases(text: str, phrases: List[str]) -> int:
    count = 0
    for phrase in phrases:
        if isinstance(phrase, str) and phrase.lower() in text:
            count += 1
    return count


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})

    # Applicability gate
    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return {
                "status": "NOT_ASSESSED",
                "evidence": {},
            }

    text_norm = normalise(text)
    evidence = rule.get("evidence", {})
    decision_logic = rule.get("decision_logic", {}).get("ok_if", [])

    counts: Dict[str, int] = {}
    evidence_out: Dict[str, Any] = {}

    for ev_key, ev_value in evidence.items():
        if isinstance(ev_value, list) and ev_value and isinstance(ev_value[0], list):
            result = evaluate_clusters(text_norm, ev_value)
            counts[ev_key] = result["hits"]
            evidence_out[ev_key] = result
        elif isinstance(ev_value, list):
            counts[ev_key] = evaluate_flat_phrases(text_norm, ev_value)
        else:
            counts[ev_key] = 0

    for rule_condition in decision_logic:
        rule_condition = rule_condition.strip()

        if rule_condition.startswith(">="):
            parts = rule_condition.replace(">=", "").split()
            needed = int(parts[0])
            key = parts[1]

            if counts.get(key, 0) < needed:
                return {
                    "status": "POTENTIAL_ISSUE",
                    "evidence": evidence_out,
                }

    return {
        "status": "OK",
        "evidence": evidence_out,
    }


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str,
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    results = []

    for rule in ruleset["rules"]:
        evaluation = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule["id"],
            "section": rule.get("section"),
            "status": evaluation["status"],
            "citation": rule["citation"],
            "source_url": rule.get("source_url"),
            "evidence": evaluation.get("evidence", {}),
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
        "results": results,
    }
