import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple

# --------------------------------------------------
# TEXT HELPERS
# --------------------------------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return re.split(r"(?<=[.!?])\s+", text)


# --------------------------------------------------
# EVIDENCE MATCHING
# --------------------------------------------------

def cluster_hits(text: str, clusters: List[List[str]]) -> Tuple[int, List[str]]:
    """
    A cluster is satisfied if ANY phrase in the cluster appears.
    Returns number of satisfied clusters + matched phrases.
    """
    hits = 0
    matched = []

    for cluster in clusters:
        for phrase in cluster:
            if phrase.lower() in text:
                hits += 1
                matched.append(phrase)
                break

    return hits, matched


def phrase_hits(text: str, phrases: List[str]) -> Tuple[int, List[str]]:
    matched = [p for p in phrases if p.lower() in text]
    return len(matched), matched


# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(
    rule: Dict[str, Any],
    document_text: str,
    context: Dict[str, Any]
) -> Tuple[str, Dict[str, Any]]:

    # Applicability
    for k, v in rule.get("applies_when", {}).items():
        if context.get(k) != v:
            return "NOT_ASSESSED", {}

    text_norm = normalise(document_text)
    sentences = split_sentences(document_text)

    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {}).get("ok_if", [])

    counts = {}
    matches = {}

    for key, value in evidence.items():
        if not value:
            continue

        # clusters = list[list[str]]
        if isinstance(value, list) and value and isinstance(value[0], list):
            c, m = cluster_hits(text_norm, value)
            counts[key] = c
            matches[key] = m

        # phrases = list[str]
        elif isinstance(value, list):
            c, m = phrase_hits(text_norm, value)
            counts[key] = c
            matches[key] = m

    # Apply decision logic
    for clause in decision:
        clause = clause.strip()

        if clause.startswith(">="):
            num, key = clause[2:].split(" ", 1)
            if counts.get(key.strip(), 0) < int(num):
                return "POTENTIAL_ISSUE", matches

    return "OK", matches


# --------------------------------------------------
# ENGINE ENTRY POINT
# --------------------------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        raw = yaml.safe_load(f)

    ruleset_id = raw.get("ruleset_id", "unknown")
    ruleset_version = raw.get("version", "unknown")

    # Extract rule blocks (flat YAML authoring format)
    rules = [
        v for v in raw.values()
        if isinstance(v, dict) and "id" in v and "citation" in v
    ]

    results = []

    for rule in rules:
        status, evidence = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule["id"],
            "status": status,
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
            "evidence": evidence,
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset_id,
        "ruleset_version": ruleset_version,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
