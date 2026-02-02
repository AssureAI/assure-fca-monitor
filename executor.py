import yaml
import re
from datetime import datetime
from typing import Dict, List, Any


# -----------------------------
# TEXT UTILITIES
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return re.split(r'(?<=[.!?])\s+', text)


# -----------------------------
# EVIDENCE HELPERS
# -----------------------------

def phrase_hits(text_norm: str, phrases: List[str]) -> List[str]:
    hits = []
    for p in phrases:
        if isinstance(p, str) and p.lower() in text_norm:
            hits.append(p)
    return hits


def cluster_hits(text_norm: str, clusters: List[List[str]]) -> List[str]:
    matched = []
    for cluster in clusters:
        if not isinstance(cluster, list):
            continue
        for phrase in cluster:
            if isinstance(phrase, str) and phrase.lower() in text_norm:
                matched.append(phrase)
                break
    return matched


# -----------------------------
# RULE EVALUATION (NEVER THROWS)
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic, crash-proof evaluation.
    Returns:
      { status: OK | POTENTIAL_ISSUE | NOT_ASSESSED, evidence: [...] }
    """

    text_norm = normalise(text)

    # Applicability
    applies_when = rule.get("applies_when", {})
    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return {
                "status": "NOT_ASSESSED",
                "evidence": []
            }

    evidence_cfg = rule.get("evidence", {})
    decision_cfg = rule.get("decision_logic", {}).get("ok_if", {})

    counts: Dict[str, int] = {}
    evidence_found: List[str] = []

    # Evaluate evidence blocks
    for ev_key, ev_val in evidence_cfg.items():

        # Cluster-based evidence
        if ev_key.endswith("_clusters") and isinstance(ev_val, list):
            matches = cluster_hits(text_norm, ev_val)
            counts[ev_key] = len(matches)
            evidence_found.extend(matches)

        # Phrase list evidence
        elif isinstance(ev_val, list):
            matches = phrase_hits(text_norm, ev_val)
            counts[ev_key] = len(matches)
            evidence_found.extend(matches)

        else:
            counts[ev_key] = 0

    # Decision logic
    for metric, condition in decision_cfg.items():
        val = counts.get(metric, 0)

        if condition.startswith(">="):
            if val < int(condition[2:]):
                return {
                    "status": "POTENTIAL_ISSUE",
                    "evidence": evidence_found
                }

        elif condition.startswith("=="):
            if val != int(condition[2:]):
                return {
                    "status": "POTENTIAL_ISSUE",
                    "evidence": evidence_found
                }

    return {
        "status": "OK",
        "evidence": evidence_found
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

    rules = ruleset.get("rules", [])

    results = []

    for rule in rules:
        evaluation = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule.get("id"),
            "status": evaluation["status"],
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
            "evidence": evaluation["evidence"]
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED")
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id"),
        "ruleset_version": ruleset.get("version"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results
    }
