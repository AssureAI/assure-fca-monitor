import yaml
import re
from datetime import datetime
from typing import Dict, Any, List


# --------------------------------------------------
# NORMALISATION
# --------------------------------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return re.split(r"(?<=[.!?])\s+", text or "")


# --------------------------------------------------
# EVIDENCE EVALUATION
# --------------------------------------------------

def cluster_hits(text: str, clusters: List[List[str]]) -> int:
    """
    A cluster counts as hit if ANY phrase in that cluster appears.
    """
    hits = 0
    for cluster in clusters:
        if not isinstance(cluster, list):
            continue
        for phrase in cluster:
            if isinstance(phrase, str) and phrase.lower() in text:
                hits += 1
                break
    return hits


def phrase_hits(text: str, phrases: List[str]) -> int:
    hits = 0
    for phrase in phrases:
        if isinstance(phrase, str) and phrase.lower() in text:
            hits += 1
    return hits


def negative_hits(text: str, sentences: List[str], indicators: List[Any]):
    matched = []
    for item in indicators:
        if isinstance(item, list):
            for p in item:
                if isinstance(p, str) and p.lower() in text:
                    matched.append(p)
        elif isinstance(item, str):
            if item.lower() in text:
                matched.append(item)
    return matched


# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(rule: Dict[str, Any], document_text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns dict with:
      status, evidence_hits, negative_hits
    Never raises.
    """

    text_norm = normalise(document_text)
    sentences = split_sentences(document_text)

    # ---------- Applicability ----------
    applies_when = rule.get("applies_when", {})
    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return {"status": "NOT_ASSESSED", "evidence": [], "negatives": []}

    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    counts: Dict[str, int] = {}
    evidence_hits: Dict[str, int] = {}
    negatives_found: List[str] = []

    # ---------- Evidence ----------
    for ev_key, ev_val in evidence.items():
        if ev_key.endswith("_clusters") and isinstance(ev_val, list):
            hits = cluster_hits(text_norm, ev_val)
            counts[ev_key] = hits
            evidence_hits[ev_key] = hits

        elif ev_key.endswith("_indicators") and isinstance(ev_val, list):
            hits = phrase_hits(text_norm, ev_val)
            counts[ev_key] = hits
            evidence_hits[ev_key] = hits

        elif ev_key == "negative_indicators" and isinstance(ev_val, list):
            negatives_found = negative_hits(text_norm, sentences, ev_val)

    # ---------- Decision Logic ----------
    ok_conditions = decision.get("ok_if", [])

    status = "OK"

    if isinstance(ok_conditions, list):
        for cond in ok_conditions:
            if not isinstance(cond, str):
                continue

            cond = cond.strip()

            # >=N key
            if cond.startswith(">="):
                parts = cond[2:].split()
                if len(parts) != 2:
                    status = "POTENTIAL_ISSUE"
                    continue
                needed = int(parts[0])
                key = parts[1]
                if counts.get(key, 0) < needed:
                    status = "POTENTIAL_ISSUE"

            # ==N key
            elif cond.startswith("=="):
                parts = cond[2:].split()
                if len(parts) != 2:
                    status = "POTENTIAL_ISSUE"
                    continue
                needed = int(parts[0])
                key = parts[1]
                if counts.get(key, 0) != needed:
                    status = "POTENTIAL_ISSUE"

            # AND / OR are implicit via sequential evaluation

    # Negative indicators override OK
    if negatives_found:
        status = "POTENTIAL_ISSUE"

    return {
        "status": status,
        "evidence": evidence_hits,
        "negatives": negatives_found
    }


# --------------------------------------------------
# ENGINE ENTRY POINT
# --------------------------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    rules = ruleset.get("rules", [])

    results = []
    section_map: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        evaluation = evaluate_rule(rule, document_text, context)

        result = {
            "rule_id": rule.get("id"),
            "status": evaluation["status"],
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
            "evidence_hits": evaluation["evidence"],
            "negative_hits": evaluation["negatives"],
        }

        results.append(result)

        # Group by COBS section prefix (e.g. COBS9)
        prefix = rule.get("id", "").split("_")[0]
        section_map.setdefault(prefix, []).append(result)

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id"),
        "ruleset_version": ruleset.get("version"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": section_map,
        "results": results,
    }
