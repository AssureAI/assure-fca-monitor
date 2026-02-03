import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple


# ==================================================
# SAFE TEXT HELPERS (NO TYPE ASSUMPTIONS)
# ==================================================

def _is_str(x) -> bool:
    return isinstance(x, str)


def normalise(text: str) -> str:
    if not _is_str(text):
        return ""
    return re.sub(r"\s+", " ", text.lower()).strip()


def split_sentences(text: str) -> List[str]:
    if not _is_str(text):
        return []
    parts = re.split(r'(?<=[.!?])\s+', text)
    return [p.strip() for p in parts if p.strip()]


def phrase_hits(sentences: List[str], phrases: List[str]) -> List[Tuple[str, str]]:
    """
    Returns [(phrase, sentence), ...] for matches.
    SAFE: ignores non-string phrases.
    """
    hits = []
    for sent in sentences:
        if not _is_str(sent):
            continue
        sent_norm = sent.lower()
        for p in phrases:
            if not _is_str(p):
                continue
            if p.lower() in sent_norm:
                hits.append((p, sent))
    return hits


# ==================================================
# RULE EVALUATION
# ==================================================

def evaluate_rule(
    rule: Dict[str, Any],
    document_text: str,
    context: Dict[str, Any],
) -> Dict[str, Any]:

    # ------------------
    # Applicability gate
    # ------------------
    applies_when = rule.get("applies_when", {})
    if isinstance(applies_when, dict):
        for k, v in applies_when.items():
            if context.get(k) != v:
                return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(document_text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    counts: Dict[str, int] = {}
    matched_sentences: List[str] = []
    matched_phrases: List[str] = []

    # ------------------
    # Evidence scanning
    # ------------------
    for key, value in evidence.items():

        # CLUSTERS: list[list[str]]
        if key.endswith("_clusters") and isinstance(value, list):
            cluster_hits = 0
            for cluster in value:
                if not isinstance(cluster, list):
                    continue
                hits = phrase_hits(sentences, cluster)
                if hits:
                    cluster_hits += 1
                    for p, s in hits:
                        matched_phrases.append(p)
                        matched_sentences.append(s)
            counts[key] = cluster_hits
            continue

        # SIMPLE LIST: list[str]
        if isinstance(value, list):
            hits = phrase_hits(sentences, value)
            counts[key] = len(hits)
            for p, s in hits:
                matched_phrases.append(p)
                matched_sentences.append(s)
            continue

    # ------------------
    # Decision logic
    # ------------------
    ok_conditions = decision.get("ok_if", [])

    if not isinstance(ok_conditions, list):
        return {"status": "POTENTIAL_ISSUE"}

    for cond in ok_conditions:
        if not _is_str(cond):
            return {"status": "POTENTIAL_ISSUE"}

        parts = cond.split()
        if len(parts) != 2:
            return {"status": "POTENTIAL_ISSUE"}

        op, key = parts
        value = counts.get(key, 0)

        if op.startswith(">="):
            if value < int(op[2:]):
                return {"status": "POTENTIAL_ISSUE"}

        elif op.startswith("=="):
            if value != int(op[2:]):
                return {"status": "POTENTIAL_ISSUE"}

        else:
            return {"status": "POTENTIAL_ISSUE"}

    # ------------------
    # Passed
    # ------------------
    return {
        "status": "OK",
        "evidence": {
            "matched_phrases": sorted(set(matched_phrases)),
            "sentences": sorted(set(matched_sentences)),
        }
    }


# ==================================================
# EXECUTOR ENTRY POINT
# ==================================================

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str,
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    rules = ruleset.get("rules", [])
    results = []

    for rule in rules:
        outcome = evaluate_rule(rule, document_text, context)

        res = {
            "rule_id": rule.get("id"),
            "status": outcome.get("status"),
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
        }

        if "evidence" in outcome:
            res["evidence"] = outcome["evidence"]

        results.append(res)

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
        "results": results,
    }
