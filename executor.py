import yaml
import re
from datetime import datetime
from typing import Dict, List, Any


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def phrase_hits(sentences: List[str], phrases: List[str]) -> List[str]:
    hits = []
    for s in sentences:
        s_norm = s.lower()
        for p in phrases:
            if isinstance(p, str) and p.lower() in s_norm:
                hits.append(s)
                break
    return hits


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})
    for k, v in applies_when.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    counts: Dict[str, int] = {}
    matched_sentences: Dict[str, List[str]] = {}

    for key, value in evidence.items():
        matched_sentences[key] = []

        # Cluster logic (list of lists)
        if key.endswith("_clusters"):
            hit_clusters = 0
            for cluster in value:
                hits = phrase_hits(sentences, cluster)
                if hits:
                    hit_clusters += 1
                    matched_sentences[key].extend(hits)
            counts[key] = hit_clusters

        # Flat phrase list
        else:
            hits = phrase_hits(sentences, value)
            counts[key] = len(hits)
            matched_sentences[key].extend(hits)

    # -----------------------------
    # DECISION
    # -----------------------------

    for cond in decision.get("ok_if", []):
        op, key = cond.split()
        val = counts.get(key, 0)

        if op.startswith(">=") and val < int(op[2:]):
            return {"status": "POTENTIAL_ISSUE"}
        if op.startswith("==") and val != int(op[2:]):
            return {"status": "POTENTIAL_ISSUE"}

    # Only return evidence that actually mattered
    final_sentences = []
    for key in decision.get("ok_if", []):
        _, k = key.split()
        final_sentences.extend(matched_sentences.get(k, []))

    return {
        "status": "OK",
        "evidence": {
            "sentences": sorted(set(final_sentences))
        }
    }


# -----------------------------
# EXECUTOR ENTRY
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
        outcome = evaluate_rule(rule, document_text, context)

        res = {
            "rule_id": rule["id"],
            "status": outcome["status"],
            "citation": rule["citation"],
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
