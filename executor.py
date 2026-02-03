import yaml
import re
from datetime import datetime
from typing import Dict, List, Any

EXECUTOR_VERSION = "2026-02-03-stable-evidence-v1"

# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return [
        s.strip()
        for s in re.split(r'(?<=[.!?])\s+', text or "")
        if s.strip()
    ]


def phrase_hits(sentences: List[str], phrases: List[str]) -> List[str]:
    hits = []
    for s in sentences:
        s_norm = s.lower()
        for p in phrases:
            if isinstance(p, str) and p.lower() in s_norm:
                hits.append(s)
    return hits


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    # Applicability gate
    for k, v in rule.get("applies_when", {}).items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    positives: List[str] = []
    negatives: List[str] = []

    counts: Dict[str, int] = {}

    # POSITIVE CLUSTERS
    for cluster in evidence.get("positive_clusters", []):
        if not isinstance(cluster, list):
            continue
        hits = phrase_hits(sentences, cluster)
        if hits:
            counts.setdefault("positive_clusters", 0)
            counts["positive_clusters"] += 1
            positives.extend(hits[:1])  # one sentence per cluster

    # NEGATIVE INDICATORS
    neg_phrases = evidence.get("negative_indicators", [])
    if isinstance(neg_phrases, list):
        neg_hits = phrase_hits(sentences, neg_phrases)
        negatives.extend(neg_hits[:3])
        counts["negative_indicators"] = len(neg_hits)

    # DECISION
    status = "OK"
    for cond in decision.get("fail_if", []):
        if cond == "any_negative" and negatives:
            status = "POTENTIAL_ISSUE"

    return {
        "status": status,
        "evidence": {
            "positive": positives[:3],
            "negative": negatives[:3],
        }
    }


# -----------------------------
# EXECUTOR ENTRY
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    results = []

    for rule in ruleset.get("rules", []):
        outcome = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule["id"],
            "section": rule.get("section", "Other"),
            "status": outcome["status"],
            "citation": rule["citation"],
            "evidence": outcome.get("evidence", {}),
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "executor_version": EXECUTOR_VERSION,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
