import yaml
import re
from datetime import datetime
from typing import Dict, List, Any

EXECUTOR_VERSION = "2026-02-03-clean-v1"
MAX_EVIDENCE_SENTENCES = 6


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return [
        s.strip()
        for s in re.split(r"(?<=[.!?])\s+", text or "")
        if s.strip()
    ]


def phrase_hits(sentences: List[str], phrases: List[str]) -> List[str]:
    hits = []
    if not isinstance(phrases, list):
        return hits

    for sent in sentences:
        s_norm = sent.lower()
        for p in phrases:
            if isinstance(p, str) and p.lower() in s_norm:
                hits.append(sent)
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
    evidence_cfg = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    counts: Dict[str, int] = {}
    evidence_sentences: List[str] = []

    for key, value in evidence_cfg.items():
        if key.endswith("_clusters"):
            if not isinstance(value, list):
                counts[key] = 0
                continue

            cluster_hits = 0
            for cluster in value:
                hits = phrase_hits(sentences, cluster if isinstance(cluster, list) else [])
                if hits:
                    cluster_hits += 1
                    evidence_sentences.extend(hits)

            counts[key] = cluster_hits

        else:
            hits = phrase_hits(sentences, value if isinstance(value, list) else [])
            counts[key] = len(hits)
            evidence_sentences.extend(hits)

    # -----------------------------
    # DECISION LOGIC
    # -----------------------------

    for cond in decision.get("ok_if", []):
        if not isinstance(cond, dict):
            return {"status": "POTENTIAL_ISSUE"}

        key = cond.get("key")
        op = cond.get("op")
        threshold = cond.get("value")

        val = counts.get(key, 0)

        if op == ">=" and val < threshold:
            return {"status": "POTENTIAL_ISSUE"}
        if op == "==" and val != threshold:
            return {"status": "POTENTIAL_ISSUE"}

    return {
        "status": "OK",
        "evidence": {
            "sentences": list(dict.fromkeys(evidence_sentences))[:MAX_EVIDENCE_SENTENCES]
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

    for rule in ruleset.get("rules", []):
        outcome = evaluate_rule(rule, document_text, context)

        res = {
            "rule_id": rule.get("id"),
            "status": outcome["status"],
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
        }

        if "evidence" in outcome and outcome["evidence"]["sentences"]:
            res["evidence"] = outcome["evidence"]

        results.append(res)

    summary = {
        "ok": sum(r["status"] == "OK" for r in results),
        "potential_issue": sum(r["status"] == "POTENTIAL_ISSUE" for r in results),
        "not_assessed": sum(r["status"] == "NOT_ASSESSED" for r in results),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id"),
        "ruleset_version": ruleset.get("version"),
        "executor_version": EXECUTOR_VERSION,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
