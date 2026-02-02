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
    # Simple, deterministic sentence splitter
    parts = re.split(r'(?<=[.!?])\s+', text.strip())
    return [p.strip() for p in parts if p.strip()]


def find_phrase_hits(sentences: List[str], phrases: List[str]):
    hits = []
    for sent in sentences:
        sent_norm = sent.lower()
        for phrase in phrases:
            if phrase.lower() in sent_norm:
                hits.append((phrase, sent))
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

    matched_phrases = []
    matched_sentences = []

    counts = {}

    for key, clusters in evidence.items():
        if not isinstance(clusters, list):
            continue

        if key.endswith("_clusters"):
            hit_count = 0
            for cluster in clusters:
                hits = find_phrase_hits(sentences, cluster)
                if hits:
                    hit_count += 1
                    for p, s in hits:
                        matched_phrases.append(p)
                        matched_sentences.append(s)
            counts[key] = hit_count

        else:
            hits = find_phrase_hits(sentences, clusters)
            counts[key] = len(hits)
            for p, s in hits:
                matched_phrases.append(p)
                matched_sentences.append(s)

    # Decision logic
    for condition in decision.get("ok_if", []):
        if isinstance(condition, str):
            parts = condition.split()
            if len(parts) != 2:
                return {"status": "POTENTIAL_ISSUE"}
            op, key = parts
            val = counts.get(key, 0)

            if op.startswith(">=") and val < int(op[2:]):
                return {"status": "POTENTIAL_ISSUE"}
            if op.startswith("==") and val != int(op[2:]):
                return {"status": "POTENTIAL_ISSUE"}

    return {
        "status": "OK",
        "evidence": {
            "matched_phrases": sorted(set(matched_phrases)),
            "sentences": sorted(set(matched_sentences)),
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

    for rule in ruleset["rules"]:
        outcome = evaluate_rule(rule, document_text, context)

        res = {
            "rule_id": rule["id"],
            "status": outcome["status"],
            "citation": rule["citation"],
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
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
