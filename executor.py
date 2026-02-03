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
    for sent in sentences:
        s_norm = sent.lower()
        for p in phrases:
            if p.lower() in s_norm:
                hits.append(sent)
    return hits


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies = rule.get("applies_when", {})

    for k, v in applies.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    phrases = rule.get("phrases", [])

    matched = phrase_hits(sentences, phrases)

    if len(matched) >= rule.get("min_hits", 1):
        return {
            "status": "OK",
            "evidence": matched[:5],  # cap evidence
        }

    return {
        "status": "POTENTIAL_ISSUE",
        "evidence": matched[:5],
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

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in ruleset["rules"]:
        outcome = evaluate_rule(rule, document_text, context)

        section = rule["section"]
        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule["id"],
            "title": rule["title"],
            "status": outcome["status"],
            "citation": rule["citation"],
            "source_url": rule["source_url"],
            "evidence": outcome.get("evidence", []),
        })

    summary = {
        "ok": sum(1 for s in grouped.values() for r in s if r["status"] == "OK"),
        "potential_issue": sum(1 for s in grouped.values() for r in s if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for s in grouped.values() for r in s if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": grouped,
    }
