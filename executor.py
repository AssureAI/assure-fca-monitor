import yaml
import re
from datetime import datetime
from typing import Dict, Any, List


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def split_sentences(text: str) -> List[str]:
    return re.split(r'(?<=[.!?])\s+', text)


def find_hits(sentences: List[str], phrases: List[str]) -> List[str]:
    hits = []
    for s in sentences:
        s_norm = normalise(s)
        for p in phrases:
            if normalise(p) in s_norm:
                hits.append(s.strip())
    return list(dict.fromkeys(hits))  # dedupe, preserve order


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})

    for k, v in applies_when.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED", "evidence": []}

    phrases = rule.get("evidence", {}).get("phrases", [])
    sentences = split_sentences(text)
    matched = find_hits(sentences, phrases)

    if matched:
        return {"status": "OK", "evidence": matched}

    return {"status": "POTENTIAL_ISSUE", "evidence": []}


# -----------------------------
# ENGINE ENTRY
# -----------------------------

def run_rules_engine(document_text: str, context: Dict[str, Any], rules_path: str) -> Dict[str, Any]:
    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    results_by_section = {}
    summary = {"ok": 0, "potential_issue": 0, "not_assessed": 0}

    for section_id, section in ruleset["sections"].items():
        section_results = []

        for rule in section["rules"]:
            outcome = evaluate_rule(rule, document_text, context)

            status = outcome["status"]
            summary_key = status.lower()
            summary[summary_key] += 1

            section_results.append({
                "rule_id": rule["id"],
                "obligation": rule["obligation"],
                "status": status,
                "citation": rule["citation"],
                "evidence": outcome["evidence"],
            })

        results_by_section[section_id] = {
            "title": section["title"],
            "rules": section_results,
        }

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": results_by_section,
    }
