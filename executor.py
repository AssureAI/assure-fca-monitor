import yaml
import re
from datetime import datetime
from typing import Dict, List, Any

MAX_EVIDENCE = 3  # hard cap per rule


def split_sentences(text: str) -> List[str]:
    return re.split(r'(?<=[.!?])\s+', text.strip())


def phrase_hits(sentences: List[str], phrases: List[str]):
    hits = []
    for s in sentences:
        s_norm = s.lower()
        for p in phrases:
            if isinstance(p, str) and p.lower() in s_norm:
                hits.append({
                    "phrase": p,
                    "sentence": s.strip()
                })
                if len(hits) >= MAX_EVIDENCE:
                    return hits
    return hits


def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    # applicability
    for k, v in rule.get("applies_when", {}).items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    evidence_hits = []

    for block in rule.get("evidence", {}).values():
        if not isinstance(block, list):
            continue
        evidence_hits.extend(phrase_hits(sentences, block))
        if len(evidence_hits) >= MAX_EVIDENCE:
            break

    if not evidence_hits:
        return {"status": "POTENTIAL_ISSUE"}

    return {
        "status": "OK",
        "evidence": {
            "hits": evidence_hits[:MAX_EVIDENCE]
        }
    }


def run_rules_engine(document_text: str, context: Dict[str, Any], rules_path: str) -> Dict[str, Any]:
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
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
