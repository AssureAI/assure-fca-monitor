import yaml
import re
from datetime import datetime
from typing import Dict, List, Any


# --------------------------------------------------
# TEXT HELPERS
# --------------------------------------------------

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
        s_norm = normalise(s)
        for p in phrases:
            if isinstance(p, str) and p.lower() in s_norm:
                hits.append(s)
    return hits


# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})

    for k, v in applies_when.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED", "evidence": []}

    sentences = split_sentences(text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    counts: Dict[str, int] = {}
    evidence_sentences: List[str] = []

    for key, clusters in evidence.items():
        if not isinstance(clusters, list):
            counts[key] = 0
            continue

        # clusters = list[list[str]]
        hit_count = 0
        for cluster in clusters:
            if not isinstance(cluster, list):
                continue
            hits = phrase_hits(sentences, cluster)
            if hits:
                hit_count += 1
                evidence_sentences.extend(hits)

        counts[key] = hit_count

    # Decision logic
    ok_conditions = decision.get("ok_if", [])

    for cond in ok_conditions:
        if not isinstance(cond, dict):
            continue

        key = cond.get("key")
        op = cond.get("op")
        val = cond.get("value")

        actual = counts.get(key, 0)

        if op == ">=" and actual < val:
            return {"status": "POTENTIAL_ISSUE", "evidence": sorted(set(evidence_sentences))}
        if op == "==" and actual != val:
            return {"status": "POTENTIAL_ISSUE", "evidence": sorted(set(evidence_sentences))}

    return {"status": "OK", "evidence": sorted(set(evidence_sentences))}


# --------------------------------------------------
# EXECUTOR ENTRY POINT
# --------------------------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    sections_out = []
    summary = {"ok": 0, "potential_issue": 0, "not_assessed": 0}

    for section in ruleset.get("sections", []):
        section_rules = []

        for rule in section.get("rules", []):
            outcome = evaluate_rule(rule, document_text, context)

            status = outcome["status"]
            summary[
                "ok" if status == "OK"
                else "potential_issue" if status == "POTENTIAL_ISSUE"
                else "not_assessed"
            ] += 1

            section_rules.append({
                "rule_id": rule["id"],
                "status": status,
                "citation": rule.get("citation"),
                "source_url": rule.get("source_url"),
                "evidence": outcome["evidence"]
            })

        sections_out.append({
            "section_id": section.get("id"),
            "title": section.get("title"),
            "rules": section_rules
        })

    return {
        "ruleset_id": ruleset.get("ruleset_id"),
        "ruleset_version": ruleset.get("version"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": sections_out
    }
