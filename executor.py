import yaml
import re
from datetime import datetime
from typing import Dict, List, Any


# -----------------------------
# TEXT UTILITIES
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return re.split(r"(?<=[.!?])\s+", text)


def find_snippets(text: str, phrases: List[str]) -> List[str]:
    sentences = split_sentences(text)
    hits = []
    for s in sentences:
        s_norm = s.lower()
        for p in phrases:
            if p.lower() in s_norm:
                hits.append(s.strip())
                break
    return hits


def cluster_hit_count(text: str, clusters: List[List[str]]) -> (int, List[str]):
    hit_phrases = []
    count = 0
    for cluster in clusters:
        for phrase in cluster:
            if phrase.lower() in text:
                count += 1
                hit_phrases.extend(cluster)
                break
    return count, list(set(hit_phrases))


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})
    for k, v in applies_when.items():
        if context.get(k) != v:
            return {
                "status": "NOT_ASSESSED",
                "evidence": {}
            }

    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {}).get("ok_if", [])

    text_norm = normalise(text)
    evidence_hits = {}
    matched_phrases = set()

    for key, value in evidence.items():
        if key.endswith("_clusters"):
            count, phrases = cluster_hit_count(text_norm, value)
            evidence_hits[key] = count
            matched_phrases.update(phrases)
        else:
            hits = [p for p in value if p.lower() in text_norm]
            evidence_hits[key] = len(hits)
            matched_phrases.update(hits)

    for rule_expr in decision:
        if rule_expr.startswith(">="):
            needed, field = rule_expr[2:].split(" ")
            if evidence_hits.get(field, 0) < int(needed):
                break
        elif rule_expr.startswith("=="):
            needed, field = rule_expr[2:].split(" ")
            if evidence_hits.get(field, 0) != int(needed):
                break
    else:
        snippets = find_snippets(text, list(matched_phrases))
        return {
            "status": "OK",
            "evidence": {
                "matched_phrases": sorted(matched_phrases),
                "snippets": snippets
            }
        }

    snippets = find_snippets(text, list(matched_phrases))
    return {
        "status": "POTENTIAL_ISSUE",
        "evidence": {
            "matched_phrases": sorted(matched_phrases),
            "snippets": snippets
        }
    }


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    sections: Dict[str, Dict[str, Any]] = {}

    for rule in ruleset["rules"]:
        section_id = rule["id"].split("_")[0]  # e.g. COBS9
        section = sections.setdefault(section_id, {
            "id": section_id,
            "title": section_id.replace("COBS", "COBS "),
            "rules": []
        })

        evaluation = evaluate_rule(rule, document_text, context)

        section["rules"].append({
            "rule_id": rule["id"],
            "obligation": rule["obligation"],
            "status": evaluation["status"],
            "citation": rule["citation"],
            "source_url": rule.get("source_url"),
            "evidence": evaluation.get("evidence", {})
        })

    all_rules = [r for s in sections.values() for r in s["rules"]]

    summary = {
        "ok": sum(1 for r in all_rules if r["status"] == "OK"),
        "potential_issue": sum(1 for r in all_rules if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in all_rules if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": list(sections.values())
    }
