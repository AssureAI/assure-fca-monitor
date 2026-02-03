import yaml
import re
from datetime import datetime
from typing import Dict, List, Any

# --------------------------------------------------
# TEXT HELPERS (SAFE, DETERMINISTIC)
# --------------------------------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()

def split_sentences(text: str) -> List[str]:
    parts = re.split(r'(?<=[.!?])\s+', text or "")
    return [p.strip() for p in parts if p.strip()]

def phrase_in_sentence(sentence: str, phrase: str) -> bool:
    return phrase.lower() in sentence.lower()

# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})

    # Applicability gate
    for k, v in applies_when.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED", "evidence": []}

    sentences = split_sentences(text)
    evidence_cfg = rule.get("evidence", {})
    decision_logic = rule.get("decision_logic", {}).get("ok_if", [])

    hit_sentences: List[str] = []
    counters: Dict[str, int] = {}

    # Evaluate evidence blocks
    for key, clusters in evidence_cfg.items():
        if not isinstance(clusters, list):
            continue

        count = 0

        for cluster in clusters:
            if not isinstance(cluster, list):
                continue

            matched = False
            for phrase in cluster:
                if not isinstance(phrase, str):
                    continue

                for sent in sentences:
                    if phrase_in_sentence(sent, phrase):
                        matched = True
                        hit_sentences.append(sent)
                        break

            if matched:
                count += 1

        counters[key] = count

    # Apply decision logic
    for condition in decision_logic:
        if not isinstance(condition, str):
            continue

        parts = condition.split()
        if len(parts) != 2:
            return {"status": "POTENTIAL_ISSUE", "evidence": hit_sentences}

        op, key = parts
        val = counters.get(key, 0)

        if op.startswith(">=") and val < int(op[2:]):
            return {"status": "POTENTIAL_ISSUE", "evidence": hit_sentences}

        if op.startswith("==") and val != int(op[2:]):
            return {"status": "POTENTIAL_ISSUE", "evidence": hit_sentences}

    return {
        "status": "OK",
        "evidence": sorted(set(hit_sentences)),
    }

# --------------------------------------------------
# EXECUTOR ENTRY POINT
# --------------------------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str,
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f)

    sections: Dict[str, Dict[str, Any]] = {}

    for rule in ruleset["rules"]:
        section_id = rule["section_id"]
        section_title = rule["section_title"]

        if section_id not in sections:
            sections[section_id] = {
                "section_id": section_id,
                "section_title": section_title,
                "rules": [],
            }

        outcome = evaluate_rule(rule, document_text, context)

        sections[section_id]["rules"].append({
            "rule_id": rule["id"],
            "status": outcome["status"],
            "citation": rule["citation"],
            "evidence": outcome["evidence"],
        })

    return {
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "sections": list(sections.values()),
    }
