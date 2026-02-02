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
    return [s.strip() for s in re.split(r'(?<=[.!?])\s+', text or "") if s.strip()]


def phrase_hits(sentences: List[str], phrases: List[str]):
    hits = []
    for sent in sentences:
        sent_l = sent.lower()
        for phrase in phrases:
            if isinstance(phrase, str) and phrase.lower() in sent_l:
                hits.append((phrase, sent))
    return hits


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    # Applicability
    for k, v in rule.get("applies_when", {}).items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {}).get("ok_if", [])

    counts: Dict[str, int] = {}
    matched_phrases: List[str] = []
    matched_sentences: List[str] = []

    # --- Evidence scanning ---
    for key, value in evidence.items():

        # CLUSTERS (list of lists)
        if key.endswith("_clusters"):
            hit_clusters = 0
            for cluster in value:
                if not isinstance(cluster, list):
                    continue
                hits = phrase_hits(sentences, cluster)
                if hits:
                    hit_clusters += 1
                    for p, s in hits:
                        matched_phrases.append(p)
                        matched_sentences.append(s)
            counts[key] = hit_clusters

        # FLAT phrase lists
        elif isinstance(value, list):
            hits = phrase_hits(sentences, value)
            counts[key] = len(hits)
            for p, s in hits:
                matched_phrases.append(p)
                matched_sentences.append(s)

    # --- Decision logic ---
    for cond in decision:
        if not isinstance(cond, str):
            continue

        if cond.startswith(">="):
            num, key = cond[2:].split(maxsplit=1)
            if counts.get(key, 0) < int(num):
                return _fail(matched_phrases, matched_sentences)

        elif cond.startswith("=="):
            num, key = cond[2:].split(maxsplit=1)
            if counts.get(key, 0) != int(num):
                return _fail(matched_phrases, matched_sentences)

    return {
        "status": "OK",
        "evidence": {
            "matched_phrases": sorted(set(matched_phrases)),
            "sentences": sorted(set(matched_sentences)),
        }
    }


def _fail(phrases, sentences):
    return {
        "status": "POTENTIAL_ISSUE",
        "evidence": {
            "matched_phrases": sorted(set(phrases)),
            "sentences": sorted(set(sentences)),
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
