import yaml
import re
from datetime import datetime
from typing import Dict, List, Any


# --------------------------------------------------
# TEXT UTILITIES
# --------------------------------------------------

SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    return [s.strip() for s in SENTENCE_SPLIT.split(text) if s.strip()]


# --------------------------------------------------
# MATCHING UTILITIES
# --------------------------------------------------

def cluster_hits(text_norm: str, sentences: List[str], clusters: List[List[str]]):
    """
    Returns:
      hits_count,
      matched_phrases,
      matched_sentences
    """
    matched_phrases = set()
    matched_sentences = set()
    hits = 0

    for cluster in clusters:
        cluster_matched = False
        for phrase in cluster:
            p = phrase.lower()
            if p in text_norm:
                matched_phrases.add(phrase)
                cluster_matched = True

                for s in sentences:
                    if p in s.lower():
                        matched_sentences.add(s)

        if cluster_matched:
            hits += 1

    return hits, list(matched_phrases), list(matched_sentences)


def negative_hits(text_norm: str, sentences: List[str], clusters: List[List[str]]):
    """
    Negative indicators behave like clusters:
    - Any phrase in a cluster triggers the cluster
    """
    hits = 0
    matched_phrases = set()
    matched_sentences = set()

    for cluster in clusters:
        cluster_hit = False
        for phrase in cluster:
            p = phrase.lower()
            if p in text_norm:
                cluster_hit = True
                matched_phrases.add(phrase)
                for s in sentences:
                    if p in s.lower():
                        matched_sentences.add(s)
        if cluster_hit:
            hits += 1

    return hits, list(matched_phrases), list(matched_sentences)


# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns full rule evaluation payload including evidence
    """
    applies_when = rule.get("applies_when", {})

    # Applicability
    for key, expected in applies_when.items():
        if context.get(key) != expected:
            return {
                "status": "NOT_ASSESSED",
                "evidence": None
            }

    text_norm = normalise(text)
    sentences = split_sentences(text)

    evidence = rule.get("evidence", {})
    decision = rule.get("decision_logic", {}).get("ok_if", [])

    cluster_counts = {}
    phrase_hits = {}
    sentence_hits = {}

    # Positive clusters
    if "positive_clusters" in evidence:
        hits, phrases, sents = cluster_hits(
            text_norm,
            sentences,
            evidence["positive_clusters"]
        )
        cluster_counts["positive_clusters"] = hits
        phrase_hits["positive_clusters"] = phrases
        sentence_hits["positive_clusters"] = sents

    # Linkage / causal / contextual clusters
    for key in ["linkage_indicators", "causal_language", "contextual_indicators"]:
        if key in evidence:
            hits, phrases, sents = cluster_hits(
                text_norm,
                sentences,
                [[p] for p in evidence[key]]
            )
            cluster_counts[key] = hits
            phrase_hits[key] = phrases
            sentence_hits[key] = sents

    # Negative indicators
    if "negative_indicators" in evidence:
        hits, phrases, sents = negative_hits(
            text_norm,
            sentences,
            evidence["negative_indicators"]
        )
        cluster_counts["negative_indicators"] = hits
        phrase_hits["negative_indicators"] = phrases
        sentence_hits["negative_indicators"] = sents

    # Decision logic evaluation
    status = "OK"
    required_clusters = 0

    for condition in decision:
        condition = condition.strip()

        if condition.startswith(">="):
            n, key = condition[2:].split(" ", 1)
            required_clusters += int(n)
            if cluster_counts.get(key.strip(), 0) < int(n):
                status = "POTENTIAL_ISSUE"

        elif condition.startswith("=="):
            n, key = condition[2:].split(" ", 1)
            if cluster_counts.get(key.strip(), 0) != int(n):
                status = "POTENTIAL_ISSUE"

    return {
        "status": status,
        "evidence": {
            "matched_phrases": sorted(set(sum(phrase_hits.values(), []))),
            "matched_sentences": sorted(set(sum(sentence_hits.values(), []))),
            "clusters_hit": sum(cluster_counts.values()),
            "required_clusters": required_clusters or None
        }
    }


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

    results = []

    for rule in ruleset["rules"]:
        evaluation = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule["id"],
            "status": evaluation["status"],
            "citation": rule["citation"],
            "source_url": rule.get("source_url"),
            "evidence": evaluation["evidence"]
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED")
    }

    return {
        "ruleset_id": ruleset["ruleset"]["id"],
        "ruleset_version": ruleset["ruleset"]["version"],
        "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "summary": summary,
        "results": results
    }
