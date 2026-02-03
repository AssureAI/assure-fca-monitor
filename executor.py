import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Iterable


# --------------------------------------------------
# TEXT UTILITIES
# --------------------------------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    return [p.strip() for p in parts if p.strip()]


def flatten_phrases(items: Any) -> List[str]:
    """
    YAML sometimes gives:
      ["a","b","c"]  (good)
    and sometimes:
      [["a","b"],["c","d"]]  (clusters)
    and sometimes mixed.
    This returns a flat list of strings only.
    """
    out: List[str] = []

    def walk(x: Any):
        if x is None:
            return
        if isinstance(x, str):
            s = x.strip()
            if s:
                out.append(s)
            return
        if isinstance(x, list) or isinstance(x, tuple):
            for y in x:
                walk(y)
            return
        # ignore non-string scalars (bool/int/etc)

    walk(items)
    return out


def phrase_hits(sentences: List[str], phrases_any: Any):
    phrases = flatten_phrases(phrases_any)
    hits = []
    for s in sentences:
        s_norm = s.lower()
        for p in phrases:
            if p.lower() in s_norm:
                hits.append((p, s))
    return hits


# --------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    # Applicability
    for k, v in (rule.get("applies_when") or {}).items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED"}

    sentences = split_sentences(text)
    evidence = rule.get("evidence") or {}
    ok_if = (rule.get("decision_logic") or {}).get("ok_if") or []

    counts: Dict[str, int] = {}
    matched_phrases = set()
    matched_sentences = set()

    for key, value in evidence.items():
        # cluster evidence: list of clusters (each cluster is list of phrases)
        if key.endswith("_clusters") and isinstance(value, list):
            cluster_hits = 0
            for cluster in value:
                hits = phrase_hits(sentences, cluster)
                if hits:
                    cluster_hits += 1
                    for p, s in hits:
                        matched_phrases.add(p)
                        matched_sentences.add(s)
            counts[key] = cluster_hits
        else:
            # non-cluster evidence: may still contain nested lists -> flatten safely
            hits = phrase_hits(sentences, value)
            counts[key] = len(hits)
            for p, s in hits:
                matched_phrases.add(p)
                matched_sentences.add(s)

    # Decision logic (machine-safe format: [" >=2 positive_clusters", ">=1 linkage_indicators" ])
    for cond in ok_if:
        if not isinstance(cond, str):
            return {"status": "POTENTIAL_ISSUE"}

        cond = cond.strip()
        # expected format: ">=2 positive_clusters" (two tokens)
        parts = cond.split()
        if len(parts) != 2:
            return {"status": "POTENTIAL_ISSUE"}

        op_num, key = parts
        val = counts.get(key, 0)

        if op_num.startswith(">="):
            req = int(op_num[2:])
            if val < req:
                return {"status": "POTENTIAL_ISSUE"}

        elif op_num.startswith("=="):
            req = int(op_num[2:])
            if val != req:
                return {"status": "POTENTIAL_ISSUE"}

        elif op_num.startswith("<="):
            req = int(op_num[2:])
            if val > req:
                return {"status": "POTENTIAL_ISSUE"}

        else:
            return {"status": "POTENTIAL_ISSUE"}

    return {
        "status": "OK",
        "evidence": {
            "matched_phrases": sorted(matched_phrases),
            "sentences": sorted(matched_sentences),
        }
    }


# --------------------------------------------------
# EXECUTOR ENTRY
# --------------------------------------------------

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

        results.append({
            "rule_id": rule.get("id", ""),
            "status": outcome.get("status", "NOT_ASSESSED"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", ""),
            "section": (rule.get("section") or rule.get("id", "").split("_")[0] or "OTHER"),
            "evidence": outcome.get("evidence", {"matched_phrases": [], "sentences": []}),
        })

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id", "unknown"),
        "ruleset_version": ruleset.get("version", "unknown"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
    }
