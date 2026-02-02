import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    # simple sentence split (good enough for v1, deterministic)
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    return [p.strip() for p in parts if p.strip()]


def cluster_hits(text_norm: str, clusters: List[List[str]], sentences: List[str]) -> Tuple[int, List[str]]:
    """
    returns: (clusters_satisfied_count, evidence_sentences)
    A cluster is satisfied if ANY phrase appears in text.
    Evidence: first matching sentence for each satisfied cluster.
    """
    hit_count = 0
    evidence = []

    for cluster in clusters or []:
        if not isinstance(cluster, list):
            continue

        found = False
        for phrase in cluster:
            if not isinstance(phrase, str) or not phrase:
                continue
            p = phrase.lower()
            if p in text_norm:
                found = True
                # capture a sentence containing it
                for s in sentences:
                    if p in normalise(s):
                        evidence.append(s)
                        break
                break

        if found:
            hit_count += 1

    return hit_count, evidence


def phrase_hits(text_norm: str, phrases: List[str], sentences: List[str]) -> Tuple[int, List[str]]:
    """
    returns: (hit_count, evidence_sentences)
    Evidence: sentences that contain any matched phrase (first 3 max).
    """
    hits = 0
    evidence = []

    for phrase in phrases or []:
        if not isinstance(phrase, str) or not phrase:
            continue
        p = phrase.lower()
        if p in text_norm:
            hits += 1
            for s in sentences:
                if p in normalise(s):
                    evidence.append(s)
                    break

    # keep it short/deterministic
    uniq = []
    for s in evidence:
        if s not in uniq:
            uniq.append(s)
    return hits, uniq[:3]


def check_condition(value: int, cond: str) -> bool:
    cond = (cond or "").strip()
    if cond.startswith(">="):
        return value >= int(cond[2:])
    if cond.startswith("<="):
        return value <= int(cond[2:])
    if cond.startswith("=="):
        return value == int(cond[2:])
    raise ValueError(f"Unsupported condition: {cond}")


def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    returns: dict with status + evidence sentences
    """
    applies_when = rule.get("applies_when") or {}

    # applicability: all keys must match
    for k, expected in applies_when.items():
        if context.get(k) != expected:
            return {"status": "NOT_ASSESSED", "evidence": []}

    evidence_cfg = rule.get("evidence") or {}
    decision = (rule.get("decision_logic") or {}).get("ok_if") or {}

    text_norm = normalise(text)
    sentences = split_sentences(text)

    counts: Dict[str, int] = {}
    evidence_out: List[Dict[str, str]] = []

    # positive_clusters: list[list[str]]
    if "positive_clusters" in evidence_cfg:
        c, ev = cluster_hits(text_norm, evidence_cfg.get("positive_clusters") or [], sentences)
        counts["positive_clusters"] = c
        for s in ev[:3]:
            evidence_out.append({"type": "positive", "sentence": s})

    # linkage_indicators: list[str]
    if "linkage_indicators" in evidence_cfg:
        c, ev = phrase_hits(text_norm, evidence_cfg.get("linkage_indicators") or [], sentences)
        counts["linkage_indicators"] = c
        for s in ev[:3]:
            evidence_out.append({"type": "linkage", "sentence": s})

    # contextual_indicators: list[str]
    if "contextual_indicators" in evidence_cfg:
        c, ev = phrase_hits(text_norm, evidence_cfg.get("contextual_indicators") or [], sentences)
        counts["contextual_indicators"] = c
        for s in ev[:3]:
            evidence_out.append({"type": "context", "sentence": s})

    # negative_indicators: list[str]
    if "negative_indicators" in evidence_cfg:
        c, ev = phrase_hits(text_norm, evidence_cfg.get("negative_indicators") or [], sentences)
        counts["negative_indicators"] = c
        for s in ev[:3]:
            evidence_out.append({"type": "negative", "sentence": s})

    # decision logic: every condition must pass
    for key, cond in decision.items():
        val = int(counts.get(key, 0))
        if not check_condition(val, cond):
            return {"status": "POTENTIAL_ISSUE", "evidence": evidence_out}

    return {"status": "OK", "evidence": evidence_out}


def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str = "rules/cobs-suitability-v1.yaml",
) -> Dict[str, Any]:

    with open(rules_path, "r", encoding="utf-8") as f:
        ruleset = yaml.safe_load(f) or {}

    ruleset_meta = ruleset.get("ruleset") or {}
    rules = ruleset.get("rules") or []
    sections_map = ruleset.get("sections") or {}

    results = []
    for rule in rules:
        evaluation = evaluate_rule(rule, document_text, context)

        results.append({
            "rule_id": rule.get("id"),
            "section": rule.get("section"),
            "title": rule.get("title"),
            "status": evaluation["status"],
            "citation": rule.get("citation"),
            "source_url": rule.get("source_url"),
            "evidence": evaluation.get("evidence", []),
        })

    # group into sections for accordion rendering
    grouped: Dict[str, Dict[str, Any]] = {}
    for r in results:
        sec = r.get("section") or "OTHER"
        if sec not in grouped:
            grouped[sec] = {
                "section_id": sec,
                "title": sections_map.get(sec, sec),
                "rules": []
            }
        grouped[sec]["rules"].append(r)

    sections = list(grouped.values())

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset_meta.get("id"),
        "ruleset_version": ruleset_meta.get("version"),
        "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "summary": summary,
        "sections": sections,
    }
