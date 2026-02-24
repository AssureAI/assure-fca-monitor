import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences(text: str) -> List[str]:
    """
    Deterministic sentence splitter.
    Keeps it simple: split on punctuation + whitespace.
    """
    t = (text or "").strip()
    if not t:
        return []
    parts = re.split(r"(?<=[.!?])\s+", t)
    return [p.strip() for p in parts if p and p.strip()]


def _is_str(x: Any) -> bool:
    return isinstance(x, str)


def _as_str_list(value: Any) -> List[str]:
    """
    Coerce YAML-provided values into a safe list[str].
    - "foo" -> ["foo"]
    - ["foo","bar"] -> ["foo","bar"]
    - [["a","b"],["c"]] -> ["a","b","c"]  (flatten safely)
    - None/other -> []
    """
    if value is None:
        return []
    if _is_str(value):
        return [value]
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            if _is_str(item):
                out.append(item)
            elif isinstance(item, list):
                for sub in item:
                    if _is_str(sub):
                        out.append(sub)
        return out
    return []


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def phrase_hits(sentences: List[str], phrases: List[str]) -> List[Tuple[str, str]]:
    """
    Returns list of (matched_phrase, sentence_text)
    """
    hits: List[Tuple[str, str]] = []
    if not sentences or not phrases:
        return hits

    safe_phrases = [p for p in phrases if isinstance(p, str) and p.strip()]
    if not safe_phrases:
        return hits

    for sent in sentences:
        s_norm = (sent or "").lower()
        if not s_norm:
            continue
        for p in safe_phrases:
            p_norm = p.lower()
            if p_norm and p_norm in s_norm:
                hits.append((p, sent))
    return hits


def cluster_hits(sentences: List[str], clusters: List[List[str]]) -> Tuple[int, List[Tuple[str, str]]]:
    """
    A cluster is "hit" if ANY phrase in the cluster appears in ANY sentence.
    Returns: (clusters_hit_count, evidence_hits)
    """
    if not sentences or not clusters:
        return 0, []

    clusters_hit = 0
    evidence: List[Tuple[str, str]] = []

    for cluster in clusters:
        cl = [p for p in _as_str_list(cluster) if p.strip()]
        hits = phrase_hits(sentences, cl)
        if hits:
            clusters_hit += 1
            evidence.extend(hits)

    return clusters_hit, evidence


# -----------------------------
# APPLICABILITY
# -----------------------------

def applies_when_ok(applies_when: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Applies_when supports:
      key: "advised"
      key: ["advised","standard"]
      key: true/false
    """
    for key, expected in (applies_when or {}).items():
        actual = context.get(key)

        # list expected
        if isinstance(expected, list):
            if actual not in expected:
                return False
            continue

        # bool expected
        if isinstance(expected, bool):
            if bool(actual) != expected:
                return False
            continue

        # string/number expected
        if actual != expected:
            return False

    return True


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns:
      {
        status: "OK"|"POTENTIAL_ISSUE"|"NOT_ASSESSED",
        evidence: { matched_phrases: [...], snippets: [...] }
      }
    """
    if not applies_when_ok(rule.get("applies_when", {}), context):
        return {"status": "NOT_ASSESSED", "evidence": {"matched_phrases": [], "snippets": []}}

    sentences = split_sentences(text)
    text_norm = normalise(text)

    checks = rule.get("checks", [])
    if not isinstance(checks, list):
        checks = []

    # Collect evidence across checks
    matched_phrases: List[str] = []
    matched_snippets: List[str] = []

    # Defaults (can be overridden per-rule)
    max_snippets = int(rule.get("evidence_policy", {}).get("max_snippets", 3))
    max_phrases = int(rule.get("evidence_policy", {}).get("max_phrases", 10))

    def add_evidence(hits: List[Tuple[str, str]]):
        nonlocal matched_phrases, matched_snippets
        for ph, sent in hits:
            if isinstance(ph, str) and ph.strip():
                matched_phrases.append(ph.strip())
            if isinstance(sent, str) and sent.strip():
                matched_snippets.append(sent.strip())

    # Evaluate all checks; if any check fails => POTENTIAL_ISSUE
    for check in checks:
        if not isinstance(check, dict):
            continue

        op = check.get("op")
        if not isinstance(op, str):
            continue

        # --- contains_any
        if op == "contains_any":
            phrases = _as_str_list(check.get("phrases"))
            min_hits = int(check.get("min_hits", 1))
            hits = phrase_hits(sentences, phrases)
            add_evidence(hits)
            if len(hits) < min_hits:
                return _finalise("POTENTIAL_ISSUE", matched_phrases, matched_snippets, max_phrases, max_snippets)

        # --- contains_none (i.e., must NOT appear)
        elif op == "contains_none":
            phrases = _as_str_list(check.get("phrases"))
            hits = phrase_hits(sentences, phrases)
            add_evidence(hits)
            if len(hits) > 0:
                return _finalise("POTENTIAL_ISSUE", matched_phrases, matched_snippets, max_phrases, max_snippets)

        # --- clusters_min (clusters are list[list[str]])
        elif op == "clusters_min":
            clusters = check.get("clusters", [])
            if not isinstance(clusters, list):
                clusters = []
            min_clusters = int(check.get("min_clusters", 1))
            hit_count, hits = cluster_hits(sentences, clusters)  # clusters hit
            add_evidence(hits)
            if hit_count < min_clusters:
                return _finalise("POTENTIAL_ISSUE", matched_phrases, matched_snippets, max_phrases, max_snippets)

        # --- text_contains (raw normalised text contains tokens; faster + crude)
        elif op == "text_contains":
            tokens = _as_str_list(check.get("tokens"))
            min_hits = int(check.get("min_hits", 1))
            count = sum(1 for t in tokens if isinstance(t, str) and t.lower() in text_norm)
            # evidence for this is just the token list; no sentence linking
            matched_phrases.extend([t for t in tokens if isinstance(t, str) and t.lower() in text_norm])
            if count < min_hits:
                return _finalise("POTENTIAL_ISSUE", matched_phrases, matched_snippets, max_phrases, max_snippets)

        # Unknown op => ignore (don’t crash)
        else:
            continue

    return _finalise("OK", matched_phrases, matched_snippets, max_phrases, max_snippets)


def _finalise(status: str, phrases: List[str], snippets: List[str], max_phrases: int, max_snippets: int) -> Dict[str, Any]:
    phrases_out = _dedupe_preserve_order([p for p in phrases if isinstance(p, str) and p.strip()])[:max_phrases]
    snippets_out = _dedupe_preserve_order([s for s in snippets if isinstance(s, str) and s.strip()])[:max_snippets]
    return {
        "status": status,
        "evidence": {
            "matched_phrases": phrases_out,
            "snippets": snippets_out,
        }
    }


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str,
) -> Dict[str, Any]:

    with open(rules_path, "r", encoding="utf-8") as f:
        ruleset = yaml.safe_load(f) or {}

    # Backward compatibility / resilience
    ruleset_id = ruleset.get("ruleset_id", "unknown-ruleset")
    version = ruleset.get("version", "0.0")
    rules = ruleset.get("rules", [])
    if not isinstance(rules, list):
        rules = []

    # Grouping in a stable, ordered list
    sections_order = ruleset.get("sections_order", [])
    if not isinstance(sections_order, list):
        sections_order = []

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section", "Unsorted")
        if not isinstance(section, str) or not section.strip():
            section = "Unsorted"

        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule.get("id", "UNKNOWN"),
            "title": rule.get("title", ""),
            "status": outcome["status"],
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", ""),  # OPTIONAL: never crash if missing
            "evidence": outcome.get("evidence", {"matched_phrases": [], "snippets": []}),
        })

    # Build sections list in an order the UI can rely on
    ordered_section_names = []
    # 1) explicit order first
    for s in sections_order:
        if isinstance(s, str) and s in grouped:
            ordered_section_names.append(s)
    # 2) then everything else alphabetically
    for s in sorted(grouped.keys()):
        if s not in ordered_section_names:
            ordered_section_names.append(s)

    sections_out = []
    for s in ordered_section_names:
        rules_list = grouped.get(s, [])
        counts = {
            "ok": sum(1 for r in rules_list if r["status"] == "OK"),
            "potential_issue": sum(1 for r in rules_list if r["status"] == "POTENTIAL_ISSUE"),
            "not_assessed": sum(1 for r in rules_list if r["status"] == "NOT_ASSESSED"),
        }
        sections_out.append({
            "section": s,
            "summary": counts,
            "rules": rules_list,
        })

    summary = {
        "ok": sum(sec["summary"]["ok"] for sec in sections_out),
        "potential_issue": sum(sec["summary"]["potential_issue"] for sec in sections_out),
        "not_assessed": sum(sec["summary"]["not_assessed"] for sec in sections_out),
    }

    return {
        "ruleset_id": ruleset_id,
        "ruleset_version": version,
        "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "summary": summary,
        "sections": sections_out,
    }
    
