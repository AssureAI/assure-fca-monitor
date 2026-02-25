# executor.py
import re
import yaml
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional


EXECUTOR_VERSION = "2026-02-24-v3-reason-missing-negation"


# -----------------------------
# TEXT HELPERS
# -----------------------------

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def split_sentences(text: str) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    parts = re.split(r"(?<=[.!?])\s+", t)
    return [p.strip() for p in parts if p and p.strip()]


def _flatten_phrases(x: Any) -> List[str]:
    """
    YAML sometimes ends up nested (lists inside lists). This makes phrase matching safe.
    """
    out: List[str] = []
    if x is None:
        return out
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        for item in x:
            out.extend(_flatten_phrases(item))
        return out
    # anything else -> ignore
    return out


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for s in items:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _cap_snippet(s: str, limit: int = 240) -> str:
    s = re.sub(r"\s+", " ", (s or "")).strip()
    if len(s) <= limit:
        return s
    return s[: limit - 1].rstrip() + "…"


NEGATION_TOKENS = [
    "no",
    "not",
    "never",
    "without",
    "cannot",
    "can't",
    "do not",
    "does not",
    "is not",
    "isn't",
    "aren't",
    "are not",
    "non",
    "none",
]


def _is_negated(sentence_norm: str, match_start: int, window: int = 35) -> bool:
    """
    If there is negation language near the hit, treat as *allowed* (not a breach).
    """
    left = max(0, match_start - window)
    context = sentence_norm[left:match_start]
    return any(tok in context for tok in NEGATION_TOKENS)


def find_hits(sentences: List[str], phrases: List[str]) -> Tuple[List[str], List[str]]:
    """
    Returns (matched_sentences, matched_phrases)
    """
    phrases = [p for p in _flatten_phrases(phrases) if isinstance(p, str) and p.strip()]
    if not phrases or not sentences:
        return [], []

    matched_sents: List[str] = []
    matched_phrases: List[str] = []

    for sent in sentences:
        s_norm = _norm(sent)
        for p in phrases:
            p_norm = _norm(p)
            if not p_norm:
                continue
            if p_norm in s_norm:
                matched_sents.append(sent)
                matched_phrases.append(p)
    return matched_sents, matched_phrases


def find_forbidden_hits(
    sentences: List[str],
    forbidden_phrases: List[str],
    allow_negation: bool = True,
) -> Tuple[List[str], List[str]]:
    """
    Returns forbidden hits that are NOT negated (if allow_negation=True).
    """
    forbidden_phrases = [p for p in _flatten_phrases(forbidden_phrases) if isinstance(p, str) and p.strip()]
    if not forbidden_phrases or not sentences:
        return [], []

    bad_sents: List[str] = []
    bad_phrases: List[str] = []

    for sent in sentences:
        s_norm = _norm(sent)
        for p in forbidden_phrases:
            p_norm = _norm(p)
            if not p_norm:
                continue
            idx = s_norm.find(p_norm)
            if idx == -1:
                continue
            if allow_negation and _is_negated(s_norm, idx):
                # e.g. "There are no guaranteed returns" -> allowed
                continue
            bad_sents.append(sent)
            bad_phrases.append(p)

    return bad_sents, bad_phrases


# -----------------------------
# APPLIES_WHEN
# -----------------------------

def applies_when_ok(applies_when: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Supports:
      applies_when:
        advice_type: advised
      or
        advice_type: [advised, nonadvised]
      or
        vulnerable: true
    """
    if not applies_when:
        return True

    for k, expected in applies_when.items():
        actual = context.get(k)

        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False

    return True


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], document_text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies_when_ok(rule.get("applies_when", {}), context):
        return {
            "status": "NOT_ASSESSED",
            "reason": "Rule does not apply to this context.",
            "evidence_snippets": [],
            "matched_terms": [],
            "missing_terms": [],
        }

    sentences = split_sentences(document_text)

    # required / positive evidence
    required_phrases = _flatten_phrases(rule.get("phrases", []))
    min_hits = int(rule.get("min_hits", 1) or 1)

    # forbidden / negative evidence
    forbidden_phrases = _flatten_phrases(rule.get("forbidden_phrases", []))
    allow_negation = bool(rule.get("forbidden_allow_negation", True))

    # 1) forbidden check FIRST (if present)
    if forbidden_phrases:
        bad_sents, bad_terms = find_forbidden_hits(
            sentences,
            forbidden_phrases,
            allow_negation=allow_negation,
        )
        bad_sents = _dedupe_preserve_order([_cap_snippet(s) for s in bad_sents])[:5]
        bad_terms = sorted(set([t for t in bad_terms if t]))

        if bad_sents:
            return {
                "status": "POTENTIAL_ISSUE",
                "reason": rule.get("forbidden_reason") or "Potentially misleading / prohibited language detected.",
                "evidence_snippets": bad_sents,
                "matched_terms": bad_terms,
                "missing_terms": [],
            }

    # 2) required evidence check
    matched_sents, matched_terms = find_hits(sentences, required_phrases)
    matched_sents = _dedupe_preserve_order([_cap_snippet(s) for s in matched_sents])[:5]
    matched_terms_set = sorted(set([t for t in matched_terms if t]))

    if len(matched_sents) >= min_hits:
        return {
            "status": "OK",
            "reason": rule.get("ok_reason") or "Required content found.",
            "evidence_snippets": matched_sents,
            "matched_terms": matched_terms_set,
            "missing_terms": [],
        }

    # Missing-content failure (no “offending snippet” exists)
    missing_terms = sorted(set([p for p in required_phrases if isinstance(p, str) and p.strip()]))
    return {
        "status": "POTENTIAL_ISSUE",
        "reason": rule.get("missing_reason") or "Required content not found.",
        "evidence_snippets": matched_sents,  # may be empty; UI should still expand + show reason
        "matched_terms": matched_terms_set,
        "missing_terms": missing_terms,
    }


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(document_text: str, context: Dict[str, Any], rules_path: str) -> Dict[str, Any]:
    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f) or {}

    rules = ruleset.get("rules", []) or []

    sections: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section") or "Unsorted"
        sections.setdefault(section, [])

        sections[section].append(
            {
                "rule_id": rule.get("id"),
                "title": rule.get("title") or "",
                "status": outcome["status"],
                "reason": outcome.get("reason", ""),
                "citation": rule.get("citation") or "",
                "source_url": rule.get("source_url") or "",
                "evidence_snippets": outcome.get("evidence_snippets", []) or [],
                "matched_terms": outcome.get("matched_terms", []) or [],
                "missing_terms": outcome.get("missing_terms", []) or [],
            }
        )

    ok = sum(1 for sec in sections.values() for r in sec if r["status"] == "OK")
    pi = sum(1 for sec in sections.values() for r in sec if r["status"] == "POTENTIAL_ISSUE")
    na = sum(1 for sec in sections.values() for r in sec if r["status"] == "NOT_ASSESSED")

    return {
        "ruleset_id": ruleset.get("ruleset_id") or ruleset.get("id") or "unknown",
        "ruleset_version": ruleset.get("version") or "unknown",
        "executor_version": EXECUTOR_VERSION,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": {"ok": ok, "potential_issue": pi, "not_assessed": na},
        "sections": sections,
    }