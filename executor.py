import re
import yaml
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


EXECUTOR_VERSION = "2026-02-24-negation-v1"


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def split_sentences(text: str) -> List[str]:
    # Deterministic sentence splitter
    parts = re.split(r"(?<=[.!?])\s+", (text or "").strip())
    return [p.strip() for p in parts if p.strip()]


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _context_matches(applies_when: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    applies_when supports scalar or list values.
    Example:
      applies_when:
        advice_type: advised
    or
      applies_when:
        advice_type: [advised, standard]
    """
    for k, v in (applies_when or {}).items():
        allowed = _as_list(v)
        if context.get(k) not in allowed:
            return False
    return True


# -----------------------------
# MATCHING (NEGATION-AWARE)
# -----------------------------

DEFAULT_NEGATION_PATTERNS = [
    r"\bno\s+{PHRASE}\b",
    r"\bnot\s+{PHRASE}\b",
    r"\bnever\s+{PHRASE}\b",
    r"\bwithout\s+{PHRASE}\b",
    r"\bthere\s+are\s+no\s+{PHRASE}\b",
    r"\bthere\s+is\s+no\s+{PHRASE}\b",
]

def _compile_phrase_re(phrase: str) -> re.Pattern:
    # word-boundary-ish matching; keeps it simple but avoids mid-word hits
    p = re.escape(phrase.strip().lower())
    return re.compile(rf"(^|[^a-z0-9]){p}([^a-z0-9]|$)")

def _is_negated(sentence_lc: str, phrase_lc: str, patterns: List[str]) -> bool:
    # Expand patterns where {PHRASE} becomes a safe regex for the phrase words
    phrase_rx = re.escape(phrase_lc)
    for pat in patterns:
        rx = pat.replace("{PHRASE}", phrase_rx)
        if re.search(rx, sentence_lc):
            return True
    return False


def find_hits(
    sentences: List[str],
    phrases: List[str],
    *,
    negation_aware: bool,
    negation_patterns: Optional[List[str]] = None
) -> List[Tuple[str, str]]:
    """
    Returns list of (matched_phrase, sentence) where the phrase appears.
    If negation_aware=True, excludes hits where the sentence negates the phrase.
    """
    negation_patterns = negation_patterns or DEFAULT_NEGATION_PATTERNS
    out: List[Tuple[str, str]] = []

    compiled = []
    for ph in phrases:
        if not isinstance(ph, str):
            continue
        ph_lc = ph.strip().lower()
        if not ph_lc:
            continue
        compiled.append((ph, ph_lc, _compile_phrase_re(ph)))

    for sent in sentences:
        sent_lc = sent.lower()
        for ph_raw, ph_lc, ph_re in compiled:
            if not ph_re.search(sent_lc):
                continue
            if negation_aware and _is_negated(sent_lc, ph_lc, negation_patterns):
                continue
            out.append((ph_raw, sent))
    return out


def build_evidence_snippets(
    hits: List[Tuple[str, str]],
    *,
    cap: int = 5
) -> List[str]:
    # Deduplicate by sentence (keep stable-ish order)
    seen = set()
    snippets: List[str] = []
    for _phrase, sent in hits:
        key = sent.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        snippets.append(key)
        if len(snippets) >= cap:
            break
    return snippets


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})
    if not _context_matches(applies_when, context):
        return {"status": "NOT_ASSESSED", "evidence": []}

    sentences = split_sentences(text)

    # Rule “mode”
    # - presence: OK if positive hits >= min_hits else POTENTIAL_ISSUE
    # - prohibited: POTENTIAL_ISSUE if prohibited hits > 0 else OK
    mode = (rule.get("mode") or "presence").strip().lower()

    min_hits = int(rule.get("min_hits", 1) or 1)
    evidence_cap = int(rule.get("evidence_cap", 5) or 5)

    # Positive phrases
    positive_phrases = _as_list(rule.get("phrases"))
    positive_hits = find_hits(
        sentences,
        positive_phrases,
        negation_aware=False
    )

    # Prohibited phrases (negation-aware by default)
    prohibited_phrases = _as_list(rule.get("prohibited_phrases"))
    prohibited_negation_aware = bool(rule.get("prohibited_negation_aware", True))
    prohibited_negation_patterns = rule.get("prohibited_negation_patterns")
    prohibited_hits = find_hits(
        sentences,
        prohibited_phrases,
        negation_aware=prohibited_negation_aware,
        negation_patterns=_as_list(prohibited_negation_patterns) or None
    )

    # Decide
    if mode == "prohibited":
        if len(prohibited_hits) > 0:
            return {
                "status": "POTENTIAL_ISSUE",
                "evidence": build_evidence_snippets(prohibited_hits, cap=evidence_cap),
                "meta": {"trigger": "prohibited_phrases", "executor_version": EXECUTOR_VERSION},
            }
        return {
            "status": "OK",
            "evidence": build_evidence_snippets(positive_hits, cap=evidence_cap),
            "meta": {"trigger": "no_prohibited_hits", "executor_version": EXECUTOR_VERSION},
        }

    # Default: presence
    if len(positive_hits) >= min_hits:
        return {
            "status": "OK",
            "evidence": build_evidence_snippets(positive_hits, cap=evidence_cap),
            "meta": {"trigger": "phrases", "executor_version": EXECUTOR_VERSION},
        }

    return {
        "status": "POTENTIAL_ISSUE",
        "evidence": build_evidence_snippets(positive_hits, cap=evidence_cap),
        "meta": {"trigger": "missing_required_phrases", "executor_version": EXECUTOR_VERSION},
    }


# -----------------------------
# EXECUTOR ENTRY POINT
# -----------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str,
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f) or {}

    rules = ruleset.get("rules", [])
    ruleset_id = ruleset.get("ruleset_id", "unknown")
    version = ruleset.get("version", "unknown")

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section", "Unsectioned")
        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule.get("id", "UNKNOWN_RULE"),
            "title": rule.get("title", ""),
            "status": outcome.get("status", "NOT_ASSESSED"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url"),  # optional
            "evidence": outcome.get("evidence", []),
        })

    summary = {
        "ok": sum(1 for s in grouped.values() for r in s if r["status"] == "OK"),
        "potential_issue": sum(1 for s in grouped.values() for r in s if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for s in grouped.values() for r in s if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset_id,
        "ruleset_version": version,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": grouped,
    }