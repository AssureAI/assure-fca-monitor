import os
import re
import yaml
from datetime import datetime
from typing import Any, Dict, List, Tuple


# ---------------------------------
# NORMALISATION + SENTENCE SPLIT
# ---------------------------------

_WS_RE = re.compile(r"\s+")
_SENT_RE = re.compile(r"(?<=[.!?])\s+")

def normalise(text: str) -> str:
    return _WS_RE.sub(" ", (text or "").strip())

def split_sentences(text: str) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    parts = _SENT_RE.split(t)
    return [p.strip() for p in parts if p and p.strip()]


# ---------------------------------
# MATCHING HELPERS (DETERMINISTIC)
# ---------------------------------

_NEGATION_TOKENS = {
    "not", "no", "never", "without", "none", "cannot", "can't",
    "isn't", "aren't", "won't", "don't", "doesn't", "didn't"
}

def _tokenise(s: str) -> List[str]:
    return re.findall(r"[a-zA-Z']+", (s or "").lower())

def _is_negated(sentence: str, phrase: str, window_tokens: int = 4) -> bool:
    """
    True if phrase appears and a negation token appears within N tokens immediately before it.
    Prevents false flags like "there are no guaranteed returns".
    """
    s_low = (sentence or "").lower()
    p_low = (phrase or "").lower().strip()
    if not p_low or p_low not in s_low:
        return False

    tokens = _tokenise(sentence)
    p_tokens = _tokenise(phrase)
    if not p_tokens:
        return False

    for i in range(len(tokens) - len(p_tokens) + 1):
        if tokens[i:i + len(p_tokens)] == p_tokens:
            start = max(0, i - window_tokens)
            prior = tokens[start:i]
            if any(t in _NEGATION_TOKENS for t in prior):
                return True
    return False

def _flatten_phrases(phrases: Any) -> List[str]:
    """
    Allow phrases to be: list[str] or accidentally list[list[str]].
    Ignore non-strings deterministically.
    """
    flat: List[str] = []
    if isinstance(phrases, list):
        for p in phrases:
            if isinstance(p, str):
                flat.append(p)
            elif isinstance(p, list):
                for pp in p:
                    if isinstance(pp, str):
                        flat.append(pp)
    elif isinstance(phrases, str):
        flat.append(phrases)
    return flat

def phrase_hits(
    sentences: List[str],
    phrases: Any,
    *,
    allow_if_negated: bool,
    max_evidence: int = 6,
) -> Tuple[int, List[str], List[str]]:
    """
    Returns: (unique_phrase_match_count, matched_phrases, evidence_sentences)
    """
    matched = set()
    evidence: List[str] = []
    seen = set()

    flat = _flatten_phrases(phrases)

    for sent in sentences:
        s_low = sent.lower()
        for p in flat:
            p_low = (p or "").lower().strip()
            if not p_low:
                continue
            if p_low in s_low:
                # For prohibited/negative lists, drop matches if they are negated in-text
                if (not allow_if_negated) and _is_negated(sent, p):
                    continue
                matched.add(p)
                if len(evidence) < max_evidence and sent not in seen:
                    evidence.append(sent)
                    seen.add(sent)

    return len(matched), sorted(matched), evidence

def cluster_hits(
    sentences: List[str],
    clusters: Any,
    *,
    allow_if_negated: bool,
    max_evidence: int = 6,
) -> Tuple[int, List[str], List[str]]:
    """
    A cluster is satisfied if ANY phrase in that cluster hits.
    Returns satisfied_cluster_count, matched_phrases, evidence.
    """
    if not isinstance(clusters, list):
        return 0, [], []

    satisfied = 0
    matched = set()
    evidence: List[str] = []
    seen = set()

    for cluster in clusters:
        if not isinstance(cluster, list):
            continue
        hit_n, phrases, ev = phrase_hits(
            sentences,
            cluster,
            allow_if_negated=allow_if_negated,
            max_evidence=max_evidence,
        )
        if hit_n > 0:
            satisfied += 1
            for p in phrases:
                matched.add(p)
            for s in ev:
                if len(evidence) < max_evidence and s not in seen:
                    evidence.append(s)
                    seen.add(s)

    return satisfied, sorted(matched), evidence


# ---------------------------------
# APPLICABILITY
# ---------------------------------

def applies(rule_applies_when: Any, context: Dict[str, Any]) -> bool:
    """
    applies_when:
      advice_type: advised OR [advised, nonadvised]
      investment_element: true/false (bools in your ctx)
      ongoing_service: true/false (bools in your ctx)
    """
    if not rule_applies_when:
        return True
    if not isinstance(rule_applies_when, dict):
        return False

    for key, expected in rule_applies_when.items():
        actual = context.get(key)

        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False

    return True


# ---------------------------------
# DECISION LOGIC (YAML SCHEMA)
# ---------------------------------

_THRESH_RE = re.compile(r"^\s*(>=|==|<=|>|<)\s*(\d+)\s*$")

def _parse_threshold(expr: Any) -> Tuple[str, int]:
    """
    YAML uses strings like ">=2" or ">0".
    """
    if not isinstance(expr, str):
        return ("==", 0)
    m = _THRESH_RE.match(expr.strip())
    if not m:
        return ("==", 0)
    return (m.group(1), int(m.group(2)))

def _cmp(op: str, actual: int, target: int) -> bool:
    if op == ">=":
        return actual >= target
    if op == "==":
        return actual == target
    if op == "<=":
        return actual <= target
    if op == ">":
        return actual > target
    if op == "<":
        return actual < target
    return False

def _eval_require_block(counts: Dict[str, int], req: Any) -> Tuple[bool, List[str]]:
    """
    req is a dict like:
      positive_clusters: ">=2"
      linkage_indicators: ">=1"
    """
    if not req:
        return True, []

    if not isinstance(req, dict):
        return False, ["Decision logic malformed (expected dict)."]

    failed: List[str] = []
    for key, expr in req.items():
        op, target = _parse_threshold(expr)
        actual = int(counts.get(key, 0))
        if not _cmp(op, actual, target):
            failed.append(f"{key} {op}{target} (actual={actual})")
    return (len(failed) == 0), failed


# ---------------------------------
# RULE EVALUATION
# ---------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies(rule.get("applies_when", {}) or {}, context):
        return {
            "status": "NOT_ASSESSED",
            "why": "Rule not applicable for current context.",
            "evidence": [],
            "missing": [],
            "details": [],
        }

    sentences = split_sentences(text)

    evidence_spec = rule.get("evidence", {}) or {}
    decision = rule.get("decision_logic", {}) or {}

    # counts bucket
    counts: Dict[str, int] = {}
    matched_phrases_all = set()
    evidence_sentences: List[str] = []
    evidence_seen = set()

    def merge(phrases: List[str], ev_sents: List[str], cap: int = 6) -> None:
        for p in phrases:
            matched_phrases_all.add(p)
        for s in ev_sents:
            if len(evidence_sentences) >= cap:
                break
            if s not in evidence_seen:
                evidence_sentences.append(s)
                evidence_seen.add(s)

    # Extract evidence counts
    if isinstance(evidence_spec, dict):
        for key, spec in evidence_spec.items():
            if key.endswith("_clusters"):
                hit_n, phrases, ev = cluster_hits(
                    sentences,
                    spec,
                    allow_if_negated=True,   # positive signals
                    max_evidence=6,
                )
                counts[key] = hit_n
                merge(phrases, ev, cap=6)
            else:
                # for "bad language" keys, ignore matches if negated
                allow_if_negated = True
                if key in ("negative_indicators", "prohibited_phrases", "must_not_contain"):
                    allow_if_negated = False

                hit_n, phrases, ev = phrase_hits(
                    sentences,
                    spec,
                    allow_if_negated=allow_if_negated,
                    max_evidence=6,
                )
                counts[key] = hit_n
                merge(phrases, ev, cap=6)

    # Strict philosophy: absence of evidence != compliance
    total_hits = sum(int(v) for v in counts.values())
    if total_hits == 0:
        return {
            "status": "POTENTIAL_ISSUE",
            "why": "No indicators matched for this rule (no evidence).",
            "counts": counts,
            "evidence": [],
            "missing": ["All required signals (none matched)"],
            "details": [],
            "matched_phrases": [],
        }

    # Evaluate decision logic blocks
    req_all = decision.get("require_all", None)
    req_none = decision.get("require_none", None)
    allow_if_present = decision.get("allow_if_present", None)

    ok_all, failed_all = _eval_require_block(counts, req_all)
    ok_none, failed_none = _eval_require_block(
        # require_none means "condition should be FALSE" in human terms,
        # but YAML expresses it as e.g. prohibited_phrases: ">0"
        # So we treat it as: must NOT satisfy threshold.
        counts,
        req_none
    )

    # Convert require_none evaluation:
    # If req_none says ">0" and actual is 1, _eval_require_block returns True,
    # but that means it's BAD. So invert.
    none_violations: List[str] = []
    if req_none and isinstance(req_none, dict):
        for key, expr in req_none.items():
            op, target = _parse_threshold(expr)
            actual = int(counts.get(key, 0))
            if _cmp(op, actual, target):
                none_violations.append(f"{key} violated (actual={actual} matched {op}{target})")
        ok_none = (len(none_violations) == 0)

    # Allow-if-present safe harbour:
    # If allow_if_present conditions are met, we allow the rule to pass even if require_none is violated.
    allow_ok = False
    allow_failures: List[str] = []
    if allow_if_present:
        allow_ok, allow_failures = _eval_require_block(counts, allow_if_present)

    details: List[str] = []
    missing: List[str] = []

    if req_all:
        if ok_all:
            details.append("require_all satisfied.")
        else:
            details.append("require_all failed: " + "; ".join(failed_all))
            missing.extend(failed_all)

    if req_none:
        if ok_none:
            details.append("require_none satisfied (no prohibited triggers).")
        else:
            details.append("require_none failed: " + "; ".join(none_violations))
            missing.extend(none_violations)

    if allow_if_present:
        if allow_ok:
            details.append("allow_if_present satisfied (safe harbour).")
        else:
            details.append("allow_if_present not satisfied: " + "; ".join(allow_failures))

    # Final decision
    # - Must pass require_all (if present)
    # - Must pass require_none (if present) UNLESS allow_if_present satisfied
    status_ok = True

    if req_all and not ok_all:
        status_ok = False

    if req_none and not ok_none and not allow_ok:
        status_ok = False

    status = "OK" if status_ok else "POTENTIAL_ISSUE"

    # Evidence still required for OK (you demanded this behaviour)
    if status == "OK" and len(evidence_sentences) == 0:
        status = "POTENTIAL_ISSUE"
        details.append("Downgraded: OK conditions met but no evidence snippets captured.")

    why = "OK" if status == "OK" else "Conditions not met."

    return {
        "status": status,
        "why": why,
        "counts": counts,
        "evidence": evidence_sentences[:6],
        "missing": missing[:20],
        "details": details[:50],
        "matched_phrases": sorted(matched_phrases_all)[:40],
    }


# ---------------------------------
# RULESET LOAD (ENV OVERRIDE + FALLBACK)
# ---------------------------------

def _resolve_rules_path(default_path: str) -> str:
    """
    1) RULES_PATH env var overrides
    2) use provided/default if exists
    3) fallback to v1 if missing
    """
    path = os.environ.get("RULES_PATH", default_path)

    if os.path.exists(path):
        return path

    fallback = "rules/cobs-suitability-v1.yaml"
    if os.path.exists(fallback):
        return fallback

    # also try ./rules/... in case cwd differs
    if os.path.exists("./" + path):
        return "./" + path
    if os.path.exists("./" + fallback):
        return "./" + fallback

    raise FileNotFoundError(f"Rules file not found: {path} (fallback missing too: {fallback})")

def _load_ruleset(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


# ---------------------------------
# EXECUTOR ENTRY POINT
# ---------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str = "rules/cobs-suitability-v1.yaml",
) -> Dict[str, Any]:

    resolved_path = _resolve_rules_path(rules_path)
    ruleset = _load_ruleset(resolved_path)

    rules = ruleset.get("rules", [])
    if not isinstance(rules, list):
        rules = []

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section") or "Unsorted"
        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "status": outcome.get("status", "POTENTIAL_ISSUE"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", "") or "",
            "why": outcome.get("why", ""),
            "evidence": outcome.get("evidence", []),
            "missing": outcome.get("missing", []),
            "details": outcome.get("details", []),
        })

    # stable ordering
    for s in list(grouped.keys()):
        grouped[s] = sorted(grouped[s], key=lambda r: (r.get("rule_id") or ""))

    summary = {
        "ok": sum(1 for sec in grouped.values() for r in sec if r.get("status") == "OK"),
        "potential_issue": sum(1 for sec in grouped.values() for r in sec if r.get("status") == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for sec in grouped.values() for r in sec if r.get("status") == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id", "unknown-ruleset"),
        "ruleset_version": ruleset.get("version", "0.0"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": grouped,
        "rules_path_used": resolved_path,
    }
