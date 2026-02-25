# executor.py
import os
import re
import yaml
from datetime import datetime
from typing import Any, Dict, List, Tuple, Optional


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
    Allow phrases to be list[str] or accidentally list[list[str]].
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
) -> Tuple[int, List[str], List[str], List[Tuple[str, str]]]:
    """
    Returns:
      hit_count (dedup phrase count),
      matched_phrases (sorted),
      evidence_sentences (dedup, capped),
      hit_pairs: list of (phrase, sentence) for mapping/debug (uncapped)
    """
    matched = set()
    evidence: List[str] = []
    seen = set()
    hit_pairs: List[Tuple[str, str]] = []

    flat = _flatten_phrases(phrases)

    for sent in sentences:
        s_low = sent.lower()
        for p in flat:
            p_low = p.lower().strip()
            if not p_low:
                continue
            if p_low in s_low:
                if (not allow_if_negated) and _is_negated(sent, p):
                    continue
                matched.add(p)
                hit_pairs.append((p, sent))
                if len(evidence) < max_evidence and sent not in seen:
                    evidence.append(sent)
                    seen.add(sent)

    return len(matched), sorted(matched), evidence, hit_pairs

def cluster_hits(
    sentences: List[str],
    clusters: Any,
    *,
    allow_if_negated: bool,
    max_evidence: int = 6,
) -> Tuple[int, List[str], List[str], Dict[int, List[str]]]:
    """
    A cluster is satisfied if ANY phrase in that cluster hits.
    Returns:
      satisfied_cluster_count,
      matched_phrases (dedup),
      evidence_sentences (dedup; capped),
      evidence_by_cluster_index (uncapped per cluster, dedup per cluster)
    """
    if not isinstance(clusters, list):
        return 0, [], [], {}

    satisfied = 0
    matched = set()
    evidence: List[str] = []
    seen_global = set()
    evidence_by_cluster: Dict[int, List[str]] = {}

    for idx, cluster in enumerate(clusters):
        if not isinstance(cluster, list):
            continue

        hit_n, phrases, ev, _pairs = phrase_hits(
            sentences,
            cluster,
            allow_if_negated=allow_if_negated,
            max_evidence=max_evidence,
        )

        if hit_n > 0:
            satisfied += 1
            for p in phrases:
                matched.add(p)

            # store per-cluster evidence (dedup, not capped aggressively)
            per_seen = set()
            per_list: List[str] = []
            for s in ev:
                if s not in per_seen:
                    per_list.append(s)
                    per_seen.add(s)
            evidence_by_cluster[idx] = per_list

            # merge to global evidence (capped)
            for s in ev:
                if len(evidence) >= max_evidence:
                    break
                if s not in seen_global:
                    evidence.append(s)
                    seen_global.add(s)

    return satisfied, sorted(matched), evidence, evidence_by_cluster


# ---------------------------------
# APPLICABILITY
# ---------------------------------

def applies(rule_applies_when: Any, context: Dict[str, Any]) -> bool:
    """
    applies_when supports scalar or list:
      advice_type: advised OR [advised, nonadvised]
      investment_element: true/false (bools in ctx)
      ongoing_service: true/false (bools in ctx)
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
# DECISION LOGIC
# ---------------------------------

_THRESH_RE = re.compile(r"^\s*(>=|==|<=|>|<)\s*(\d+)\s*$")

def _parse_threshold(expr: Any) -> Optional[Tuple[str, int]]:
    """
    Accepts: ">=2", "==0", "<=1"
    """
    if not isinstance(expr, str):
        return None
    m = _THRESH_RE.match(expr.strip())
    if not m:
        return None
    return m.group(1), int(m.group(2))

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

def _eval_require_block(
    counts: Dict[str, int],
    block: Any,
    *,
    block_name: str,
) -> Tuple[bool, List[str], List[str]]:
    """
    block like:
      require_all:
        positive_clusters: ">=2"
        linkage_indicators: ">=1"
    returns:
      ok, missing_list, details_list
    """
    if not block:
        return True, [], [f"{block_name} empty (no requirements)."]
    if not isinstance(block, dict):
        return False, ["Invalid decision logic block shape"], [f"{block_name} must be a dict."]

    missing: List[str] = []
    details: List[str] = []

    ok = True
    for key, expr in block.items():
        th = _parse_threshold(expr)
        if not th:
            ok = False
            missing.append(f"{key} {expr} (invalid threshold)")
            details.append(f"{block_name} invalid threshold for {key}: {expr}")
            continue
        op, target = th
        actual = int(counts.get(key, 0))
        passed = _cmp(op, actual, target)
        if not passed:
            ok = False
            missing.append(f"{key} {op}{target} (actual={actual})")
            details.append(f"{block_name} failed: {key} {op}{target} (actual={actual})")
        else:
            details.append(f"{block_name} satisfied: {key} {op}{target} (actual={actual})")

    return ok, missing, details


# ---------------------------------
# RULE EVALUATION
# ---------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies(rule.get("applies_when") or {}, context):
        return {
            "status": "NOT_ASSESSED",
            "why": "Rule not applicable for current context.",
            "counts": {},
            "evidence": [],
            "evidence_by_key": {},
            "missing": [],
            "details": [],
        }

    sentences = split_sentences(text)
    evidence_spec = rule.get("evidence") or {}
    decision = rule.get("decision_logic") or {}

    # Counts + evidence mapping
    counts: Dict[str, int] = {}
    evidence_by_key: Dict[str, List[str]] = {}
    matched_phrases_all = set()

    # global evidence (for your table summary)
    evidence_sentences: List[str] = []
    evidence_seen = set()

    def _merge_global(ev_sents: List[str], cap: int = 6) -> None:
        for s in ev_sents:
            if len(evidence_sentences) >= cap:
                break
            if s not in evidence_seen:
                evidence_sentences.append(s)
                evidence_seen.add(s)

    # 1) Build counts per evidence bucket
    if isinstance(evidence_spec, dict):
        for key, spec in evidence_spec.items():
            # "bad language" keys: ignore matches if negated
            allow_if_negated = True
            if key in ("negative_indicators", "prohibited_phrases", "must_not_contain"):
                allow_if_negated = False

            if key.endswith("_clusters"):
                # IMPORTANT: cluster count is satisfied clusters, not phrase hits
                satisfied_n, phrases, ev, _by_cluster = cluster_hits(
                    sentences,
                    spec,
                    allow_if_negated=True,   # clusters treated as positive signals
                    max_evidence=6,
                )
                counts[key] = satisfied_n
                evidence_by_key[key] = ev
                for p in phrases:
                    matched_phrases_all.add(p)
                _merge_global(ev, cap=6)

            else:
                hit_n, phrases, ev, _pairs = phrase_hits(
                    sentences,
                    spec,
                    allow_if_negated=allow_if_negated,
                    max_evidence=6,
                )
                counts[key] = hit_n
                evidence_by_key[key] = ev
                for p in phrases:
                    matched_phrases_all.add(p)
                _merge_global(ev, cap=6)
    else:
        # broken YAML -> treat as no evidence
        evidence_spec = {}
        counts = {}
        evidence_by_key = {}

    # 2) Special-case: allow_negations override for prohibited phrases (stops false flags)
    # If a prohibited phrase is only present alongside an allowed negation phrase, don't treat it as prohibited.
    # Example: "There are no guaranteed returns" should NOT be flagged.
    if "prohibited_phrases" in counts and counts.get("prohibited_phrases", 0) > 0:
        if counts.get("allowed_negations", 0) > 0:
            # neutralise prohibited hits
            counts["prohibited_phrases"] = 0

    # 3) Decision logic evaluation (supports your v2 YAML)
    # v1 philosophy: NO AUTO-PASS. If decision logic missing/empty -> POTENTIAL_ISSUE.
    if not isinstance(decision, dict) or len(decision.keys()) == 0:
        return {
            "status": "POTENTIAL_ISSUE",
            "why": "No decision_logic provided (cannot auto-pass).",
            "counts": counts,
            "evidence": evidence_sentences[:6],
            "evidence_by_key": evidence_by_key,
            "missing": ["decision_logic missing"],
            "details": [],
        }

    require_all = decision.get("require_all")
    require_none = decision.get("require_none")
    allow_if_present = decision.get("allow_if_present")

    ok_all, missing_all, details_all = _eval_require_block(counts, require_all, block_name="require_all")
    ok_none, missing_none, details_none = _eval_require_block(counts, require_none, block_name="require_none")
    ok_allow, missing_allow, details_allow = _eval_require_block(counts, allow_if_present, block_name="allow_if_present")

    # Semantics:
    # - require_all: must pass
    # - require_none: must pass (typically "==0" or "<=0")
    # - allow_if_present: doesn't make things OK by itself; it only *adds context* (and for the COBS4 guarantee rule,
    #   we already neutralised prohibited_phrases when allowed_negations present).
    missing: List[str] = []
    details: List[str] = []

    details.extend(details_all)
    details.extend(details_none)
    details.extend(details_allow)

    if not ok_all:
        missing.extend(missing_all)
    if not ok_none:
        missing.extend(missing_none)

    # Strict: if no indicators matched at all, always PI (absence != compliance)
    total_hits = sum(int(v) for v in counts.values())
    if total_hits == 0:
        return {
            "status": "POTENTIAL_ISSUE",
            "why": "No indicators matched for this rule (no evidence).",
            "counts": counts,
            "evidence": [],
            "evidence_by_key": evidence_by_key,
            "missing": ["All required signals (none matched)"],
            "details": [],
        }

    # OK only if require_all and require_none (if present) are satisfied
    status = "OK" if (ok_all and ok_none) else "POTENTIAL_ISSUE"

    if status == "OK":
        # still enforce: must have evidence
        if len(evidence_sentences) == 0:
            status = "POTENTIAL_ISSUE"
            missing.append("No evidence sentences (cannot assert OK).")
            details.append("Downgraded: decision passed but evidence list empty.")

    why = "OK" if status == "OK" else "Conditions not met."

    return {
        "status": status,
        "why": why,
        "counts": counts,
        "evidence": evidence_sentences[:6],
        "evidence_by_key": evidence_by_key,
        "missing": missing,
        "details": details,
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

    raise FileNotFoundError(f"Rules file not found: {path} (and fallback missing: {fallback})")

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
            "source_url": rule.get("source_url") or "",
            "why": outcome.get("why", ""),
            "counts": outcome.get("counts", {}),
            "missing": outcome.get("missing", []),
            "details": outcome.get("details", []),
            "evidence": outcome.get("evidence", []),
            "evidence_by_key": outcome.get("evidence_by_key", {}),
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
