import re
import yaml
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()

def split_sentences(text: str) -> List[str]:
    """
    Deterministic sentence-ish splitter.
    Keeps bullets reasonably intact.
    """
    t = normalise(text)
    if not t:
        return []
    # split on line breaks first (bullets / headings), then sentence punctuation
    lines = [ln.strip() for ln in re.split(r"[\r\n]+", t) if ln.strip()]
    out: List[str] = []
    for ln in lines:
        parts = re.split(r"(?<=[.!?])\s+", ln)
        out.extend([p.strip() for p in parts if p.strip()])
    return out

def _ensure_str_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    if isinstance(x, list):
        return [str(i) for i in x if isinstance(i, (str, int, float))]
    return [str(x)]

def _compile_patterns(patterns: List[str], regex: bool) -> List[re.Pattern]:
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE) if regex else re.compile(re.escape(p), re.IGNORECASE))
        except re.error:
            # skip invalid regex (deterministic, don't crash)
            continue
    return compiled

def find_hits(
    sentences: List[str],
    patterns: List[str],
    *,
    regex: bool = False,
) -> List[Tuple[str, str, int]]:
    """
    Returns list of (pattern, sentence, sentence_index)
    """
    pats = _compile_patterns(patterns, regex)
    hits: List[Tuple[str, str, int]] = []
    if not pats:
        return hits

    for i, sent in enumerate(sentences):
        for raw, comp in zip(patterns, pats):
            if comp.search(sent):
                hits.append((raw, sent, i))
    return hits

def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out

def cap(items: List[str], n: int) -> List[str]:
    return items[: max(0, int(n or 0))]


# -----------------------------
# CUSTOM CHECKS (deterministic)
# -----------------------------

AGE_RE = re.compile(r"\bage\s*(\d{2})\b", re.IGNORECASE)
EQUITY_ALLOC_RE = re.compile(r"\b(\d{1,3})\s*%\s*(?:global\s*)?(?:equity|equities|shares)\b", re.IGNORECASE)

def check_equity_near_retirement(sentences: List[str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flags if:
      - age >= min_age (default 55)
      - max equity allocation >= min_equity_pct (default 75)
      - and NO balancing language present anywhere (default phrases list)
    """
    min_age = int(cfg.get("min_age", 55))
    min_equity = int(cfg.get("min_equity_pct", 75))
    balancers = _ensure_str_list(cfg.get("balancers")) or [
        "can fall as well as rise",
        "no guarantee",
        "not guaranteed",
        "may get back less",
        "volatility",
        "capacity for loss",
        "risk of loss",
    ]

    full_text = " ".join(sentences)

    # age
    ages = [int(m.group(1)) for m in AGE_RE.finditer(full_text) if m.group(1).isdigit()]
    age = max(ages) if ages else None

    # equity pct
    pcts = []
    for m in EQUITY_ALLOC_RE.finditer(full_text):
        try:
            pct = int(m.group(1))
            if 0 <= pct <= 100:
                pcts.append(pct)
        except ValueError:
            pass
    max_equity = max(pcts) if pcts else None

    # balancers
    has_balancer = any(re.search(re.escape(b), full_text, re.IGNORECASE) for b in balancers)

    evidence: List[str] = []
    if age is not None:
        evidence.append(f"Detected age {age}.")
    if max_equity is not None:
        evidence.append(f"Detected equity allocation {max_equity}%.")

    if age is None or max_equity is None:
        return {"status": "NOT_ASSESSED", "evidence": cap(evidence, 5)}

    if age >= min_age and max_equity >= min_equity and not has_balancer:
        return {"status": "POTENTIAL_ISSUE", "evidence": cap(evidence, 5)}

    return {"status": "OK", "evidence": cap(evidence, 5)}


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies = rule.get("applies_when", {}) or {}
    for k, v in applies.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED", "evidence": []}

    sentences = split_sentences(text)

    # Custom rule handler
    if rule.get("type") == "custom" and rule.get("custom") == "equity_near_retirement":
        return check_equity_near_retirement(sentences, rule.get("custom_config", {}) or {})

    evidence_cap = int(rule.get("evidence_cap", 5))

    # 1) FORBIDDEN (certainty / guarantees)
    forbid = _ensure_str_list(rule.get("forbid_phrases"))
    forbid_regex = _ensure_str_list(rule.get("forbid_regex"))
    allow_near = _ensure_str_list(rule.get("allow_if_near"))
    allow_near_regex = _ensure_str_list(rule.get("allow_if_near_regex"))
    near_window = int(rule.get("near_window", 1))

    forbid_hits = []
    if forbid:
        forbid_hits.extend(find_hits(sentences, forbid, regex=False))
    if forbid_regex:
        forbid_hits.extend(find_hits(sentences, forbid_regex, regex=True))

    if forbid_hits:
        # If allow_near exists, require a balancer phrase within ±near_window sentences
        if allow_near or allow_near_regex:
            allow_hits = []
            if allow_near:
                allow_hits.extend(find_hits(sentences, allow_near, regex=False))
            if allow_near_regex:
                allow_hits.extend(find_hits(sentences, allow_near_regex, regex=True))

            allow_idx = {idx for _, _, idx in allow_hits}
            bad_sentences = []
            for _, sent, idx in forbid_hits:
                ok = any((idx + d) in allow_idx for d in range(-near_window, near_window + 1))
                if not ok:
                    bad_sentences.append(sent)

            bad_sentences = dedupe_preserve_order(bad_sentences)
            if bad_sentences:
                return {"status": "POTENTIAL_ISSUE", "evidence": cap(bad_sentences, evidence_cap)}

        # no allow_near configured -> any forbid hit is a potential issue
        matched = dedupe_preserve_order([s for _, s, _ in forbid_hits])
        return {"status": "POTENTIAL_ISSUE", "evidence": cap(matched, evidence_cap)}

    # 2) REQUIRED SETS (logic-style checks)
    # rule passes if it satisfies ALL sets
    # set shape: { any: [...], any_regex: [...], min_hits: 1 }
    require_sets = rule.get("require_sets") or []
    if require_sets:
        all_evidence: List[str] = []
        for rs in require_sets:
            any_phr = _ensure_str_list(rs.get("any"))
            any_re = _ensure_str_list(rs.get("any_regex"))
            min_hits = int(rs.get("min_hits", 1))

            hits = []
            if any_phr:
                hits.extend(find_hits(sentences, any_phr, regex=False))
            if any_re:
                hits.extend(find_hits(sentences, any_re, regex=True))

            matched = dedupe_preserve_order([s for _, s, _ in hits])
            if len(matched) < min_hits:
                # fail fast
                return {"status": "POTENTIAL_ISSUE", "evidence": cap(dedupe_preserve_order(all_evidence), evidence_cap)}
            all_evidence.extend(matched)

        return {"status": "OK", "evidence": cap(dedupe_preserve_order(all_evidence), evidence_cap)}

    # 3) SIMPLE REQUIRED PHRASES (default)
    phrases = _ensure_str_list(rule.get("phrases"))
    regexes = _ensure_str_list(rule.get("regex_phrases"))
    min_hits = int(rule.get("min_hits", 1))

    hits = []
    if phrases:
        hits.extend(find_hits(sentences, phrases, regex=False))
    if regexes:
        hits.extend(find_hits(sentences, regexes, regex=True))

    matched = dedupe_preserve_order([s for _, s, _ in hits])

    if len(matched) >= min_hits:
        return {"status": "OK", "evidence": cap(matched, evidence_cap)}

    return {"status": "POTENTIAL_ISSUE", "evidence": cap(matched, evidence_cap)}


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

    rules = ruleset.get("rules", []) or []

    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section", "Unsorted")
        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule.get("id"),
            "title": rule.get("title", ""),
            "status": outcome.get("status", "NOT_ASSESSED"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", ""),
            "evidence": dedupe_preserve_order(outcome.get("evidence", []) or []),
        })

    summary = {
        "ok": sum(1 for s in grouped.values() for r in s if r["status"] == "OK"),
        "potential_issue": sum(1 for s in grouped.values() for r in s if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for s in grouped.values() for r in s if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id", "unknown"),
        "ruleset_version": ruleset.get("version", "unknown"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": grouped,
    }