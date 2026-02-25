#eval executor.py
import os
import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple


# =================================
# TEXT NORMALISATION + SENTENCES
# =================================

_WS_RE = re.compile(r"\s+")
_SENT_RE = re.compile(r'(?<=[.!?])\s+')

def normalise(text: str) -> str:
    return _WS_RE.sub(" ", (text or "").strip())

def normalise_lower(text: str) -> str:
    return normalise(text).lower()

def split_sentences(text: str) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    parts = _SENT_RE.split(t)
    return [p.strip() for p in parts if p and p.strip()]


# =================================
# MATCHING HELPERS (DETERMINISTIC)
# =================================

_NEGATION_TOKENS = {
    "not", "no", "never", "without", "none", "cannot", "can't",
    "isn't", "aren't", "won't", "don't"
}

def _tokenise(s: str) -> List[str]:
    return re.findall(r"[a-zA-Z']+", (s or "").lower())

def _is_negated(sentence: str, phrase: str, window_tokens: int = 4) -> bool:
    """
    True if phrase appears AND a negation token is within N tokens immediately before it.
    Prevents false flags like: "there are no guaranteed returns".
    """
    s_low = (sentence or "").lower()
    p_low = (phrase or "").lower().strip()
    if not p_low or p_low not in s_low:
        return False

    tokens = _tokenise(sentence)
    phrase_tokens = _tokenise(phrase)
    if not phrase_tokens:
        return False

    for i in range(len(tokens) - len(phrase_tokens) + 1):
        if tokens[i:i + len(phrase_tokens)] == phrase_tokens:
            start = max(0, i - window_tokens)
            prior = tokens[start:i]
            if any(t in _NEGATION_TOKENS for t in prior):
                return True
    return False


def _flatten_phrases(phrases: Any) -> List[str]:
    """
    YAML mistakes happen: sometimes phrase lists get nested.
    We accept:
      - ["a", "b"]
      - [["a","b"], ["c"]]  (flatten 1 level)
      - mixed junk -> ignored safely
    """
    out: List[str] = []
    if not phrases:
        return out

    if isinstance(phrases, str):
        return [phrases]

    if isinstance(phrases, list):
        for p in phrases:
            if isinstance(p, str):
                out.append(p)
            elif isinstance(p, list):
                for pp in p:
                    if isinstance(pp, str):
                        out.append(pp)
    return out


def phrase_hits(
    sentences: List[str],
    phrases: Any,
    *,
    allow_if_negated: bool = True,
    max_evidence: int = 6
) -> Tuple[int, List[str], List[str]]:
    """
    Returns:
      hit_count (dedup phrase count),
      matched_phrases (sorted, dedup),
      evidence_sentences (dedup, capped)
    """
    flat = _flatten_phrases(phrases)

    matched_phrases: set[str] = set()
    evidence: List[str] = []
    seen_sent: set[str] = set()

    for sent in sentences:
        s_norm = sent.lower()
        for p in flat:
            p_norm = (p or "").lower()
            if p_norm and p_norm in s_norm:
                if not allow_if_negated and _is_negated(sent, p):
                    continue
                matched_phrases.add(p)
                if len(evidence) < max_evidence and sent not in seen_sent:
                    evidence.append(sent)
                    seen_sent.add(sent)

    return len(matched_phrases), sorted(matched_phrases), evidence


def cluster_hits(
    sentences: List[str],
    clusters: Any,
    *,
    allow_if_negated: bool = True,
    max_evidence: int = 6
) -> Tuple[int, List[str], List[str]]:
    """
    A cluster is satisfied if ANY phrase in that cluster hits at least once.
    clusters expected: list[list[str]]
    Returns:
      satisfied_cluster_count, matched_phrases (dedup), evidence_sentences (dedup; capped)
    """
    if not isinstance(clusters, list):
        return 0, [], []

    satisfied = 0
    matched_all: set[str] = set()
    evidence: List[str] = []
    seen_sent: set[str] = set()

    for cluster in clusters:
        if not isinstance(cluster, list):
            continue

        hit_n, phrases, ev = phrase_hits(
            sentences,
            cluster,
            allow_if_negated=allow_if_negated,
            max_evidence=max_evidence
        )

        if hit_n > 0:
            satisfied += 1
            for p in phrases:
                matched_all.add(p)
            for s in ev:
                if len(evidence) < max_evidence and s not in seen_sent:
                    evidence.append(s)
                    seen_sent.add(s)

    return satisfied, sorted(matched_all), evidence


# =================================
# APPLICABILITY
# =================================

def applies(rule_applies_when: Any, context: Dict[str, Any]) -> bool:
    """
    Supports:
      applies_when:
        advice_type: advised
        advice_type: [advised, nonadvised]
        investment_element: true
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


# =================================
# DECISION LOGIC
# =================================

_COND_RE = re.compile(r"^\s*(>=|==|<=|>|<)\s*(\d+)\s+([a-zA-Z0-9_]+)\s*$")

def eval_condition(counts: Dict[str, int], cond: str) -> bool:
    m = _COND_RE.match(cond or "")
    if not m:
        return False
    op, n_str, key = m.group(1), m.group(2), m.group(3)
    n = int(n_str)
    v = int(counts.get(key, 0))

    if op == ">=":
        return v >= n
    if op == "==":
        return v == n
    if op == "<=":
        return v <= n
    if op == ">":
        return v > n
    if op == "<":
        return v < n
    return False


def eval_ok_if(counts: Dict[str, int], ok_if: Any) -> Tuple[bool, str]:
    """
    If ok_if is missing/None -> DO NOT auto-pass.
    We only mark OK when explicit conditions are provided and met.
    """
    if ok_if is None:
        return False, "No ok_if provided (cannot auto-pass)."

    if isinstance(ok_if, dict):
        return False, "ok_if must be a list of strings."

    if isinstance(ok_if, str):
        ok_if_list = [ok_if]
    elif isinstance(ok_if, list):
        ok_if_list = ok_if
    else:
        return False, "ok_if must be list/str."

    clauses: List[str] = []
    for raw in ok_if_list:
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        s = s.replace("AND ", "").strip() if s.upper().startswith("AND ") else s
        clauses.append(s)

    if not clauses:
        return False, "ok_if empty (cannot auto-pass)."

    failed = []
    for c in clauses:
        if not eval_condition(counts, c):
            failed.append(c)

    if failed:
        return False, "Failed: " + "; ".join(failed)
    return True, "All conditions met."


# =================================
# RULE EVALUATION
# =================================

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies(rule.get("applies_when", {}), context):
        return {"status": "NOT_ASSESSED", "why": "Rule not applicable for current context.", "evidence": []}

    sentences = split_sentences(text)
    evidence_spec = rule.get("evidence", {}) or {}
    decision = rule.get("decision_logic", {}) or {}

    # --------------------------------------------------
# STRICT DEFAULT: no evidence = potential issue
# --------------------------------------------------

# We will compute counts first, then enforce that
# zero matches cannot auto-pass.

counts: Dict[str, int] = {}
matched_phrases_all: set[str] = set()
evidence_sentences: List[str] = []
evidence_seen: set[str] = set()

    counts: Dict[str, int] = {}
    matched_phrases_all: set[str] = set()
    evidence_sentences: List[str] = []
    evidence_seen: set[str] = set()

    def merge(phrases: List[str], ev_sents: List[str], cap: int = 6):
        nonlocal matched_phrases_all, evidence_sentences, evidence_seen
        for p in phrases:
            matched_phrases_all.add(p)
        for s in ev_sents:
            if len(evidence_sentences) >= cap:
                break
            if s not in evidence_seen:
                evidence_sentences.append(s)
                evidence_seen.add(s)

    if isinstance(evidence_spec, dict):
        for key, spec in evidence_spec.items():
            if key.endswith("_clusters"):
                hit_n, phrases, ev = cluster_hits(
                    sentences,
                    spec,
                    allow_if_negated=True,   # clusters = positive signals
                    max_evidence=6
                )
                counts[key] = hit_n
                merge(phrases, ev, cap=6)
            else:
                # negative/prohibited style keys: ignore when negated (avoid false flags)
                allow_if_negated = True
                if key in ("negative_indicators", "prohibited_phrases", "must_not_contain"):
                    allow_if_negated = False

                hit_n, phrases, ev = phrase_hits(
                    sentences,
                    spec,
                    allow_if_negated=allow_if_negated,
                    max_evidence=6
                )
                counts[key] = hit_n
                merge(phrases, ev, cap=6)
    else:
        # If someone broke the YAML shape, treat as no evidence.
        evidence_spec = {}

total_hits = sum(int(v) for v in counts.values())

if total_hits == 0:
    return {
        "status": "POTENTIAL_ISSUE",
        "why": "No rule indicators matched. No evidence found.",
        "counts": counts,
        "evidence": [],
        "matched_phrases": [],
    }

    ok_if = decision.get("ok_if", None)
    ok, why = eval_ok_if(counts, ok_if)
    status = "OK" if ok else "POTENTIAL_ISSUE"

    # v1 philosophy: don't mark OK unless we can point to at least *some* evidence
    if status == "OK" and ok_if and len(evidence_sentences) == 0:
        status = "POTENTIAL_ISSUE"
        why = "Decision conditions met numerically, but no matching snippets found (no evidence)."

    return {
        "status": status,
        "why": why,
        "counts": counts,
        "evidence": evidence_sentences[:6],
        "matched_phrases": sorted(matched_phrases_all)[:30],
    }


# =================================
# RULESET LOAD (ENV OVERRIDE + FALLBACK)
# =================================

def _resolve_rules_path(default_path: str) -> str:
    """
    1) RULES_PATH env var overrides
    2) use provided/default if exists
    3) fallback to v1 if v2 missing
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


# =================================
# EXECUTOR ENTRY POINT
# =================================

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
            "source_url": rule.get("source_url", ""),  # optional
            "why": outcome.get("why", ""),
            "evidence": outcome.get("evidence", []),
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
