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
    matched = set()
    evidence: List[str] = []
    seen = set()

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

def applies(rule_applies_when: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    applies_when:
      advice_type: advised OR [advised, nonadvised]
      investment_element: true/false (strings, because your form posts strings)
      ongoing_service: true/false (strings)
    """
    if not rule_applies_when:
        return True

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
    v1 philosophy: NO AUTO-PASS.
    If ok_if is missing/empty, fail deterministically.
    """
    if ok_if is None:
        return False, "No ok_if provided (cannot auto-pass)."

    if isinstance(ok_if, str):
        ok_if_list = [ok_if]
    elif isinstance(ok_if, list):
        ok_if_list = ok_if
    else:
        return False, "ok_if must be a string or list of strings."

    clauses: List[str] = []
    for raw in ok_if_list:
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        if s.upper().startswith("AND "):
            s = s[4:].strip()
        clauses.append(s)

    if not clauses:
        return False, "ok_if empty (cannot auto-pass)."

    failed: List[str] = []
    for c in clauses:
        if not eval_condition(counts, c):
            failed.append(c)

    if failed:
        return False, "Failed: " + "; ".join(failed)

    return True, "All conditions met."


# ---------------------------------
# RULE EVALUATION
# ---------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies(rule.get("applies_when", {}) or {}, context):
        return {"status": "NOT_ASSESSED", "why": "Rule not applicable for current context.", "evidence": []}

    sentences = split_sentences(text)

    evidence_spec = rule.get("evidence", {}) or {}
    decision = rule.get("decision_logic", {}) or {}

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

    if isinstance(evidence_spec, dict):
        for key, spec in evidence_spec.items():
            if key.endswith("_clusters"):
                hit_n, phrases, ev = cluster_hits(
                    sentences,
                    spec,
                    allow_if_negated=True,   # clusters treated as positive signals
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
    else:
        # broken YAML shape -> no evidence
        counts = {}

    ok_if = decision.get("ok_if", None)
    ok, why = eval_ok_if(counts, ok_if)

    status = "OK" if ok else "POTENTIAL_ISSUE"

    # v1 philosophy: don't mark OK unless we can point to *some* evidence
    if status == "OK" and len(evidence_sentences) == 0:
        status = "POTENTIAL_ISSUE"
        why = "Decision conditions met, but no matching snippets found (no evidence)."

    return {
        "status": status,
        "why": why,
        "counts": counts,
        "evidence": evidence_sentences[:6],
        "matched_phrases": sorted(matched_phrases_all)[:30],
    }


# ---------------------------------
# EXECUTOR ENTRY POINT
# ---------------------------------

def run_rules_engine(
    document_text: str,
    context: Dict[str, Any],
    rules_path: str = "rules/cobs-suitability-v1.yaml",
) -> Dict[str, Any]:

    with open(rules_path, "r") as f:
        ruleset = yaml.safe_load(f) or {}

    rules = ruleset.get("rules", []) or []
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        outcome = evaluate_rule(rule, document_text, context)

        section = rule.get("section", "Unsorted")
        grouped.setdefault(section, [])

        grouped[section].append({
            "rule_id": rule.get("id", ""),
            "title": rule.get("title", ""),
            "status": outcome.get("status", "POTENTIAL_ISSUE"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", ""),
            "why": outcome.get("why", ""),
            "evidence": outcome.get("evidence", []),
        })

    for s in list(grouped.keys()):
        grouped[s] = sorted(grouped[s], key=lambda r: (r.get("rule_id") or ""))

    summary = {
        "ok": sum(1 for sec in grouped.values() for r in sec if r["status"] == "OK"),
        "potential_issue": sum(1 for sec in grouped.values() for r in sec if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for sec in grouped.values() for r in sec if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "ruleset_id": ruleset.get("ruleset_id", "unknown-ruleset"),
        "ruleset_version": ruleset.get("version", "0.0"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": grouped,
    }
