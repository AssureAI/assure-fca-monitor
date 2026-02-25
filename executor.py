import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


# ---------------------------------
# NORMALISATION + SENTENCE SPLIT
# ---------------------------------

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


# ---------------------------------
# MATCHING HELPERS (DETERMINISTIC)
# ---------------------------------

_NEGATION_TOKENS = {"not", "no", "never", "without", "none", "cannot", "can't", "isn't", "aren't", "won't", "don't"}

def _tokenise(s: str) -> List[str]:
    # keep it simple & deterministic
    return re.findall(r"[a-zA-Z']+", (s or "").lower())

def _is_negated(sentence: str, phrase: str, window_tokens: int = 4) -> bool:
    """
    True if the phrase appears, and a negation token is within N tokens immediately before it.
    This prevents false flags like: "there are no guaranteed returns".
    """
    s_low = sentence.lower()
    p_low = (phrase or "").lower().strip()
    if not p_low or p_low not in s_low:
        return False

    tokens = _tokenise(sentence)
    phrase_tokens = _tokenise(phrase)
    if not phrase_tokens:
        return False

    # find occurrences of phrase_tokens in tokens
    for i in range(len(tokens) - len(phrase_tokens) + 1):
        if tokens[i:i+len(phrase_tokens)] == phrase_tokens:
            start = max(0, i - window_tokens)
            prior = tokens[start:i]
            if any(t in _NEGATION_TOKENS for t in prior):
                return True
    return False

def phrase_hits(
    sentences: List[str],
    phrases: List[Any],
    *,
    allow_if_negated: bool = True,
    max_evidence: int = 6
) -> Tuple[int, List[str], List[str]]:
    """
    Returns:
      hit_count, matched_phrases (dedup), evidence_sentences (dedup; capped)
    Supports phrases list that may accidentally contain nested lists (we ignore non-strings safely).
    """
    matched_phrases_set = set()
    evidence_set = []
    evidence_seen = set()

    # flatten only one level if someone accidentally nested
    flat: List[str] = []
    for p in (phrases or []):
        if isinstance(p, str):
            flat.append(p)
        elif isinstance(p, list):
            for pp in p:
                if isinstance(pp, str):
                    flat.append(pp)

    for sent in sentences:
        s_low = sent.lower()
        for p in flat:
            p_low = p.lower()
            if p_low and p_low in s_low:
                # if phrase is prohibited-style, ignore when negated
                if not allow_if_negated and _is_negated(sent, p):
                    continue
                matched_phrases_set.add(p)
                if len(evidence_set) < max_evidence and sent not in evidence_seen:
                    evidence_set.append(sent)
                    evidence_seen.add(sent)

    return len(matched_phrases_set), sorted(matched_phrases_set), evidence_set


def cluster_hits(
    sentences: List[str],
    clusters: List[Any],
    *,
    allow_if_negated: bool = True,
    max_evidence: int = 6
) -> Tuple[int, List[str], List[str]]:
    """
    A cluster is satisfied if ANY phrase in that cluster hits at least once.
    Returns:
      satisfied_cluster_count, matched_phrases (dedup), evidence_sentences (dedup; capped)
    """
    satisfied = 0
    matched_phrases_set = set()
    evidence_set = []
    evidence_seen = set()

    if not isinstance(clusters, list):
        return 0, [], []

    for cluster in clusters:
        # each cluster should be list[str]
        if not isinstance(cluster, list):
            continue
        hit_count, phrases, ev = phrase_hits(
            sentences, cluster,
            allow_if_negated=allow_if_negated,
            max_evidence=max_evidence
        )
        if hit_count > 0:
            satisfied += 1
            for p in phrases:
                matched_phrases_set.add(p)
            for s in ev:
                if len(evidence_set) < max_evidence and s not in evidence_seen:
                    evidence_set.append(s)
                    evidence_seen.add(s)

    return satisfied, sorted(matched_phrases_set), evidence_set


# ---------------------------------
# APPLICABILITY
# ---------------------------------

def applies(rule_applies_when: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Supports:
      applies_when:
        advice_type: advised        (scalar)
        advice_type: [advised,...]  (list)
        investment_element: true
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
# DECISION LOGIC PARSING
# ---------------------------------

_COND_RE = re.compile(r"^\s*(>=|==|<=|>|<)\s*(\d+)\s+([a-zA-Z0-9_]+)\s*$")

def eval_condition(counts: Dict[str, int], cond: str) -> bool:
    """
    cond examples:
      ">=2 positive_clusters"
      "==0 negative_indicators"
    """
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
    Supports:
      ok_if: ["<=0 negative_indicators", "AND >=2 positive_clusters", "AND >=1 linkage_indicators"]
    or:
      ok_if:
        - ">=2 positive_clusters"
        - "AND >=1 linkage_indicators"
    """
    if ok_if is None:
        return True, "No ok_if provided."

    if isinstance(ok_if, dict):
        # not supported; keep deterministic
        return False, "ok_if must be a list of strings."

    if isinstance(ok_if, str):
        ok_if_list = [ok_if]
    elif isinstance(ok_if, list):
        ok_if_list = ok_if
    else:
        return False, "ok_if must be list/str."

    # default operator between clauses is AND (explicit AND supported)
    clauses: List[str] = []
    for raw in ok_if_list:
        if not isinstance(raw, str):
            continue
        s = raw.strip()
        s = s.replace("AND ", "").strip() if s.upper().startswith("AND ") else s
        clauses.append(s)

    if not clauses:
        return True, "No clauses."

    failed = []
    for c in clauses:
        if not eval_condition(counts, c):
            failed.append(c)

    if failed:
        return False, "Failed: " + "; ".join(failed)
    return True, "All conditions met."


# ---------------------------------
# RULE EVALUATION (V1-LEVEL)
# ---------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies(rule.get("applies_when", {}), context):
        return {"status": "NOT_ASSESSED", "why": "Rule not applicable for current context.", "evidence": []}

    sentences = split_sentences(text)
    evidence_spec = rule.get("evidence", {}) or {}
    decision = rule.get("decision_logic", {}) or {}

    # count buckets
    counts: Dict[str, int] = {}

    # evidence capture (dedup)
    matched_phrases_all = set()
    evidence_sentences_all: List[str] = []
    evidence_seen = set()

    # helper to merge evidence
    def merge(phrases: List[str], ev_sents: List[str], cap: int = 6):
        nonlocal matched_phrases_all, evidence_sentences_all, evidence_seen
        for p in phrases:
            matched_phrases_all.add(p)
        for s in ev_sents:
            if len(evidence_sentences_all) >= cap:
                break
            if s not in evidence_seen:
                evidence_sentences_all.append(s)
                evidence_seen.add(s)

    # Process known evidence keys; any *_clusters treated as clusters; any other list treated as phrase list.
    for key, spec in evidence_spec.items():
        if key.endswith("_clusters"):
            hit_n, phrases, ev = cluster_hits(
                sentences, spec,
                allow_if_negated=True,      # cluster phrases are generally "positive signals"
                max_evidence=6
            )
            counts[key] = hit_n
            merge(phrases, ev, cap=6)

        else:
            # special case: negative_indicators should ignore negated contexts (avoid false flags)
            allow_if_negated = True
            if key in ("negative_indicators", "prohibited_phrases", "must_not_contain"):
                allow_if_negated = False

            hit_n, phrases, ev = phrase_hits(
                sentences, spec,
                allow_if_negated=allow_if_negated,
                max_evidence=6
            )
            counts[key] = hit_n
            merge(phrases, ev, cap=6)

    # Decision evaluation
    ok_if = decision.get("ok_if", None)

    ok, why = eval_ok_if(counts, ok_if)
    status = "OK" if ok else "POTENTIAL_ISSUE"

    # Make "OK" require at least one matched sentence IF ok_if exists and is non-empty.
    # This keeps the v1 philosophy: absence of evidence != compliance.
    if status == "OK":
        # If there is an ok_if and we have zero evidence sentences, downgrade.
        if ok_if and len(evidence_sentences_all) == 0:
            status = "POTENTIAL_ISSUE"
            why = "Decision conditions met numerically, but no matching snippets found (no evidence)."

    # Cap evidence and keep it readable
    evidence_out = evidence_sentences_all[:6]

    return {
        "status": status,
        "why": why,
        "counts": counts,
        "evidence": evidence_out,
        "matched_phrases": sorted(matched_phrases_all)[:30],  # keep small but useful
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
            "source_url": rule.get("source_url", ""),  # optional
            "why": outcome.get("why", ""),
            "evidence": outcome.get("evidence", []),
        })

    # stable ordering: sort rules by rule_id within each section
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
