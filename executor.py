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
    "isn't", "aren't", "won't", "don't", "doesn't", "didn't",
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
        if tokens[i : i + len(p_tokens)] == p_tokens:
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

            per_seen = set()
            per_list: List[str] = []
            for s in ev:
                if s not in per_seen:
                    per_list.append(s)
                    per_seen.add(s)
            evidence_by_cluster[idx] = per_list

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
# HUMAN "WHAT TO FIX" + SUGGESTED WORDING
# ---------------------------------

RULE_FIXES: Dict[str, List[str]] = {
    "COBS4_BALANCED": [
        "Add at least one clear benefit of the recommendation (why it helps meet the client’s objectives).",
        "Add at least one clear risk/disadvantage (what could go wrong, including capital at risk where relevant).",
        "Keep benefits and risks close together so the narrative reads balanced.",
    ],
    "COBS4_NO_GUAR_IMPLIED": [
        "Remove any wording that implies certainty (e.g. “guaranteed”, “will”, “risk-free”).",
        "Add a clear statement that returns are not guaranteed and capital may be at risk.",
    ],
    "COBS4_PAST_PERF": [
        "If you mention past performance, include the warning that it is not a reliable indicator of future performance.",
        "If you include projections/illustrations, explain key assumptions and that outcomes may differ materially.",
    ],
    "COBS6_COSTS_DISC": [
        "State platform/product charges and ongoing fund charges (OCF) clearly.",
        "Include numeric values (e.g. percentages) rather than generic statements like “charges apply”.",
        "If relevant, show adviser initial/ongoing fees separately.",
    ],
    "COBS6_COSTS_TOTAL": [
        "Provide an aggregated/total ongoing cost figure (e.g. ‘total ongoing charge is ~X% p.a.’).",
        "Make it clear whether the figure includes platform + fund costs (+ adviser fee if applicable).",
    ],
    "COBS9_ALTS": [
        "List the reasonable alternatives considered (e.g. do nothing, keep existing, lower-risk option).",
        "State why alternatives were rejected (tie it back to objectives, risk, time horizon, costs).",
    ],
    "COBS9_CFL": [
        "Explain capacity for loss using a scenario (e.g. ‘in a downturn you could tolerate ~15–20% fall…’).",
        "Link the scenario to essentials/lifestyle/retirement plan impact.",
    ],
    "COBS9_CIRC": [
        "Add key personal/financial circumstances (income, assets, debts, dependants, emergency fund, retirement timing).",
        "Include enough context to show you considered the client’s situation, not just a risk score.",
    ],
    "COBS9_CHANGES": [
        "Record explicit client understanding/confirmation (e.g. confirms they understand risks and volatility).",
    ],
    "COBS9_DOWNSIDES": [
        "Include disadvantages/drawbacks that are specific to the recommendation (not only generic market-risk text).",
    ],
    "COBS9_KNOWEXP": [
        "Reference the client’s knowledge/experience where relevant (previous investing, familiarity with products).",
        "If experience is limited, acknowledge it and show how the recommendation remains appropriate.",
    ],
    "COBS9_RISKS": [
        "Explain material risks in plain English (market risk, volatility, concentration, liquidity, inflation).",
        "Include ‘capital at risk’ language where appropriate.",
    ],
    "COBS9_OBJ": [
        "State the client’s objectives clearly (what they want to achieve and by when).",
        "Show how the recommendation links to those objectives (not just restating them).",
    ],
    "COBS9_RECO": [
        "Make the recommendation explicit (what to do, where, and what allocation/portfolio).",
    ],
    "COBS9_RISK": [
        "State the assessed attitude to risk.",
        "Explain how the recommended portfolio matches that risk profile (link risk → allocation).",
        "Avoid any certainty/guarantee language.",
    ],
    "COBS9_RATIONALE": [
        "Explain the rationale using ‘because… therefore…’ (why this is suitable for this client).",
        "Tie the rationale to objectives, time horizon, risk profile, costs, and circumstances.",
    ],
    "COBS9_TIME": [
        "State the investment time horizon (e.g. years to retirement / intended holding period).",
        "Link time horizon to asset mix (why equities/bonds/cash proportions make sense).",
    ],
    "SR_STRUCT_CLIENT_DETAILS": [
        "Include client name and key metadata (date, adviser, firm) near the top of the report.",
    ],
    "SR_STRUCT_NEXT_STEPS": [
        "Add clear next steps (transfer/implementation steps, what happens after sign-off, review if applicable).",
    ],
}

RULE_SUGGESTED_WORDING: Dict[str, List[str]] = {
    "COBS4_PAST_PERF": [
        "Past performance is not a reliable indicator of future performance.",
        "If projections are shown, they are based on assumptions and actual outcomes may differ materially.",
    ],
    "COBS4_NO_GUAR_IMPLIED": [
        "Investment returns are not guaranteed and the value of investments can fall as well as rise.",
        "You may get back less than you invested.",
    ],
    "COBS6_COSTS_TOTAL": [
        "The total ongoing charge is therefore approximately X% per annum (platform + fund costs).",
    ],
    "COBS9_CFL": [
        "In a severe market downturn you could tolerate an approximate X% fall in value without materially affecting essential expenditure or retirement plans.",
    ],
    "COBS9_RATIONALE": [
        "Because you have a time horizon of X years and a Balanced risk profile, the recommended allocation aims to support long-term growth while moderating volatility through diversification.",
    ],
}

_BUCKET_LABELS: Dict[str, str] = {
    "benefit_clusters": "a clear benefit statement",
    "risk_clusters": "a clear risk/disadvantage statement",
    "warning_clusters": "a past performance warning",
    "trigger_clusters": "a past performance reference",
    "prohibited_phrases": "remove guarantee/certainty language",
    "allowed_negations": "add a ‘no guarantee’ style disclaimer",
    "cost_clusters": "cost/charge disclosure",
    "cost_specific": "specific cost items (platform/fund/adviser fees)",
    "numeric_indicators": "numeric values (%, £, p.a., etc.)",
    "positive_clusters": "supporting wording for this control",
    "linkage_indicators": "explicit linkage between client facts and recommendation",
    "negative_indicators": "remove problematic/negative wording for this control",
    "contextual_indicators": "scenario framing / context explanation",
    "hard_circumstances": "core circumstances (income/assets/debts/dependants/emergency fund)",
    "supporting_circumstances": "supporting circumstances (existing arrangements, goals, retirement timing)",
    "causal_language": "causal rationale (‘because/therefore/as a result’)",
}


def _humanise_missing(missing: List[str]) -> List[str]:
    """
    Converts items like 'hard_circumstances >=1 (actual=0)' into plain-English bullets.
    We do NOT expose the raw operator/threshold to end users.
    """
    out: List[str] = []
    for m in missing or []:
        mm = (m or "").strip()
        if not mm:
            continue

        key = mm.split(" ", 1)[0].strip()
        label = _BUCKET_LABELS.get(key)

        if key in ("prohibited_phrases", "negative_indicators"):
            out.append("Remove wording that implies certainty/guarantees or otherwise breaches this control.")
            continue

        if key == "warning_clusters":
            out.append("Add the standard warning alongside any past performance references.")
            continue

        if label:
            out.append(f"Add {label} so this control is evidenced.")
        else:
            if "decision_logic missing" in mm:
                out.append("This rule cannot be assessed because the ruleset is incomplete (missing decision logic).")
            else:
                out.append("Add clearer wording/evidence so this control is evidenced in the report.")

    seen = set()
    deduped: List[str] = []
    for x in out:
        if x not in seen:
            deduped.append(x)
            seen.add(x)
    return deduped


# ---------------------------------
# RULE EVALUATION
# ---------------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = rule.get("id", "") or ""

    def _pack(
        *,
        status: str,
        why: str,
        counts: Dict[str, int],
        evidence: List[str],
        evidence_by_key: Dict[str, List[str]],
        missing: List[str],
        details: List[str],
    ) -> Dict[str, Any]:
        fixes: List[str] = []
        suggested_wording: List[str] = []

        if status != "OK":
            fixes = list(RULE_FIXES.get(rule_id, []))
            if not fixes:
                fixes = _humanise_missing(missing)
            if not fixes:
                fixes = ["Add clear wording/evidence so this control is evidenced in the report."]
            suggested_wording = list(RULE_SUGGESTED_WORDING.get(rule_id, []))

        return {
            "status": status,
            "why": why,
            "counts": counts,
            "evidence": evidence[:6],
            "evidence_by_key": evidence_by_key,
            "missing": missing,
            "details": details,
            "fixes": fixes,
            "suggested_wording": suggested_wording,
        }

    if not applies(rule.get("applies_when") or {}, context):
        return _pack(
            status="NOT_ASSESSED",
            why="Rule not applicable for current context.",
            counts={},
            evidence=[],
            evidence_by_key={},
            missing=[],
            details=[],
        )

    sentences = split_sentences(text)
    evidence_spec = rule.get("evidence") or {}
    decision = rule.get("decision_logic") or {}

    counts: Dict[str, int] = {}
    evidence_by_key: Dict[str, List[str]] = {}

    evidence_sentences: List[str] = []
    evidence_seen = set()

    def _merge_global(ev_sents: List[str], cap: int = 6) -> None:
        for s in ev_sents:
            if len(evidence_sentences) >= cap:
                break
            if s not in evidence_seen:
                evidence_sentences.append(s)
                evidence_seen.add(s)

    # 1) Count evidence buckets
    if isinstance(evidence_spec, dict):
        for key, spec in evidence_spec.items():
            allow_if_negated = True
            if key in ("negative_indicators", "prohibited_phrases", "must_not_contain"):
                allow_if_negated = False

            if key.endswith("_clusters"):
                satisfied_n, _phrases, ev, _by_cluster = cluster_hits(
                    sentences,
                    spec,
                    allow_if_negated=True,
                    max_evidence=6,
                )
                counts[key] = satisfied_n
                evidence_by_key[key] = ev
                _merge_global(ev, cap=6)
            else:
                hit_n, _phrases, ev, _pairs = phrase_hits(
                    sentences,
                    spec,
                    allow_if_negated=allow_if_negated,
                    max_evidence=6,
                )
                counts[key] = hit_n
                evidence_by_key[key] = ev
                _merge_global(ev, cap=6)

    # 2) “No guarantees” override: if negation exists, don’t treat prohibited phrases as failing
    if counts.get("prohibited_phrases", 0) > 0 and counts.get("allowed_negations", 0) > 0:
        counts["prohibited_phrases"] = 0

    # 3) Decision logic
    if not isinstance(decision, dict) or len(decision.keys()) == 0:
        return _pack(
            status="POTENTIAL_ISSUE",
            why="No decision_logic provided (cannot auto-pass).",
            counts=counts,
            evidence=evidence_sentences,
            evidence_by_key=evidence_by_key,
            missing=["decision_logic missing"],
            details=[],
        )

    require_all = decision.get("require_all")
    require_none = decision.get("require_none")
    allow_if_present = decision.get("allow_if_present")

    ok_all, missing_all, details_all = _eval_require_block(counts, require_all, block_name="require_all")
    ok_none, missing_none, details_none = _eval_require_block(counts, require_none, block_name="require_none")
    _ok_allow, _missing_allow, details_allow = _eval_require_block(counts, allow_if_present, block_name="allow_if_present")

    details: List[str] = []
    details.extend(details_all)
    details.extend(details_none)
    details.extend(details_allow)

    missing: List[str] = []
    if not ok_all:
        missing.extend(missing_all)
    if not ok_none:
        missing.extend(missing_none)

    # Strict: if nothing matched at all, treat as missing evidence
    total_hits = sum(int(v) for v in counts.values())
    if total_hits == 0:
        return _pack(
            status="POTENTIAL_ISSUE",
            why="No supporting wording found in the report.",
            counts=counts,
            evidence=[],
            evidence_by_key=evidence_by_key,
            missing=["All required signals (none matched)"],
            details=[],
        )

    status = "OK" if (ok_all and ok_none) else "POTENTIAL_ISSUE"

    # Must have evidence to be OK
    if status == "OK" and len(evidence_sentences) == 0:
        status = "POTENTIAL_ISSUE"
        missing.append("No evidence sentences (cannot assert OK).")
        details.append("Downgraded: decision passed but evidence list empty.")

    why = "OK" if status == "OK" else "Conditions not met."

    return _pack(
        status=status,
        why=why,
        counts=counts,
        evidence=evidence_sentences,
        evidence_by_key=evidence_by_key,
        missing=missing,
        details=details,
    )


# ---------------------------------
# RULESET LOAD
# ---------------------------------

def _resolve_rules_path(default_path: str) -> str:
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

        grouped[section].append(
            {
                "rule_id": rule.get("id", ""),
                "title": rule.get("title", ""),
                "status": outcome.get("status", "POTENTIAL_ISSUE"),
                "citation": rule.get("citation", ""),
                "source_url": rule.get("source_url") or "",
                "why": outcome.get("why", ""),

                # product UI fields (always present; empty lists if OK)
                "fixes": outcome.get("fixes", []) or [],
                "suggested_wording": outcome.get("suggested_wording", []) or [],

                # keep for debugging/admin views
                "counts": outcome.get("counts", {}) or {},
                "missing": outcome.get("missing", []) or [],
                "details": outcome.get("details", []) or [],
                "evidence": outcome.get("evidence", []) or [],
                "evidence_by_key": outcome.get("evidence_by_key", {}) or {},
            }
        )

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