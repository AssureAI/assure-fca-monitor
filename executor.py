import re
import yaml
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


EXECUTOR_VERSION = "2026-02-25-v2.0-hardened"


# -----------------------------
# TEXT HELPERS
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def normalise_lower(text: str) -> str:
    return normalise(text).lower()


def split_sentences(text: str) -> List[str]:
    # Deterministic, decent-enough sentence splitting (avoid heavy NLP deps)
    t = normalise(text)
    if not t:
        return []
    parts = re.split(r'(?<=[\.\?\!])\s+|\n{2,}', t)
    out = []
    for p in parts:
        p = p.strip()
        if p:
            out.append(p)
    return out


def unique_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        k = x.strip()
        if not k:
            continue
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def find_hits_by_terms(sentences: List[str], terms: List[str]) -> List[str]:
    if not terms:
        return []
    terms_l = [t.lower() for t in terms]
    hits = []
    for s in sentences:
        s_l = s.lower()
        for t in terms_l:
            if t and t in s_l:
                hits.append(s)
                break
    return hits


def find_hits_by_patterns(sentences: List[str], patterns: List[str]) -> List[str]:
    if not patterns:
        return []
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    hits = []
    for s in sentences:
        for rx in compiled:
            if rx.search(s):
                hits.append(s)
                break
    return hits


# -----------------------------
# STRUCTURED EXTRACTORS
# -----------------------------

PCT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,2})?)\s*%")
AGE_RE = re.compile(r"\bage\s*(\d{1,3})\b", re.IGNORECASE)
RETIRE_AGE_RE = re.compile(r"\bretire(?:ment)?\s*(?:at|age)\s*(\d{1,3})\b", re.IGNORECASE)
HORIZON_YEARS_RE = re.compile(r"\bnext\s*(\d{1,2})\s*years?\b|\b(\d{1,2})\s*year\s*(?:time\s*)?horizon\b", re.IGNORECASE)

EQUITY_WORDS = [
    "equity", "equities", "global equity", "uk equity", "emerging markets", "shares", "stock", "stocks"
]
BOND_WORDS = [
    "bond", "bonds", "fixed income", "gilts", "credit", "strategic bond"
]
DIVERSIFY_WORDS = [
    "diversif", "asset class", "multi-asset", "balanced", "spread risk", "mix of", "allocation across"
]

def extract_age(text: str) -> Optional[int]:
    m = AGE_RE.search(text or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except:
        return None


def extract_retire_age(text: str) -> Optional[int]:
    m = RETIRE_AGE_RE.search(text or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except:
        return None


def infer_years_to_retirement(text: str) -> Optional[int]:
    a = extract_age(text)
    r = extract_retire_age(text)
    if a is None or r is None:
        return None
    yrs = r - a
    if yrs < 0 or yrs > 80:
        return None
    return yrs


def extract_horizon_years(text: str) -> Optional[int]:
    m = HORIZON_YEARS_RE.search(text or "")
    if not m:
        return None
    for g in m.groups():
        if g:
            try:
                return int(g)
            except:
                pass
    return None


def parse_allocation_blocks(text: str) -> List[Tuple[str, float]]:
    """
    Very lightweight allocation parser.
    Returns list of (label, pct) from bullet-like lines containing %.
    """
    allocations: List[Tuple[str, float]] = []
    if not text:
        return allocations

    lines = [ln.strip(" \t•-*") for ln in (text.splitlines() or [])]
    for ln in lines:
        if not ln:
            continue
        m = PCT_RE.search(ln)
        if not m:
            continue
        try:
            pct = float(m.group(1))
        except:
            continue
        label = PCT_RE.sub("", ln).strip(" :-–—")
        if not label:
            label = "unknown"
        allocations.append((label, pct))
    return allocations


def equity_pct_from_allocations(allocs: List[Tuple[str, float]]) -> Optional[float]:
    if not allocs:
        return None
    eq = 0.0
    total = 0.0
    for label, pct in allocs:
        total += pct
        l = (label or "").lower()
        if any(w in l for w in EQUITY_WORDS):
            eq += pct
    # ignore if totals look insane
    if total < 20 or total > 150:
        # could still be valid, but we avoid confident numeric assertions
        return None
    return eq


def has_any_words(text: str, words: List[str]) -> bool:
    t = (text or "").lower()
    return any(w.lower() in t for w in words)


# -----------------------------
# RULE EVALUATION
# -----------------------------

def applies_when_ok(applies: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    supports:
      key: value
      key: [v1, v2]
    """
    if not applies:
        return True
    for k, v in applies.items():
        cv = context.get(k)
        if isinstance(v, list):
            if cv not in v:
                return False
        else:
            if cv != v:
                return False
    return True


def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    if not applies_when_ok(rule.get("applies_when", {}), context):
        return {"status": "NOT_ASSESSED", "evidence": [], "why": "Rule not applicable for selected inputs.", "missing": []}

    sentences = split_sentences(text)
    text_l = normalise_lower(text)

    # Signals
    require_any_terms = rule.get("require_any_terms", []) or []
    require_any_patterns = rule.get("require_any_patterns", []) or []
    require_all_terms = rule.get("require_all_terms", []) or []
    forbid_any_terms = rule.get("forbid_any_terms", []) or []
    forbid_any_patterns = rule.get("forbid_any_patterns", []) or []

    hits = []
    hits += find_hits_by_terms(sentences, require_any_terms)
    hits += find_hits_by_patterns(sentences, require_any_patterns)

    # All-terms enforcement (best-effort)
    all_ok = True
    missing_all = []
    for t in require_all_terms:
        if t.lower() not in text_l:
            all_ok = False
            missing_all.append(t)

    # Forbid checks
    forbid_hits = []
    forbid_hits += find_hits_by_terms(sentences, forbid_any_terms)
    forbid_hits += find_hits_by_patterns(sentences, forbid_any_patterns)

    # Structured checks
    structured = rule.get("structured_checks", {}) or {}
    structured_findings = []
    structured_ok = True
    structured_missing = []

    if structured:
        # Retirement equity mismatch: near retirement + high equity + lacks balancing language
        if structured.get("type") == "retirement_equity_mismatch":
            yrs = infer_years_to_retirement(text)  # may be None
            horizon = extract_horizon_years(text)
            yrs_effective = yrs if yrs is not None else horizon

            allocs = parse_allocation_blocks(text)
            eq_pct = equity_pct_from_allocations(allocs)

            # thresholds configurable
            max_years = int(structured.get("near_retirement_years", 7))
            eq_threshold = float(structured.get("equity_pct_threshold", 70.0))

            balancing_terms = structured.get("balancing_terms", []) or []
            has_balancing = has_any_words(text, balancing_terms) if balancing_terms else has_any_words(text, DIVERSIFY_WORDS + BOND_WORDS)

            if yrs_effective is None:
                # If we can't infer, we *don't* fail the rule; we mark as missing context
                structured_ok = False
                structured_missing.append("Could not infer time-to-retirement / investment horizon.")
            else:
                if yrs_effective <= max_years:
                    # We are near retirement; now check equity %
                    if eq_pct is None:
                        structured_ok = False
                        structured_missing.append("Could not confidently detect equity allocation %.")
                    else:
                        if eq_pct >= eq_threshold and not has_balancing:
                            # This is the *risk* condition; for this rule, meeting condition means POTENTIAL_ISSUE.
                            structured_findings.append(
                                f"Detected approx equity allocation {eq_pct:.0f}% with horizon {yrs_effective}y and no balancing/diversification language."
                            )
                        else:
                            # Not a mismatch
                            pass
                else:
                    # Not near retirement -> not applicable
                    return {"status": "NOT_ASSESSED", "evidence": [], "why": f"Not near retirement (inferred horizon {yrs_effective}y).", "missing": []}

    # Decide status
    min_hits = int(rule.get("min_hits", 1))

    # Special rule mode: "forbid_only" means OK if no forbidden hits; POTENTIAL_ISSUE if forbidden hits.
    if rule.get("mode") == "forbid_only":
        if forbid_hits:
            ev = unique_preserve_order(forbid_hits)[: int(rule.get("evidence_cap", 5))]
            return {
                "status": "POTENTIAL_ISSUE",
                "evidence": ev,
                "why": "Prohibited / risky wording detected.",
                "missing": [],
            }
        return {"status": "OK", "evidence": [], "why": "No prohibited / risky wording detected.", "missing": []}

    # Structured mismatch mode: if findings exist -> POTENTIAL_ISSUE
    if structured.get("type") == "retirement_equity_mismatch":
        if structured_findings:
            return {
                "status": "POTENTIAL_ISSUE",
                "evidence": [],
                "why": "Retirement/equity mismatch risk flagged.",
                "missing": [],
                "details": structured_findings,
            }
        # If we tried and couldn't infer, treat as POTENTIAL_ISSUE with why, unless rule says otherwise
        if structured_missing:
            return {
                "status": "POTENTIAL_ISSUE",
                "evidence": [],
                "why": "Unable to confirm retirement/equity balance from document.",
                "missing": structured_missing,
            }
        return {"status": "OK", "evidence": [], "why": "No retirement/equity mismatch detected.", "missing": []}

    # Standard positive-signal rule:
    ok_by_hits = len(unique_preserve_order(hits)) >= min_hits
    ok_by_all = all_ok
    ok_by_forbid = not bool(forbid_hits)

    if ok_by_hits and ok_by_all and ok_by_forbid:
        ev = unique_preserve_order(hits)[: int(rule.get("evidence_cap", 5))]
        return {"status": "OK", "evidence": ev, "why": "Required signals found.", "missing": []}

    # Potential issue
    ev = unique_preserve_order(hits)[: int(rule.get("evidence_cap", 5))]
    missing = []
    # Missing “any” signals: report what it was looking for
    if not ok_by_hits:
        missing += (require_any_terms or [])
    if not ok_by_all:
        missing += missing_all
    if forbid_hits:
        # show the forbidden signals as "missing" isn't right; keep them as evidence for why
        ev2 = unique_preserve_order(forbid_hits)[: int(rule.get("evidence_cap", 5))]
        return {
            "status": "POTENTIAL_ISSUE",
            "evidence": ev2,
            "why": "Risky/prohibited wording detected.",
            "missing": [],
        }

    return {
        "status": "POTENTIAL_ISSUE",
        "evidence": ev,
        "why": "Required signals not found.",
        "missing": unique_preserve_order(missing)[:15],
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

    ruleset_id = ruleset.get("ruleset_id") or ruleset.get("ruleset", {}).get("id") or "unknown-ruleset"
    version = ruleset.get("version") or ruleset.get("ruleset", {}).get("version") or "unknown"

    sections: Dict[str, List[Dict[str, Any]]] = {}

    for rule in (ruleset.get("rules") or []):
        outcome = evaluate_rule(rule, document_text or "", context or {})

        section = rule.get("section", "Unsorted")
        sections.setdefault(section, [])

        sections[section].append({
            "rule_id": rule.get("id", "UNKNOWN"),
            "title": rule.get("title", ""),
            "status": outcome.get("status", "NOT_ASSESSED"),
            "citation": rule.get("citation", ""),
            "source_url": rule.get("source_url", ""),  # OPTIONAL
            "evidence": outcome.get("evidence", []),
            "why": outcome.get("why", ""),
            "missing": outcome.get("missing", []),
            "details": outcome.get("details", []),
        })

    summary = {
        "ok": sum(1 for rs in sections.values() for r in rs if r["status"] == "OK"),
        "potential_issue": sum(1 for rs in sections.values() for r in rs if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for rs in sections.values() for r in rs if r["status"] == "NOT_ASSESSED"),
    }

    return {
        "executor_version": EXECUTOR_VERSION,
        "ruleset_id": ruleset_id,
        "ruleset_version": version,
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "sections": sections,
    }