import yaml
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional


EXECUTOR_VERSION = "2026-02-03-contract-v2"


# -----------------------------
# TEXT HELPERS (DETERMINISTIC)
# -----------------------------

def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower()).strip()


def split_sentences_with_offsets(text: str) -> List[Tuple[str, int, int]]:
    """
    Deterministic sentence splitter with offsets.
    Returns [(sentence, start_idx, end_idx), ...]
    """
    t = text or ""
    if not t.strip():
        return []

    spans: List[Tuple[str, int, int]] = []
    start = 0

    # Split on punctuation followed by whitespace (good enough + deterministic)
    for m in re.finditer(r"([.!?])\s+", t):
        end = m.end()  # include whitespace boundary
        sent = t[start:end].strip()
        if sent:
            s_start = t.find(sent, start, end)
            s_end = s_start + len(sent)
            spans.append((sent, s_start, s_end))
        start = end

    tail = t[start:].strip()
    if tail:
        s_start = t.find(tail, start)
        s_end = s_start + len(tail)
        spans.append((tail, s_start, s_end))

    return spans


def _iter_strings_deep(value: Any) -> List[str]:
    """
    Safely flatten any nested list structure and return only strings.
    This prevents `.lower()` explosions forever.
    """
    out: List[str] = []

    def rec(v: Any):
        if v is None:
            return
        if isinstance(v, str):
            s = v.strip()
            if s:
                out.append(s)
            return
        if isinstance(v, (list, tuple)):
            for x in v:
                rec(x)
            return
        # ignore dicts / numbers / anything else
        return

    rec(value)
    return out


def phrase_hits(
    sentence_spans: List[Tuple[str, int, int]],
    phrases_any_shape: Any,
    *,
    max_hits: int,
) -> List[Dict[str, Any]]:
    """
    Find phrase hits in sentences; returns capped hit objects:
    {"phrase": "...", "sentence": "...", "start": int, "end": int}
    """
    phrases = _iter_strings_deep(phrases_any_shape)
    if not phrases or not sentence_spans:
        return []

    hits: List[Dict[str, Any]] = []
    seen = set()

    for sent, s0, s1 in sentence_spans:
        sent_norm = sent.lower()
        for p in phrases:
            p_norm = p.lower()
            if p_norm and p_norm in sent_norm:
                key = (p_norm, s0, s1)
                if key in seen:
                    continue
                seen.add(key)

                hits.append(
                    {
                        "phrase": p,
                        "sentence": sent,
                        "start": s0,
                        "end": s1,
                    }
                )
                if len(hits) >= max_hits:
                    return hits

    return hits


def cluster_hits(
    sentence_spans: List[Tuple[str, int, int]],
    clusters_any_shape: Any,
    *,
    max_clusters: int,
    max_hits_per_cluster: int,
) -> Dict[str, Any]:
    """
    For cluster lists (list of lists), count how many clusters have >=1 hit.
    Returns:
      {
        "clusters_hit": int,
        "cluster_evidence": [
           {"cluster_index": i, "hits":[...hit objects...]},
        ]
      }
    """
    clusters: List[Any] = clusters_any_shape if isinstance(clusters_any_shape, list) else []
    clusters_hit = 0
    cluster_evidence: List[Dict[str, Any]] = []

    for i, cluster in enumerate(clusters):
        hits = phrase_hits(sentence_spans, cluster, max_hits=max_hits_per_cluster)
        if hits:
            clusters_hit += 1
            cluster_evidence.append({"cluster_index": i, "hits": hits})
            if clusters_hit >= max_clusters:
                break

    return {"clusters_hit": clusters_hit, "cluster_evidence": cluster_evidence}


# -----------------------------
# CONTRACT VALIDATION
# -----------------------------

def _require(d: Dict[str, Any], key: str, typ: Any, where: str):
    if key not in d:
        raise ValueError(f"[ruleset] missing required key '{key}' at {where}")
    if not isinstance(d[key], typ):
        raise ValueError(f"[ruleset] key '{key}' must be {typ.__name__} at {where}")
    return d[key]


def _validate_ruleset(ruleset: Dict[str, Any]):
    _require(ruleset, "ruleset_id", str, "root")
    _require(ruleset, "version", str, "root")
    rules = _require(ruleset, "rules", list, "root")

    for idx, rule in enumerate(rules):
        where = f"rules[{idx}]"
        if not isinstance(rule, dict):
            raise ValueError(f"[ruleset] rule must be object at {where}")

        _require(rule, "id", str, where)
        _require(rule, "section", dict, where)
        _require(rule["section"], "id", str, f"{where}.section")
        _require(rule["section"], "title", str, f"{where}.section")
        _require(rule, "citation", str, where)

        # evidence + decision must be dicts (no list nonsense)
        ev = _require(rule, "evidence", dict, where)
        _require(rule, "decision_logic", dict, where)

        # Evidence keys are optional, but if present must be list (any nested ok)
        for k in ["positive_clusters", "linkage_indicators", "negative_indicators"]:
            if k in ev and not isinstance(ev[k], list):
                raise ValueError(f"[ruleset] evidence.{k} must be a list at {where}")

        # applies_when optional dict
        if "applies_when" in rule and not isinstance(rule["applies_when"], dict):
            raise ValueError(f"[ruleset] applies_when must be object at {where}")


# -----------------------------
# RULE EVALUATION
# -----------------------------

def evaluate_rule(rule: Dict[str, Any], text: str, context: Dict[str, Any]) -> Dict[str, Any]:
    applies_when = rule.get("applies_when", {})
    for k, v in applies_when.items():
        if context.get(k) != v:
            return {"status": "NOT_ASSESSED", "evidence": {"sentences": [], "hits": []}}

    sentence_spans = split_sentences_with_offsets(text)
    ev = rule.get("evidence", {})
    decision = rule.get("decision_logic", {})

    # Caps (deterministic + prevents “whole document” dumps)
    caps = decision.get("caps", {}) if isinstance(decision.get("caps", {}), dict) else {}
    max_sentences = int(caps.get("max_sentences", 6))
    max_hits_total = int(caps.get("max_hits_total", 10))
    max_clusters = int(caps.get("max_clusters", 3))
    max_hits_per_cluster = int(caps.get("max_hits_per_cluster", 2))

    # Compute evidence
    pos = cluster_hits(
        sentence_spans,
        ev.get("positive_clusters", []),
        max_clusters=max_clusters,
        max_hits_per_cluster=max_hits_per_cluster,
    )
    link_hits = phrase_hits(sentence_spans, ev.get("linkage_indicators", []), max_hits=max_hits_total)
    neg_hits = phrase_hits(sentence_spans, ev.get("negative_indicators", []), max_hits=max_hits_total)

    counts = {
        "positive_clusters": int(pos["clusters_hit"]),
        "linkage_indicators": int(len(link_hits)),
        "negative_indicators": int(len(neg_hits)),
    }

    # Decision: OK if all ok_if conditions pass AND (if fail_on_negative) no negatives
    ok_if = decision.get("ok_if", [])
    if not isinstance(ok_if, list):
        ok_if = []

    fail_on_negative = bool(decision.get("fail_on_negative", False))

    def cond_pass(c: Any) -> bool:
        # Supported condition forms:
        # {"type":"clusters_at_least","key":"positive_clusters","n":2}
        # {"type":"hits_at_least","key":"linkage_indicators","n":1}
        if not isinstance(c, dict):
            return False
        ctype = c.get("type")
        key = c.get("key")
        n = c.get("n")
        if ctype not in ("clusters_at_least", "hits_at_least"):
            return False
        if key not in counts:
            return False
        try:
            n_int = int(n)
        except Exception:
            return False
        return counts[key] >= n_int

    ok_pass = all(cond_pass(c) for c in ok_if) if ok_if else True
    if fail_on_negative and counts["negative_indicators"] > 0:
        ok_pass = False

    status = "OK" if ok_pass else "POTENTIAL_ISSUE"

    # Build compact evidence: dedupe sentences, cap, and also include hit phrases
    all_hit_objs: List[Dict[str, Any]] = []
    # Pull representative hits (cluster hits first)
    for ce in pos.get("cluster_evidence", []):
        all_hit_objs.extend(ce.get("hits", []))
    all_hit_objs.extend(link_hits)
    all_hit_objs.extend(neg_hits)

    # Dedup hits
    dedup_hits = []
    seen = set()
    for h in all_hit_objs:
        if not isinstance(h, dict):
            continue
        phrase = (h.get("phrase") or "").strip()
        sent = (h.get("sentence") or "").strip()
        key = (phrase.lower(), sent.lower())
        if not phrase or not sent or key in seen:
            continue
        seen.add(key)
        dedup_hits.append({"phrase": phrase, "sentence": sent})

    # Cap sentences based on dedup hits
    sentences = []
    seen_s = set()
    for h in dedup_hits:
        s = h["sentence"]
        k = s.lower()
        if k in seen_s:
            continue
        seen_s.add(k)
        sentences.append(s)
        if len(sentences) >= max_sentences:
            break

    return {
        "status": status,
        "counts": counts,
        "evidence": {
            "sentences": sentences,
            "hits": dedup_hits[:max_hits_total],
        },
    }


# -----------------------------
# EXECUTOR ENTRY
# -----------------------------

def run_rules_engine(document_text: str, context: Dict[str, Any], rules_path: str) -> Dict[str, Any]:
    with open(rules_path, "r", encoding="utf-8") as f:
        ruleset = yaml.safe_load(f) or {}

    _validate_ruleset(ruleset)

    results: List[Dict[str, Any]] = []
    sections_map: Dict[str, Dict[str, Any]] = {}

    for rule in ruleset["rules"]:
        outcome = evaluate_rule(rule, document_text, context)

        section = rule["section"]
        sec_id = section["id"]
        if sec_id not in sections_map:
            sections_map[sec_id] = {"section_id": sec_id, "section_title": section["title"], "rules": []}

        res = {
            "rule_id": rule["id"],
            "section_id": sec_id,
            "status": outcome["status"],
            "citation": rule["citation"],
            "source_url": rule.get("source_url"),
            "counts": outcome.get("counts", {}),
            "evidence": outcome.get("evidence", {"sentences": [], "hits": []}),
        }
        results.append(res)
        sections_map[sec_id]["rules"].append(res)

    summary = {
        "ok": sum(1 for r in results if r["status"] == "OK"),
        "potential_issue": sum(1 for r in results if r["status"] == "POTENTIAL_ISSUE"),
        "not_assessed": sum(1 for r in results if r["status"] == "NOT_ASSESSED"),
    }

    sections = list(sections_map.values())

    return {
        "executor_version": EXECUTOR_VERSION,
        "ruleset_id": ruleset["ruleset_id"],
        "ruleset_version": ruleset["version"],
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "summary": summary,
        "results": results,
        "sections": sections,
    }
