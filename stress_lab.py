import os
import re
import json
import time
import random
import argparse
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple

import requests

from executor import run_rules_engine


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
MODEL = os.getenv("STRESS_MODEL", "gpt-4o-mini")
RULES_PATH = os.getenv("RULES_PATH", "rules/cobs-mvp-v2.yaml")
API_URL = "https://api.openai.com/v1/chat/completions"

RANDOM = random.Random(42)

SCENARIOS = [
    {
        "name": "strong_compliant",
        "label": "Strong compliant",
        "quality": "good",
        "prompt": """
Write a realistic UK financial adviser suitability report extract.

Requirements:
- Clearly personalised to the client
- Explicit personal recommendation
- Objectives stated
- Risk profile stated and linked to recommendation
- Capacity for loss explained
- Time horizon stated
- Alternatives considered and rejected
- Costs and charges quantified
- Material risks explained
- No certainty language
- Include standard warnings where appropriate

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["..."],
  "notes": "..."
}
""".strip(),
        "expected_band": "low_flags",
    },
    {
        "name": "minimal_compliant",
        "label": "Minimal but compliant",
        "quality": "good",
        "prompt": """
Write a concise but still compliant UK suitability report extract.

Requirements:
- Keep it brief
- Still include recommendation, objectives, risk, time horizon, and costs
- No certainty language
- Natural adviser tone

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["..."],
  "notes": "..."
}
""".strip(),
        "expected_band": "low_medium_flags",
    },
    {
        "name": "obviously_poor",
        "label": "Obviously poor",
        "quality": "bad",
        "prompt": """
Write a poor-quality UK suitability report extract.

Characteristics:
- vague objectives
- weak or absent recommendation detail
- no quantified costs
- no alternatives
- weak rationale
- little personalisation
- generic or missing risks

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["missing_costs", "missing_alternatives", "weak_rationale"],
  "notes": "..."
}
""".strip(),
        "expected_band": "high_flags",
    },
    {
        "name": "subtle_non_compliant",
        "label": "Subtle non-compliant",
        "quality": "borderline",
        "prompt": """
Write a polished, professional sounding UK suitability report extract that subtly fails regulatory expectations.

Use examples like:
- recommendation sounds plausible but is not clearly linked to objectives
- costs mentioned but not quantified
- risks generic rather than tailored
- alternatives mentioned but not properly rejected
- rationale sounds smooth but says little

Do not make it cartoonishly bad.

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["..."],
  "notes": "..."
}
""".strip(),
        "expected_band": "medium_flags",
    },
    {
        "name": "certainty_adversarial",
        "label": "Certainty / guarantee adversarial",
        "quality": "bad",
        "prompt": """
Write a UK adviser-style recommendation extract containing dangerous certainty language.

Use one or more of:
- guarantee
- guaranteed
- risk-free
- cannot lose
- safe investment
- will make you money
- your capital is safe

The wording should sound persuasive and polished.

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["certainty_language"],
  "notes": "..."
}
""".strip(),
        "expected_band": "high_flags",
    },
    {
        "name": "negation_edge",
        "label": "Negation edge cases",
        "quality": "good",
        "prompt": """
Write a UK suitability report extract that correctly explains uncertainty and risk.

Include natural wording such as:
- returns are not guaranteed
- there is no guarantee of return
- capital is at risk
- values can fall as well as rise

Make it realistic and compliant.

Return JSON only with:
{
  "report_text": "...",
  "context": {
    "advice_type": "advised",
    "investment_element": true,
    "ongoing_service": false
  },
  "inserted_themes": ["negated_guarantee_warning"],
  "notes": "..."
}
""".strip(),
        "expected_band": "very_low_flags",
    },
]

CLIENT_PROFILES = [
    "Client age 48, accumulating for retirement, balanced risk, 15-year horizon.",
    "Client age 61, retiring in 6 years, moderate risk, pension consolidation case.",
    "Client age 55, long-term growth objective, moderate adventurous risk, ISA and GIA review.",
    "Client age 67, preserving value with some growth, 8-year horizon, existing portfolio rebalance.",
    "Client age 44, medium-term family planning goals, balanced risk, monthly investing.",
    "Client age 72, decumulation planning, cautious-balanced risk, income and preservation focus.",
]

ADVICE_SHAPES = [
    "Use a pension recommendation with named wrapper and broad allocation.",
    "Use an ISA recommendation with diversified funds.",
    "Use an existing portfolio rebalance recommendation.",
    "Use a pension transfer or consolidation recommendation.",
]

LENGTH_GUIDANCE = [
    "Write 4 to 6 short paragraphs.",
    "Write 6 to 8 short paragraphs.",
    "Write 3 to 4 concise paragraphs.",
]


def call_llm_json(system_prompt: str, user_prompt: str, temperature: float = 0.8) -> Dict[str, Any]:
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY is missing")

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": MODEL,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }

    r = requests.post(API_URL, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    content = data["choices"][0]["message"]["content"]
    return json.loads(content)


def scrub_json_text(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"^```json\s*", "", s, flags=re.I)
    s = re.sub(r"^```\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    return s.strip()


def build_generation_prompt(scenario: Dict[str, Any]) -> str:
    profile = RANDOM.choice(CLIENT_PROFILES)
    shape = RANDOM.choice(ADVICE_SHAPES)
    length = RANDOM.choice(LENGTH_GUIDANCE)

    return f"""
{scenario["prompt"]}

Additional scenario instructions:
- {profile}
- {shape}
- {length}
- Use UK spelling
- Make the report realistic, not generic filler
- Do not mention rules, FCA, compliance, or that this is a test
""".strip()


def generate_case(scenario: Dict[str, Any], idx: int) -> Dict[str, Any]:
    system_prompt = """
You generate realistic UK adviser suitability report extracts for testing a deterministic compliance engine.
Return valid JSON only.
""".strip()

    user_prompt = build_generation_prompt(scenario)
    obj = call_llm_json(system_prompt, user_prompt, temperature=0.9)

    report_text = scrub_json_text(obj.get("report_text", ""))
    if not report_text:
        raise ValueError("Model returned empty report_text")

    context = obj.get("context") or {}
    context.setdefault("advice_type", "advised")
    context.setdefault("investment_element", True)
    context.setdefault("ongoing_service", False)

    return {
        "case_id": f"{scenario['name']}_{idx:03d}",
        "scenario": scenario["name"],
        "scenario_label": scenario["label"],
        "intended_quality": scenario["quality"],
        "expected_band": scenario["expected_band"],
        "report_text": report_text,
        "context": context,
        "inserted_themes": obj.get("inserted_themes") or [],
        "notes": obj.get("notes") or "",
    }


def flatten_results(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for section, items in (result.get("sections") or {}).items():
        for item in items or []:
            row = dict(item)
            row["section"] = section
            rows.append(row)
    return rows


def rule_status_map(result: Dict[str, Any]) -> Dict[str, str]:
    out = {}
    for row in flatten_results(result):
        out[row.get("rule_id", "")] = row.get("status", "")
    return out


def evaluate_case(case: Dict[str, Any]) -> Dict[str, Any]:
    result = run_rules_engine(
        document_text=case["report_text"],
        context=case["context"],
        rules_path=RULES_PATH,
    )

    rows = flatten_results(result)
    summary = result.get("summary") or {}
    status_map = rule_status_map(result)

    flags = [r for r in rows if r.get("status") == "POTENTIAL_ISSUE"]
    ok = [r for r in rows if r.get("status") == "OK"]

    # Heuristic expectations for stress testing
    expected_fail_rules = set()
    if "certainty_language" in case.get("inserted_themes", []):
        expected_fail_rules.add("COBS4_NO_GUAR_IMPLIED")
    if "missing_costs" in case.get("inserted_themes", []):
        expected_fail_rules.update({"COBS6_COSTS_DISC", "COBS6_COSTS_TOTAL"})
    if "missing_alternatives" in case.get("inserted_themes", []):
        expected_fail_rules.add("COBS9_ALTS")
    if "weak_rationale" in case.get("inserted_themes", []):
        expected_fail_rules.add("COBS9_RATIONALE")
    if "negated_guarantee_warning" in case.get("inserted_themes", []):
        expected_fail_rules.add("COBS4_NO_GUAR_IMPLIED__SHOULD_PASS")

    misses: List[str] = []
    false_pos_hints: List[str] = []

    for rid in sorted(expected_fail_rules):
        if rid.endswith("__SHOULD_PASS"):
            base = rid.replace("__SHOULD_PASS", "")
            if status_map.get(base) == "POTENTIAL_ISSUE":
                false_pos_hints.append(base)
        else:
            if status_map.get(rid) != "POTENTIAL_ISSUE":
                misses.append(rid)

    return {
        "case": case,
        "result": result,
        "flag_count": len(flags),
        "ok_count": len(ok),
        "missed_expected_rules": misses,
        "false_positive_hints": false_pos_hints,
        "rows": rows,
        "summary": summary,
    }


def aggregate(run_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(run_rows)
    by_scenario: Dict[str, Dict[str, Any]] = {}
    rule_hits: Dict[str, int] = {}
    rule_fp_hints: Dict[str, int] = {}
    rule_misses: Dict[str, int] = {}

    for row in run_rows:
        case = row["case"]
        scenario = case["scenario"]
        by_scenario.setdefault(
            scenario,
            {
                "count": 0,
                "flag_total": 0,
                "ok_total": 0,
                "cases_with_flags": 0,
                "misses": 0,
                "false_positive_hints": 0,
            },
        )
        bucket = by_scenario[scenario]
        bucket["count"] += 1
        bucket["flag_total"] += row["flag_count"]
        bucket["ok_total"] += row["ok_count"]
        if row["flag_count"] > 0:
            bucket["cases_with_flags"] += 1
        bucket["misses"] += len(row["missed_expected_rules"])
        bucket["false_positive_hints"] += len(row["false_positive_hints"])

        for rr in row["rows"]:
            if rr.get("status") == "POTENTIAL_ISSUE":
                rid = rr.get("rule_id", "")
                if rid:
                    rule_hits[rid] = rule_hits.get(rid, 0) + 1

        for rid in row["false_positive_hints"]:
            rule_fp_hints[rid] = rule_fp_hints.get(rid, 0) + 1

        for rid in row["missed_expected_rules"]:
            rule_misses[rid] = rule_misses.get(rid, 0) + 1

    return {
        "total_cases": total,
        "by_scenario": by_scenario,
        "top_rule_hits": sorted(rule_hits.items(), key=lambda x: (-x[1], x[0]))[:15],
        "top_false_positive_hints": sorted(rule_fp_hints.items(), key=lambda x: (-x[1], x[0]))[:15],
        "top_missed_expected_rules": sorted(rule_misses.items(), key=lambda x: (-x[1], x[0]))[:15],
    }


def build_analysis_input(run_rows: List[Dict[str, Any]], agg: Dict[str, Any]) -> Dict[str, Any]:
    sample_cases = []
    for row in run_rows[:]:
        case = row["case"]
        flagged = [r for r in row["rows"] if r.get("status") == "POTENTIAL_ISSUE"][:5]
        sample_cases.append(
            {
                "case_id": case["case_id"],
                "scenario": case["scenario"],
                "intended_quality": case["intended_quality"],
                "inserted_themes": case.get("inserted_themes", []),
                "flag_count": row["flag_count"],
                "missed_expected_rules": row["missed_expected_rules"],
                "false_positive_hints": row["false_positive_hints"],
                "flagged_rules": [
                    {
                        "rule_id": r.get("rule_id"),
                        "title": r.get("title"),
                        "evidence": r.get("evidence", [])[:2],
                    }
                    for r in flagged
                ],
                "report_excerpt": case["report_text"][:1200],
            }
        )

    return {
        "aggregate": agg,
        "sample_cases": sample_cases[:40],
    }


def analyse_with_llm(analysis_input: Dict[str, Any]) -> Dict[str, Any]:
    system_prompt = """
You are analysing regression output from a deterministic FCA suitability-report compliance engine.
Do not propose automatic rule changes.
Return JSON only.
""".strip()

    user_prompt = f"""
Review this stress-test output and produce a concise manual review pack.

Required output JSON shape:
{{
  "executive_summary": [
    "...",
    "..."
  ],
  "priority_rules_to_review": [
    {{
      "rule_id": "COBS4_NO_GUAR_IMPLIED",
      "reason": "...",
      "manual_change_options": ["...", "..."],
      "sample_failure_pattern": "..."
    }}
  ],
  "likely_false_positive_patterns": [
    {{
      "rule_id": "...",
      "pattern": "...",
      "why_it_looks_noisy": "..."
    }}
  ],
  "likely_false_negative_patterns": [
    {{
      "rule_id": "...",
      "pattern": "...",
      "why_it_looks_missed": "..."
    }}
  ],
  "permanent_regression_cases_to_add": [
    {{
      "case_name": "...",
      "why": "..."
    }}
  ]
}}

Data:
{json.dumps(analysis_input, ensure_ascii=False)}
""".strip()

    return call_llm_json(system_prompt, user_prompt, temperature=0.2)


def write_outputs(out_dir: Path, run_rows: List[Dict[str, Any]], agg: Dict[str, Any], ai_review: Dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    cases_path = out_dir / "cases.jsonl"
    with cases_path.open("w", encoding="utf-8") as f:
        for row in run_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary_path = out_dir / "aggregate.json"
    summary_path.write_text(json.dumps(agg, ensure_ascii=False, indent=2), encoding="utf-8")

    ai_path = out_dir / "ai_review.json"
    ai_path.write_text(json.dumps(ai_review, ensure_ascii=False, indent=2), encoding="utf-8")

    md = []
    md.append(f"# Stress test review\n")
    md.append(f"- Generated at: {datetime.utcnow().isoformat()}Z")
    md.append(f"- Model: {MODEL}")
    md.append(f"- Rules path: {RULES_PATH}")
    md.append(f"- Total cases: {agg['total_cases']}\n")

    md.append("## By scenario")
    for scenario, bucket in sorted(agg["by_scenario"].items()):
        avg_flags = round(bucket["flag_total"] / max(bucket["count"], 1), 2)
        md.append(
            f"- {scenario}: count={bucket['count']}, avg_flags={avg_flags}, "
            f"cases_with_flags={bucket['cases_with_flags']}, misses={bucket['misses']}, "
            f"fp_hints={bucket['false_positive_hints']}"
        )

    md.append("\n## Top triggered rules")
    for rid, n in agg["top_rule_hits"]:
        md.append(f"- {rid}: {n}")

    md.append("\n## Top missed expected rules")
    for rid, n in agg["top_missed_expected_rules"]:
        md.append(f"- {rid}: {n}")

    md.append("\n## Top false-positive hints")
    for rid, n in agg["top_false_positive_hints"]:
        md.append(f"- {rid}: {n}")

    md.append("\n## AI executive summary")
    for line in ai_review.get("executive_summary", []):
        md.append(f"- {line}")

    md.append("\n## Priority rules to review")
    for item in ai_review.get("priority_rules_to_review", []):
        md.append(f"- {item.get('rule_id')}: {item.get('reason')}")
        for opt in item.get("manual_change_options", []):
            md.append(f"  - manual option: {opt}")

    md.append("\n## Likely false negatives")
    for item in ai_review.get("likely_false_negative_patterns", []):
        md.append(f"- {item.get('rule_id')}: {item.get('pattern')}")

    md.append("\n## Likely false positives")
    for item in ai_review.get("likely_false_positive_patterns", []):
        md.append(f"- {item.get('rule_id')}: {item.get('pattern')}")

    md.append("\n## Permanent regression cases to add")
    for item in ai_review.get("permanent_regression_cases_to_add", []):
        md.append(f"- {item.get('case_name')}: {item.get('why')}")

    (out_dir / "review.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-scenario", type=int, default=3)
    parser.add_argument("--sleep", type=float, default=0.4)
    parser.add_argument("--out-dir", type=str, default="")
    args = parser.parse_args()

    if not OPENAI_API_KEY:
        raise RuntimeError("Set OPENAI_API_KEY before running")

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir) if args.out_dir else Path("stress_runs") / f"cycle1_{timestamp}"

    run_rows: List[Dict[str, Any]] = []
    total = len(SCENARIOS) * args.per_scenario
    counter = 0

    for scenario in SCENARIOS:
        for i in range(1, args.per_scenario + 1):
            counter += 1
            print(f"[{counter}/{total}] generating {scenario['name']} #{i}")
            case = generate_case(scenario, i)
            evaluated = evaluate_case(case)
            run_rows.append(evaluated)
            time.sleep(args.sleep)

    agg = aggregate(run_rows)
    analysis_input = build_analysis_input(run_rows, agg)
    ai_review = analyse_with_llm(analysis_input)
    write_outputs(out_dir, run_rows, agg, ai_review)

    print(f"\nDone. Outputs written to: {out_dir}")
    print(f"- {out_dir / 'cases.jsonl'}")
    print(f"- {out_dir / 'aggregate.json'}")
    print(f"- {out_dir / 'ai_review.json'}")
    print(f"- {out_dir / 'review.md'}")


if __name__ == "__main__":
    print("Starting stress_lab.py")
    main()
