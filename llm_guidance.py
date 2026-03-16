"""
Demo-safe LLM rule guidance: sanitization and prompt building.
"""
from __future__ import annotations

import re
from typing import List, Optional


def sanitize_for_llm(text: str) -> str:
    """
    Simple regex masking: emails, dates, long numbers, currency.
    """
    if not text or not isinstance(text, str):
        return ""
    s = text.strip()
    if not s:
        return ""
    # emails
    s = re.sub(
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "[EMAIL]",
        s,
        flags=re.IGNORECASE,
    )
    # dates (UK and ISO)
    s = re.sub(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "[DATE]", s)
    s = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "[DATE]", s)
    # long numbers (5+ digits)
    s = re.sub(r"\b\d{5,}\b", "[NUMBER]", s)
    # currency
    s = re.sub(r"£\s*[\d,]+\.?\d*", "[CURRENCY]", s)
    s = re.sub(r"\b[\d,]+\.?\d*\s*%", "[PERCENT]", s)
    return s.strip()


def build_rule_guidance_prompt(
    rule_id: str = "",
    title: str = "",
    citation: str = "",
    decision_logic: Optional[str] = None,
    evidence: Optional[List[str]] = None,
    fixes: Optional[List[str]] = None,
    section: str = "",
) -> str:
    """
    Build a single prompt string from allowed fields. All text is sanitized.
    """
    instructions = [
        "Instructions. The response must:",
        "- be explanatory only",
        "- not ask questions",
        "- not offer further help",
        "- not suggest tailoring to a client",
        "- not give advice",
        "- not use conversational phrases like: \"would you like\", \"you should consider\", \"I recommend\", \"you may want to\", \"let me know\", \"for your client\"",
        "",
        "Tone must be: neutral, factual, regulatory explanation, not advisory.",
        "",
        "The model must never provide financial advice. The model must never provide suitability recommendations. The model must only explain the rule and why it may have triggered.",
        "",
    ]
    title = (title or "").strip() or (rule_id or "").strip() or "Rule"
    parts = ["\n".join(instructions), f"Rule: {title}"]
    if rule_id:
        parts.append(f"Rule ID: {rule_id}")
    if section:
        parts.append(f"Section: {section}")
    if citation:
        parts.append(f"Citation: {sanitize_for_llm(citation)}")
    if decision_logic:
        dl = sanitize_for_llm(decision_logic)
        if len(dl) > 800:
            dl = dl[:800]
        parts.append(f"Decision logic: {dl}")
    if evidence:
        parts.append("Evidence:")
        for e in evidence[:3]:
            if isinstance(e, str) and e.strip():
                ev = sanitize_for_llm(e)
                if len(ev) > 220:
                    ev = ev[:220]
                parts.append(f"- {ev}")
    if fixes:
        parts.append("Fixes:")
        for f in fixes[:2]:
            if isinstance(f, str) and f.strip():
                fx = sanitize_for_llm(f)
                if len(fx) > 220:
                    fx = fx[:220]
                parts.append(f"- {fx}")
    return "\n".join(parts)
