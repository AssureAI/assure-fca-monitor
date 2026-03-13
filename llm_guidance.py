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
    title = (title or "").strip() or (rule_id or "").strip() or "Rule"
    parts = [f"Rule: {title}"]
    if rule_id:
        parts.append(f"Rule ID: {rule_id}")
    if section:
        parts.append(f"Section: {section}")
    if citation:
        parts.append(f"Citation: {sanitize_for_llm(citation)}")
    if decision_logic:
        parts.append(f"Decision logic: {sanitize_for_llm(decision_logic)}")
    if evidence:
        parts.append("Evidence:")
        for e in evidence[:6]:
            if isinstance(e, str) and e.strip():
                parts.append(f"- {sanitize_for_llm(e)}")
    if fixes:
        parts.append("Fixes:")
        for f in fixes[:6]:
            if isinstance(f, str) and f.strip():
                parts.append(f"- {sanitize_for_llm(f)}")
    return "\n".join(parts)
