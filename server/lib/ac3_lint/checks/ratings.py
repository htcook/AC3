"""
Rating word consistency.

Catches narrative text that contradicts the computed risk band. This is the
most-cited symptom of stale prompt-template variables: the score is updated,
but the narrative still references the rating word that was in the example.
"""

from __future__ import annotations

import re
from typing import List

from ..issues import LintIssue, Severity
from ..models import get, iter_text_blocks


_BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL", "INFORMATIONAL")

_RATING_PHRASE = re.compile(
    r"\b(?:overall|risk)\s+(?:rating|score|level)\s+(?:is|of|:)?\s*"
    r"(CRITICAL|HIGH|MEDIUM|LOW|MINIMAL|INFORMATIONAL)\b",
    re.IGNORECASE,
)

# Also catch '{BAND} risk rating' phrasings ("based on the overall LOW risk rating is")
_BAND_RATING_PHRASE = re.compile(
    r"\boverall\s+(CRITICAL|HIGH|MEDIUM|LOW|MINIMAL|INFORMATIONAL)\s+(?:risk\s+)?rating\b",
    re.IGNORECASE,
)


def check_rating_word_consistency(report: dict) -> List[LintIssue]:
    issues: List[LintIssue] = []
    canonical = get(report, "risk", "overall_band")
    if not canonical:
        return issues
    canonical = str(canonical).upper().strip()
    if canonical not in _BANDS:
        return issues

    for location, text in iter_text_blocks(report):
        for pattern in (_RATING_PHRASE, _BAND_RATING_PHRASE):
            for m in pattern.finditer(text):
                claimed = m.group(1).upper()
                if claimed != canonical:
                    snippet = text[max(0, m.start() - 30):min(len(text), m.end() + 30)]
                    issues.append(LintIssue(
                        check_id="AC3LINT-RATING-001",
                        check_name="rating_word_consistency",
                        severity=Severity.ERROR,
                        message=f"Narrative asserts '{claimed}' rating but canonical "
                                f"risk band is '{canonical}'.",
                        location=location,
                        detail=f"Snippet: ...{snippet.strip()}...",
                        suggestion="Bind rating-word in the prompt template to the computed "
                                   "band; lint for any rating word that disagrees.",
                        evidence={"narrative_band": claimed, "canonical_band": canonical},
                    ))
    return issues


def check_peak_vs_overall_band(report: dict) -> List[LintIssue]:
    """If peak asset risk is HIGH+ but overall band is LOW, that's worth a flag."""
    issues: List[LintIssue] = []
    overall = (get(report, "risk", "overall_band") or "").upper()
    peak = (get(report, "risk", "peak_asset_band") or "").upper()
    if not overall or not peak:
        return issues

    band_rank = {"INFORMATIONAL": 0, "MINIMAL": 1, "LOW": 2,
                 "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
    if band_rank.get(peak, 0) - band_rank.get(overall, 0) >= 2:
        issues.append(LintIssue(
            check_id="AC3LINT-RATING-002",
            check_name="peak_vs_overall_band_gap",
            severity=Severity.WARNING,
            message=f"Peak asset band ({peak}) is two or more levels above overall "
                    f"band ({overall}); verify aggregation logic isn't washing out "
                    f"a critical asset.",
            location="risk.overall_band vs risk.peak_asset_band",
            evidence={"overall": overall, "peak": peak},
        ))
    return issues
