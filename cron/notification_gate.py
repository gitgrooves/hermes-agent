"""Pre-delivery JT-value gate for successful cron messages.

Defence-in-depth guard against a recurring failure mode: a cron watchdog
completes successfully and its human-facing message explicitly says nothing
is needed from JT ("Needs JT: none", "Bob will reconcile silently", ...).
Source scripts should return ``[SILENT]`` (or say nothing) in that case, but
a single bad emitter is enough to page a human — this gate is the last,
deterministic check before delivery.  (Upstream context: hermes-agent
issue #74546 proposes a ``pre_cron_delivery`` hook; this is the minimal
internal equivalent for the built-in scheduler path.)

Design rules:

* Pure and deterministic — regex only, no LLM, no config, no I/O.
* Suppress only on an *explicit* non-actionable self-identification.
* Fail OPEN: any material-awareness signal (outage, data loss, credentials,
  security, spend, approval, capacity, critical risk) always delivers, even
  alongside a "Needs JT: none" marker.  A false suppression is worse than
  an extra message, so the material list is deliberately broad and the
  non-actionable list deliberately narrow.

The scheduler applies this only to *successful*, human-facing deliveries
(never failure alerts, never ``deliver=local``) — see ``cron.scheduler``.
"""

from __future__ import annotations

import re
from typing import Optional

# Separator between "Needs JT" and its value: whitespace, colon, and common
# markdown emphasis characters ("**Needs JT:** none").
_SEP = r"[\s:*_~`]{1,8}"

# Explicit non-actionable self-identifications.  Narrow on purpose: each
# pattern is a phrase an emitter uses to say "a human does not need this".
_NON_ACTIONABLE_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "needs-jt-none",
        re.compile(rf"needs\s+jt{_SEP}no(?:ne|thing)\b", re.IGNORECASE),
    ),
    (
        "needs-jt-only-if",
        re.compile(rf"needs\s+jt{_SEP}only\s+if\b", re.IGNORECASE),
    ),
    (
        "jt-action-none",
        re.compile(rf"jt\s+action{_SEP}no(?:ne|thing)\b", re.IGNORECASE),
    ),
    (
        # The non-actionable verb (needed/required/expected) is mandatory:
        # bare "no action from JT" is an observation that JT hasn't acted —
        # a nudge TO JT — not an assertion that none is needed.  Both word
        # orders: "no action is needed from JT" / "no action from JT is
        # required".
        "no-action-from-jt",
        re.compile(
            r"no\s+(?:immediate\s+)?action\s+"
            r"(?:(?:is\s+)?(?:needed|required|expected)\s+(?:from|by|for)\s+jt\b"
            r"|(?:from|by|for)\s+jt\s+(?:is\s+)?(?:needed|required|expected)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "no-jt-input-needed",
        re.compile(
            r"no\s+jt\s+(?:action|input|attention|involvement)\s+"
            r"(?:is\s+)?(?:needed|required)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "bob-silent-handling",
        re.compile(
            r"bob\s+(?:will|can|is\s+going\s+to)\s+"
            r"(?:review|reconcile|handle|monitor|investigate|action)"
            r"[^.\n]{0,60}\bsilent(?:ly)?\b",
            re.IGNORECASE,
        ),
    ),
]

# Material-awareness boundaries.  Any hit fails open (delivers).  Broad on
# purpose — over-matching only costs an extra delivered message.
_MATERIAL_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        # Active outage / availability
        r"\boutages?\b",
        r"\bunreachable\b",
        r"\bdown\b",
        r"\boffline\b",
        r"\bunavailable\b",
        r"\bnot\s+responding\b",
        r"\bdegraded\b",
        r"\b[45]xx\b",
        # Data loss / backup risk.  Bounded proximity ([^.\n]{0,40}) in both
        # directions so "backup job failed" / "backups have been failing"
        # match, without crossing sentence boundaries or backtracking.
        r"\bdata\b[^.\n]{0,30}\blos[st]\b",
        r"\blos[st]\b[^.\n]{0,30}\bdata\b",
        r"\bcorrupt\w*\b",
        r"\bbackups?\b[^.\n]{0,40}\b(?:fail\w*|missed|missing|stale)\b",
        r"\b(?:fail\w*|missed|missing|stale)\b[^.\n]{0,40}\bbackups?\b",
        r"\brestores?\b[^.\n]{0,30}\bfail\w*\b",
        r"\bfail\w*\b[^.\n]{0,30}\brestores?\b",
        # Credential / auth action
        r"\bcredentials?\b",
        r"\bpasswords?\b",
        r"\bapi\s+keys?\b",
        r"\btokens?\s+(?:expired|expiring|invalid|revoked)\b",
        r"\b(?:expired|expiring|invalid|revoked)\s+tokens?\b",
        r"\bauth\w*\s+(?:fail\w*|error|expired|required|issue)\b",
        r"\blog-?in\s+fail\w*\b",
        r"\bsign[-\s]?in\s+fail\w*\b",
        r"\bre-?authenticat\w*\b",
        r"\b40[13]\b",
        # Security / breach
        r"\bsecurity\b",
        r"\bbreach\w*\b",
        r"\bcompromis\w*\b",
        r"\bvulnerab\w*\b",
        r"\bintrusion\b",
        r"\bmalware\b",
        r"\bphish\w*\b",
        r"\bexploit\w*\b",
        r"\bunauthori[sz]ed\b",
        r"\bcve-\d{4}-\d+\b",
        # Payment / spend
        r"\bpayments?\b",
        r"\bbilling\b",
        r"\binvoices?\b",
        r"\bcharge[ds]?\b",
        r"\brefund\w*\b",
        r"\bspend\w*\b",
        r"\boverspend\w*\b",
        r"\bbudget\b",
        r"\bcosts?\s+(?:spike\w*|exceed\w*|overrun\w*)\b",
        r"[$£€]\s?\d",
        # Explicit approval
        r"\bapprovals?\b",
        r"\bapprove\b",
        r"\bsign[-\s]?off\b",
        # Capacity / hardware (incl. percentage-style disk pressure)
        r"\bdisk\s+(?:full|space|usage)\b",
        r"\bdisks?\b[^.\n]{0,30}\d{1,3}\s?%",
        r"\d{1,3}\s?%[^.\n]{0,30}\bdisks?\b",
        r"\bout\s+of\s+(?:disk|memory|space)\b",
        r"\bcapacity\b",
        r"\bhardware\b",
        r"\boom\b",
        r"\bmemory\s+(?:pressure|exhaust\w*|leak\w*)\b",
        # Critical risk / urgency
        r"\bcritical\b",
        r"\burgent\w*\b",
        r"\bemergency\b",
        r"\bescalat\w*\b",
        r"\bincidents?\b",
        r"\bsev\s*-?\s*[12]\b",
        r"\bp[01]\b",
        r"\bat\s+risk\b",
    )
]


def should_suppress_delivery(content) -> Optional[str]:
    """Decide whether a successful human-facing cron message is worth sending.

    Returns a short kebab-case reason string when the message explicitly
    self-identifies as non-actionable for JT AND carries no material-awareness
    signal; returns ``None`` (deliver) otherwise.  Non-string or empty input
    never suppresses.
    """
    if not isinstance(content, str) or not content.strip():
        return None

    matched_reason = None
    for reason, pattern in _NON_ACTIONABLE_PATTERNS:
        if pattern.search(content):
            matched_reason = reason
            break
    if matched_reason is None:
        return None

    # Fail open: any material boundary outranks the non-actionable marker.
    for pattern in _MATERIAL_PATTERNS:
        if pattern.search(content):
            return None

    return matched_reason
