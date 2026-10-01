"""
Incident State Machine for SOC Workflow.

States:
- NEW: Newly created incident from correlation engine
- INVESTIGATING: Active analyst or AI triage in progress
- AWAITING_USER_VERIFICATION: Out-of-band verification challenge dispatched to user
- USER_CONFIRMED: User attested that activity was legitimate
- USER_DENIED: User denied activity (potential account compromise)
- VERIFICATION_EXPIRED: User challenge timed out without response
- CONTAINMENT_PENDING: Proposed containment actions awaiting analyst execution
- CONTAINED: Host quarantined, attacker IP blocked, or session revoked
- FALSE_POSITIVE: Analyst marked incident as benign
- CONFIRMED_INCIDENT: Confirmed true positive security intrusion
- RESOLVED: Mitigation complete and post-incident review concluded
"""

from typing import Set, Dict, List

VALID_STATES: Set[str] = {
    "NEW",
    "INVESTIGATING",
    "AWAITING_USER_VERIFICATION",
    "USER_CONFIRMED",
    "USER_DENIED",
    "VERIFICATION_EXPIRED",
    "CONTAINMENT_PENDING",
    "CONTAINED",
    "FALSE_POSITIVE",
    "CONFIRMED_INCIDENT",
    "RESOLVED",
}

# Mapping of current state -> set of allowed next states
VALID_TRANSITIONS: Dict[str, Set[str]] = {
    "NEW": {"INVESTIGATING", "AWAITING_USER_VERIFICATION", "FALSE_POSITIVE", "CONFIRMED_INCIDENT", "CONTAINED"},
    "INVESTIGATING": {
        "AWAITING_USER_VERIFICATION",
        "CONTAINMENT_PENDING",
        "CONTAINED",
        "FALSE_POSITIVE",
        "CONFIRMED_INCIDENT",
        "RESOLVED",
        "INVESTIGATING",
    },
    "AWAITING_USER_VERIFICATION": {
        "USER_CONFIRMED",
        "USER_DENIED",
        "VERIFICATION_EXPIRED",
        "INVESTIGATING",
        "CONTAINMENT_PENDING",
        "CONTAINED",
    },
    "USER_CONFIRMED": {
        "INVESTIGATING",
        "FALSE_POSITIVE",
        "RESOLVED",
        "CONTAINED",
        "CONFIRMED_INCIDENT",
        "AWAITING_USER_VERIFICATION",
    },
    "USER_DENIED": {
        "CONTAINMENT_PENDING",
        "CONTAINED",
        "CONFIRMED_INCIDENT",
        "INVESTIGATING",
        "AWAITING_USER_VERIFICATION",
        "RESOLVED",
    },
    "VERIFICATION_EXPIRED": {
        "INVESTIGATING",
        "AWAITING_USER_VERIFICATION",
        "CONTAINMENT_PENDING",
        "CONTAINED",
        "CONFIRMED_INCIDENT",
        "RESOLVED",
        "FALSE_POSITIVE",
    },
    "CONTAINMENT_PENDING": {"CONTAINED", "INVESTIGATING", "CONFIRMED_INCIDENT"},
    "CONTAINED": {"CONFIRMED_INCIDENT", "RESOLVED", "INVESTIGATING"},
    "FALSE_POSITIVE": {"INVESTIGATING", "NEW", "RESOLVED"},
    "CONFIRMED_INCIDENT": {"CONTAINMENT_PENDING", "CONTAINED", "RESOLVED", "INVESTIGATING"},
    "RESOLVED": {"INVESTIGATING", "FALSE_POSITIVE"},
}


def validate_transition(current_state: str, new_state: str) -> bool:
    """Validate whether transitioning from current_state to new_state is permissible."""
    curr = current_state.upper().strip()
    nxt = new_state.upper().strip()

    # Normalize existing legacy statuses (e.g. "Investigating" -> "INVESTIGATING")
    if curr not in VALID_STATES:
        curr = "INVESTIGATING"

    if nxt not in VALID_STATES:
        return False

    if curr == nxt:
        return True

    allowed = VALID_TRANSITIONS.get(curr, set())
    return nxt in allowed
