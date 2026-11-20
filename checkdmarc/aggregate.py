"""Combine per-check statuses into a single aggregate status for a domain"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from checkdmarc import DomainCheckResult

AggregateStatus = Literal["passed", "skipped", "unknown", "partial", "error"]
"""The status of a single check, or of a domain as a whole

- ``passed`` - The check ran and found no problems
- ``skipped`` - The check was not run (for example, MX TLS testing is
  opt-in via ``check_mx_tls``)
- ``unknown`` - The check could not reach a conclusive outcome
- ``partial`` - Aggregate-only: every conclusive check passed, but at
  least one check was skipped or inconclusive, so coverage is incomplete
- ``error`` - A check failed or reported an error
"""

# Severity order from best to worst. A partial aggregate still holds
# conclusive passes, so it ranks above skipped and unknown, which hold
# none; a check that ran without a conclusion (unknown) ranks worse than
# one deliberately not run (skipped). combine_statuses() is monotonic in
# this order: widening either input can only keep or worsen the result, so
# error and partial are terminal — once reached, no further check result
# can upgrade the aggregate back to a cleaner state.
STATUS_RANK: dict[AggregateStatus, int] = {
    "passed": 0,
    "partial": 1,
    "skipped": 2,
    "unknown": 3,
    "error": 4,
}

# The fixed combination matrix. Rules, in priority order:
#
# 1. error combined with anything stays error
# 2. partial combined with anything but error stays partial
# 3. passed combined with anything less certain than passed (skipped or
#    unknown) degrades to partial — a skipped or unknown result is never
#    folded into a complete success
# 4. skipped combined with unknown is unknown (nothing conclusive either
#    way, and a check that ran beats one that did not)
# 5. equal statuses combine to themselves
COMBINATION_MATRIX: dict[AggregateStatus, dict[AggregateStatus, AggregateStatus]] = {
    "passed": {
        "passed": "passed",
        "skipped": "partial",
        "unknown": "partial",
        "partial": "partial",
        "error": "error",
    },
    "skipped": {
        "passed": "partial",
        "skipped": "skipped",
        "unknown": "unknown",
        "partial": "partial",
        "error": "error",
    },
    "unknown": {
        "passed": "partial",
        "skipped": "unknown",
        "unknown": "unknown",
        "partial": "partial",
        "error": "error",
    },
    "partial": {
        "passed": "partial",
        "skipped": "partial",
        "unknown": "partial",
        "partial": "partial",
        "error": "error",
    },
    "error": {
        "passed": "error",
        "skipped": "error",
        "unknown": "error",
        "partial": "error",
        "error": "error",
    },
}


class CheckStatus(TypedDict):
    """The status of a single check, with the warnings it produced"""

    status: AggregateStatus
    warnings: list[str]


class AggregateReport(TypedDict):
    """The combined status of every check run against a domain

    ``warnings`` is keyed by the name of the check that produced each
    warning, so the source of a warning survives the merge.
    """

    status: AggregateStatus
    checks: dict[str, AggregateStatus]
    warnings: dict[str, list[str]]


def combine_statuses(left: AggregateStatus, right: AggregateStatus) -> AggregateStatus:
    """
    Combine two check statuses into one, using ``COMBINATION_MATRIX``

    The combination is commutative, associative, and monotonic in
    ``STATUS_RANK``: error and partial are terminal states that no
    additional result can upgrade, and a skipped or unknown result never
    folds into a complete success.

    Args:
        left (str): One status
        right (str): Another status

    Returns:
        str: The combined status
    """
    return COMBINATION_MATRIX[left][right]


def combine_all_statuses(statuses: Iterable[AggregateStatus]) -> AggregateStatus:
    """
    Combine any number of check statuses into one

    Args:
        statuses (list): The statuses to combine

    Returns:
        str: The combined status, or ``unknown`` when there is nothing to
        combine
    """
    combined: AggregateStatus = "unknown"
    first = True
    for status in statuses:
        combined = status if first else combine_statuses(combined, status)
        first = False
    return combined


def aggregate_check_statuses(
    checks: Mapping[str, CheckStatus],
) -> AggregateReport:
    """
    Combine named check statuses into a single aggregate report

    Args:
        checks (dict): A ``dict`` mapping each check name to its
                       ``CheckStatus``

    Returns:
        dict: An ``AggregateReport`` with the combined status, the
        per-check statuses, and the warnings of each check keyed by check
        name
    """
    warnings = {
        name: list(check["warnings"])
        for name, check in checks.items()
        if check["warnings"]
    }
    return {
        "status": combine_all_statuses(check["status"] for check in checks.values()),
        "checks": {name: check["status"] for name, check in checks.items()},
        "warnings": warnings,
    }


def _valid_check_status(check_result: Mapping[str, object]) -> AggregateStatus:
    """Status of a check whose result carries ``valid``/``error`` keys"""
    if "error" in check_result:
        return "error"
    valid = check_result.get("valid")
    if valid is True:
        return "passed"
    if valid is False:
        return "error"
    return "unknown"


def _plain_check_status(check_result: Mapping[str, object]) -> AggregateStatus:
    """Status of a check whose result carries only an optional ``error`` key"""
    if "error" in check_result:
        return "error"
    return "passed"


def _tls_check_status(mx_results: Mapping[str, object], key: str) -> AggregateStatus:
    """Status of the per-MX-host ``tls`` or ``starttls`` tests"""
    hosts = mx_results.get("hosts")
    if "error" in mx_results or not hosts:
        # A failed MX lookup — or a domain with no MX hosts to test, such
        # as a null MX — leaves TLS support undetermined
        return "unknown"
    assert isinstance(hosts, list)
    if any(key not in host for host in hosts):
        # TLS testing is opt-in via check_mx_tls
        return "skipped"
    if all(host[key] for host in hosts):
        return "passed"
    return "error"


def domain_check_statuses(result: DomainCheckResult) -> dict[str, CheckStatus]:
    """
    Derive the status of each check in a ``DomainCheckResult``

    DNSSEC needs a word of its own: ``check_dnssec()`` returns ``False``
    for an unsigned zone (a legitimate state), a broken zone, and a failed
    lookup alike, so ``False`` cannot be read as either a pass or a
    failure. It is reported as ``unknown`` rather than folded into a
    complete success.

    Args:
        result (dict): A ``DomainCheckResult`` from ``check_domains()``

    Returns:
        dict: A ``dict`` mapping each check name to its ``CheckStatus``
    """
    spf = result["spf"]
    dmarc = result["dmarc"]
    mx = result["mx"]
    ns = result["ns"]
    soa = result["soa"]
    mta_sts = result["mta_sts"]
    smtp_tls_reporting = result["smtp_tls_reporting"]

    checks: dict[str, CheckStatus] = {
        "spf": {
            "status": _valid_check_status(spf),
            "warnings": list(spf.get("warnings", [])),
        },
        "dmarc": {
            "status": _valid_check_status(dmarc),
            "warnings": list(dmarc.get("warnings", [])),
        },
        "mx": {
            "status": _plain_check_status(mx),
            "warnings": list(mx.get("warnings", [])),
        },
        "tls": {"status": _tls_check_status(mx, "tls"), "warnings": []},
        "starttls": {"status": _tls_check_status(mx, "starttls"), "warnings": []},
        "ns": {
            "status": _plain_check_status(ns),
            "warnings": list(ns.get("warnings", [])),
        },
        "soa": {"status": _plain_check_status(soa), "warnings": []},
        "mta_sts": {
            "status": _valid_check_status(mta_sts),
            "warnings": list(mta_sts.get("warnings", [])),
        },
        "smtp_tls_reporting": {
            "status": _valid_check_status(smtp_tls_reporting),
            "warnings": list(smtp_tls_reporting.get("warnings", [])),
        },
        "dnssec": {
            "status": "passed" if result["dnssec"] is True else "unknown",
            "warnings": [],
        },
    }
    if "bimi" in result:
        bimi = result["bimi"]
        checks["bimi"] = {
            "status": _valid_check_status(bimi),
            "warnings": list(bimi.get("warnings", [])),
        }
    return checks


def aggregate_domain_result(result: DomainCheckResult) -> AggregateReport:
    """
    Combine every check status of a ``DomainCheckResult`` into one report

    Args:
        result (dict): A ``DomainCheckResult`` from ``check_domains()``

    Returns:
        dict: An ``AggregateReport`` with the combined status, the
        per-check statuses, and the warnings of each check keyed by check
        name
    """
    return aggregate_check_statuses(domain_check_statuses(result))
