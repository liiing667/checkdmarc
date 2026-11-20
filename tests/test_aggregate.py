"""Tests for checkdmarc.aggregate"""

import unittest
from typing import cast

import checkdmarc
from checkdmarc.aggregate import (
    COMBINATION_MATRIX,
    STATUS_RANK,
    AggregateStatus,
    CheckStatus,
    aggregate_check_statuses,
    aggregate_domain_result,
    combine_all_statuses,
    combine_statuses,
    domain_check_statuses,
)

STATUSES: list[AggregateStatus] = ["passed", "skipped", "unknown", "partial", "error"]

# The expected result of combining each ordered pair of statuses. This
# table pins COMBINATION_MATRIX independently of the module under test.
EXPECTED_COMBINATIONS: dict[
    tuple[AggregateStatus, AggregateStatus], AggregateStatus
] = {
    ("passed", "passed"): "passed",
    ("passed", "skipped"): "partial",
    ("passed", "unknown"): "partial",
    ("passed", "partial"): "partial",
    ("passed", "error"): "error",
    ("skipped", "passed"): "partial",
    ("skipped", "skipped"): "skipped",
    ("skipped", "unknown"): "unknown",
    ("skipped", "partial"): "partial",
    ("skipped", "error"): "error",
    ("unknown", "passed"): "partial",
    ("unknown", "skipped"): "unknown",
    ("unknown", "unknown"): "unknown",
    ("unknown", "partial"): "partial",
    ("unknown", "error"): "error",
    ("partial", "passed"): "partial",
    ("partial", "skipped"): "partial",
    ("partial", "unknown"): "partial",
    ("partial", "partial"): "partial",
    ("partial", "error"): "error",
    ("error", "passed"): "error",
    ("error", "skipped"): "error",
    ("error", "unknown"): "error",
    ("error", "partial"): "error",
    ("error", "error"): "error",
}


def _check_status(status: AggregateStatus, warnings: list[str] | None = None):
    return CheckStatus(status=status, warnings=warnings or [])


def _statuses(*statuses: AggregateStatus) -> list[AggregateStatus]:
    return list(statuses)


def _domain_result(**overrides):
    """A minimal DomainCheckResult with every check conclusive and clean"""
    result = {
        "domain": "example.com",
        "base_domain": "example.com",
        "dnssec": True,
        "soa": {"record": "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"},
        "ns": {"hostnames": ["ns1.example.com"], "warnings": []},
        "mx": {
            "hosts": [
                {
                    "preference": 0,
                    "hostname": "mail.example.com",
                    "addresses": ["192.0.2.1"],
                    "tls": True,
                    "starttls": True,
                }
            ],
            "warnings": [],
        },
        "spf": {
            "record": "v=spf1 -all",
            "valid": True,
            "dns_lookups": 0,
            "void_dns_lookups": 0,
            "warnings": [],
        },
        "dmarc": {
            "record": "v=DMARC1; p=reject",
            "location": "example.com",
            "valid": True,
            "warnings": [],
        },
        "mta_sts": {
            "valid": True,
            "id": "20240101T000000",
            "policy": {
                "version": "STSv1",
                "mode": "enforce",
                "max_age": 86400,
                "mx": ["mail.example.com"],
            },
            "warnings": [],
        },
        "smtp_tls_reporting": {
            "valid": True,
            "tags": {"rua": {"value": ["mailto:tls@example.com"]}},
            "warnings": [],
        },
    }
    result.update(overrides)
    return cast(checkdmarc.DomainCheckResult, result)


class TestCombinationMatrix(unittest.TestCase):
    def testMatrixCoversEveryStatusPair(self):
        """The matrix has an entry for every ordered pair of statuses"""
        self.assertEqual(sorted(COMBINATION_MATRIX), sorted(STATUSES))
        for row in COMBINATION_MATRIX.values():
            self.assertEqual(sorted(row), sorted(STATUSES))

    def testMatrixMatchesExpectedCombinations(self):
        """Every status pair combines to its expected compatible result"""
        for (left, right), expected in EXPECTED_COMBINATIONS.items():
            self.assertEqual(
                combine_statuses(left, right),
                expected,
                f"{left} combined with {right}",
            )
            self.assertEqual(COMBINATION_MATRIX[left][right], expected)

    def testMatrixIsSymmetric(self):
        """Combining statuses is commutative"""
        for left in STATUSES:
            for right in STATUSES:
                self.assertEqual(
                    combine_statuses(left, right),
                    combine_statuses(right, left),
                )

    def testCombinationIsMonotonic(self):
        """Widening either input can only keep or worsen the result"""
        for left in STATUSES:
            for wider_left in STATUSES:
                if STATUS_RANK[left] > STATUS_RANK[wider_left]:
                    continue
                for right in STATUSES:
                    self.assertLessEqual(
                        STATUS_RANK[combine_statuses(left, right)],
                        STATUS_RANK[combine_statuses(wider_left, right)],
                        f"{left} -> {wider_left} combined with {right}",
                    )

    def testCombinationIsAssociative(self):
        """Folding statuses does not depend on grouping"""
        for first in STATUSES:
            for second in STATUSES:
                for third in STATUSES:
                    self.assertEqual(
                        combine_statuses(combine_statuses(first, second), third),
                        combine_statuses(first, combine_statuses(second, third)),
                    )

    def testSkippedAndUnknownNeverFoldIntoPassed(self):
        """A skipped or unknown result keeps the aggregate below passed"""
        for other in ("skipped", "unknown", "partial", "error"):
            self.assertNotEqual(combine_statuses("passed", other), "passed")
        self.assertEqual(
            combine_all_statuses(_statuses("passed", "passed", "skipped")), "partial"
        )
        self.assertEqual(
            combine_all_statuses(_statuses("passed", "passed", "unknown")), "partial"
        )

    def testErrorAndPartialAreTerminal(self):
        """No further result upgrades an error or partial aggregate"""
        for other in STATUSES:
            self.assertEqual(combine_statuses("error", other), "error")
            self.assertIn(combine_statuses("partial", other), ("partial", "error"))

    def testCombineAllStatuses(self):
        """Folding any number of statuses matches pairwise combination"""
        self.assertEqual(combine_all_statuses([]), "unknown")
        self.assertEqual(combine_all_statuses(_statuses("passed")), "passed")
        self.assertEqual(
            combine_all_statuses(_statuses("skipped", "skipped", "skipped")), "skipped"
        )
        self.assertEqual(
            combine_all_statuses(_statuses("unknown", "unknown")), "unknown"
        )
        self.assertEqual(
            combine_all_statuses(_statuses("passed", "skipped", "unknown")), "partial"
        )
        self.assertEqual(
            combine_all_statuses(_statuses("unknown", "error", "passed")), "error"
        )


class TestAggregateCheckStatuses(unittest.TestCase):
    def testAllPassed(self):
        """Conclusive passes combine into a complete success"""
        report = aggregate_check_statuses(
            {"spf": _check_status("passed"), "dmarc": _check_status("passed")}
        )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["checks"], {"spf": "passed", "dmarc": "passed"})
        self.assertEqual(report["warnings"], {})

    def testSkippedCheckIsPartialCoverage(self):
        """A skipped check degrades a clean run to partial, not passed"""
        report = aggregate_check_statuses(
            {
                "spf": _check_status("passed"),
                "dmarc": _check_status("passed"),
                "tls": _check_status("skipped"),
            }
        )
        self.assertEqual(report["status"], "partial")

    def testErrorDominates(self):
        """A single failed check makes the aggregate an error"""
        report = aggregate_check_statuses(
            {
                "spf": _check_status("error"),
                "dmarc": _check_status("passed"),
                "tls": _check_status("skipped"),
            }
        )
        self.assertEqual(report["status"], "error")

    def testWarningsKeepTheirSourceCheck(self):
        """Warnings stay attributed to the check that produced them"""
        report = aggregate_check_statuses(
            {
                "spf": _check_status("passed", ["SPF record is too long"]),
                "dmarc": _check_status("error", ["rua tag not found"]),
                "mx": _check_status("passed"),
            }
        )
        self.assertEqual(
            report["warnings"],
            {
                "spf": ["SPF record is too long"],
                "dmarc": ["rua tag not found"],
            },
        )

    def testWarningsAreCopied(self):
        """The report does not alias the per-check warning lists"""
        warnings = ["a warning"]
        report = aggregate_check_statuses({"spf": _check_status("passed", warnings)})
        warnings.append("mutated")
        self.assertEqual(report["warnings"], {"spf": ["a warning"]})


class TestDomainCheckStatuses(unittest.TestCase):
    def testCleanDomain(self):
        """A fully conclusive clean result passes on every check"""
        checks = domain_check_statuses(_domain_result())
        self.assertTrue(
            all(check["status"] == "passed" for check in checks.values()),
            checks,
        )

    def testSkippedTlsTests(self):
        """Untested MX TLS is skipped, so the aggregate is only partial"""
        result = _domain_result()
        for host in result["mx"]["hosts"]:
            del host["tls"]
            del host["starttls"]
        checks = domain_check_statuses(result)
        self.assertEqual(checks["tls"]["status"], "skipped")
        self.assertEqual(checks["starttls"]["status"], "skipped")
        report = aggregate_domain_result(result)
        self.assertEqual(report["status"], "partial")

    def testUnsupportedTlsIsAnError(self):
        """An MX host without TLS support fails the TLS check"""
        result = _domain_result()
        result["mx"]["hosts"][0]["starttls"] = False
        checks = domain_check_statuses(result)
        self.assertEqual(checks["starttls"]["status"], "error")
        self.assertEqual(aggregate_domain_result(result)["status"], "error")

    def testMxErrorLeavesTlsUnknown(self):
        """A failed MX lookup leaves TLS support undetermined"""
        result = _domain_result(mx={"hosts": [], "error": "No MX records found"})
        checks = domain_check_statuses(result)
        self.assertEqual(checks["mx"]["status"], "error")
        self.assertEqual(checks["tls"]["status"], "unknown")
        self.assertEqual(checks["starttls"]["status"], "unknown")

    def testSpfError(self):
        """An SPF error dominates the aggregate and keeps its warnings"""
        result = _domain_result(
            spf={
                "record": None,
                "valid": False,
                "error": "No SPF record found",
                "warnings": ["Unrelated TXT records were discovered"],
            }
        )
        report = aggregate_domain_result(result)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["checks"]["spf"], "error")
        self.assertEqual(
            report["warnings"]["spf"], ["Unrelated TXT records were discovered"]
        )

    def testDmarcErrorWarningsKeepSource(self):
        """DMARC warnings surface under the dmarc check, not a shared pool"""
        result = _domain_result(
            dmarc={
                "record": None,
                "location": None,
                "valid": False,
                "error": "No DMARC record found",
                "warnings": ["_dmarc has both a TXT record and a CNAME record"],
            }
        )
        report = aggregate_domain_result(result)
        self.assertEqual(report["status"], "error")
        self.assertEqual(
            report["warnings"],
            {"dmarc": ["_dmarc has both a TXT record and a CNAME record"]},
        )

    def testDnssecFalseIsUnknown(self):
        """An unsigned or broken DNSSEC zone is unknown, not passed"""
        result = _domain_result(dnssec=False)
        checks = domain_check_statuses(result)
        self.assertEqual(checks["dnssec"]["status"], "unknown")
        report = aggregate_domain_result(result)
        self.assertEqual(report["status"], "partial")

    def testBimiOnlyWhenPresent(self):
        """The optional BIMI check appears only when it was run"""
        self.assertNotIn("bimi", domain_check_statuses(_domain_result()))
        result = _domain_result(
            bimi={"record": None, "valid": False, "error": "No BIMI record"}
        )
        checks = domain_check_statuses(result)
        self.assertEqual(checks["bimi"]["status"], "error")

    def testInvalidWithoutErrorIsAnError(self):
        """A check reporting valid=False without an error still fails"""
        result = _domain_result(
            spf={"record": "v=spf1 -all", "valid": False, "warnings": []}
        )
        checks = domain_check_statuses(result)
        self.assertEqual(checks["spf"]["status"], "error")

    def testInconclusiveCheckIsUnknown(self):
        """A check with neither valid nor error is unknown, not passed"""
        result = _domain_result(smtp_tls_reporting={"warnings": []})
        checks = domain_check_statuses(result)
        self.assertEqual(checks["smtp_tls_reporting"]["status"], "unknown")
        report = aggregate_domain_result(result)
        self.assertEqual(report["status"], "partial")

    def testAggregateDomainResultMatchesManualAggregation(self):
        """aggregate_domain_result is aggregate_check_statuses over the
        derived per-check statuses"""
        result = _domain_result()
        self.assertEqual(
            aggregate_domain_result(result),
            aggregate_check_statuses(domain_check_statuses(result)),
        )

    def testPackageExports(self):
        """The aggregate API is importable from the top-level package"""
        self.assertIs(checkdmarc.aggregate_domain_result, aggregate_domain_result)
        self.assertIs(checkdmarc.combine_statuses, combine_statuses)
        self.assertIs(checkdmarc.aggregate_check_statuses, aggregate_check_statuses)
        self.assertIs(checkdmarc.domain_check_statuses, domain_check_statuses)


if __name__ == "__main__":
    unittest.main()
