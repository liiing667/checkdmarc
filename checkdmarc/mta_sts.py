"""SMTP MTA Strict Transport Security (MTA-STS) validation"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Sequence
from typing import Literal, TypedDict, cast

import dns.exception
import dns.resolver
import pyleri
import requests
from dns.nameserver import Nameserver

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    SYNTAX_ERROR_MARKER,
    USER_AGENT,
)
from checkdmarc.utils import (
    WSP_REGEX,
    _txt_cname_conflict_warning,
    normalize_domain,
    query_dns,
)

"""Copyright 2019-2023 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

logger = logging.getLogger(__name__)


# RFC 8461 section 3.1: the record must begin with the case-sensitive
# version field "v=STSv1" — no spaces around the equals sign. The
# whitespace around the ";" is the field delimiter (*WSP ";" *WSP), so
# "v=STSv1 ; id=x" is syntactically valid, though senders applying the
# section's literal 'begin with "v=STSv1;"' discard rule may ignore it
# (parse_mta_sts_record warns about that form).
MTA_STS_VERSION_REGEX_STRING = rf"v=STSv1{WSP_REGEX}*;{WSP_REGEX}*"
# RFC 8461 section 3.1: a field name is 1-32 letters, digits, underscores,
# hyphens, or dots (starting with a letter or digit), followed directly by
# "=" (no surrounding spaces) and a value of any visible ASCII characters
# except "=" and ";". This is wide enough to accept extension fields,
# which are ignored with a warning rather than rejected.
MTA_STS_TAG_VALUE_REGEX_STRING = (
    r"([A-Za-z0-9][A-Za-z0-9_\-.]{0,31})=([\x21-\x3A\x3C\x3E-\x7E]+)"
)

# RFC 8461 section 3.2: an mx value is ["*."] Domain, where Domain is
# dot-separated labels of letters, digits, and interior hyphens (RFC 5321
# section 4.1.2). A wildcard is only allowed as the complete left-most
# label, so "mail.*.example.com" and "*example.com" are invalid.
# Each label is capped at 63 octets (RFC 1035 section 2.3.4): a first
# and last alphanumeric character around at most 61 interior characters.
MTA_STS_MX_REGEX_STRING = (
    r"(?:\*\.)?"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*"
)
MTA_STS_MX_REGEX = re.compile(MTA_STS_MX_REGEX_STRING)

# RFC 8461 section 3.1: an id value is 1-32 letters or digits
MTA_STS_ID_REGEX = re.compile(r"[A-Za-z0-9]{1,32}")

# RFC 8461 section 3.2: a policy extension field name is 1-32 letters,
# digits, underscores, hyphens, or dots, starting with a letter or digit
# (sts-policy-ext-name)
MTA_STS_POLICY_EXT_NAME_REGEX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}")
# RFC 8461 section 3.2: a policy extension value is one or more visible or
# UTF-8 characters, with interior spaces allowed but no control characters
# and no leading/trailing spaces (sts-policy-ext-value; the parser strips
# surrounding whitespace before this check)
MTA_STS_POLICY_EXT_VALUE_REGEX = re.compile(r"[^\x00-\x1F\x7F]+")


class MTASTSError(Exception):
    """Raised when a fatal MTA-STS error occurs"""

    def __init__(self, msg: str, data: dict | None = None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class MTASTSRecordNotFound(MTASTSError):
    """Raised when an MTA-STS record could not be found"""

    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class MTASTSRecordSyntaxError(MTASTSError):
    """Raised when an MTA-STS DNS record syntax error is found"""


class InvalidMTASTSTag(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag is found

    .. note::
        No longer raised: RFC 8461 sections 3.1-3.2 say unknown fields
        are ignored, so parsing now warns instead. The class remains
        defined for backwards compatibility."""


class InvalidSTSTagValue(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag value is found"""


class UnrelatedTXTRecordFoundAtMTASTS(MTASTSError):
    """Raised when a TXT record unrelated to MTA-STS is found"""


class SPFRecordFoundWhereMTASTSRecordShouldBe(UnrelatedTXTRecordFoundAtMTASTS):
    """Raised when an SPF record is found where an MTA-STS record should be;
    most likely, the ``_mta-sts`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class MTASTSRecordInWrongLocation(MTASTSError):
    """Raised when an MTA-STS record is found at the root of a domain"""


class MultipleMTASTSRecords(MTASTSError):
    """Raised when multiple MTA-STS records are found"""


class MTASTSPolicyError(MTASTSError):
    """Raised when the MTA-STS policy cannot be downloaded or parsed"""


class MTASTSPolicyDownloadError(MTASTSPolicyError):
    """Raised when the MTA-STS policy cannot be downloaded"""


class MTASTSPolicySyntaxError(MTASTSPolicyError):
    """Raised when a syntax error is found in an MTA-STS policy"""


class MTASTSPinError(MTASTSError):
    """Raised when a pinned MTA-STS publishing identity does not match
    the policy currently served"""


class MTASTSQueryResult(TypedDict):
    record: str
    warnings: list[str]


# Deprecated alias for MTASTSQueryResult
MTASTSQueryResults = MTASTSQueryResult


# Tags is a dict mapping tag names to tag values (simple strings in MTA-STS)
MTASTSTags = dict[str, str]
MTASTSTagsWithDescription = dict[
    str, str
]  # Currently no difference, kept for API compat


class ParsedMTASTSRecord(TypedDict):
    tags: MTASTSTags | MTASTSTagsWithDescription
    warnings: list[str]


class MTASTSFailure(TypedDict):
    valid: bool
    error: str


class MTASTSSuccess(TypedDict):
    valid: bool
    tags: MTASTSTags | MTASTSTagsWithDescription
    warnings: list[str]


MTASTSResults = MTASTSSuccess | MTASTSFailure


class DownloadedMTASTSPolicy(TypedDict):
    policy: str
    warnings: list[str]


class ParsedMTASTSPolicy(TypedDict):
    version: Literal["STSv1"]
    mode: Literal["enforce", "testing", "none"]
    max_age: int
    mx: list[str]


class MTASTSPolicyParsingResults(TypedDict):
    policy: ParsedMTASTSPolicy
    warnings: list[str]


class MTASTSPin(TypedDict):
    """A fixed, offline copy of an MTA-STS publishing identity.

    The hash, domain, MX set, and max_age together describe one
    publication of a policy, so a replacement policy or a similar policy
    domain cannot silently reuse trust previously granted to this pin."""

    domain: str
    # Lowercase hex SHA-256 digest of the exact policy bytes served over
    # HTTPS, computed by mta_sts_policy_hash()
    policy_hash: str
    mx: list[str]
    max_age: int


class MTASTSPinVerification(TypedDict):
    # "hit": the served policy hash and every other field match the pin;
    # "compatible": the hash differs but the MX set is unchanged and
    # max_age was not shortened; "mismatch": the pin no longer matches and
    # relying on the served policy would break the pinned identity
    status: Literal["hit", "compatible", "mismatch"]
    pinned: MTASTSPin
    observed: dict[str, object]
    # Per-field conflicts for a mismatch; empty for a hit or compatible
    # result
    conflicts: list[str]
    # Non-breaking differences for a compatible result; empty otherwise
    warnings: list[str]


class MTASTSCheckSuccess(TypedDict):
    valid: Literal[True]
    id: str
    policy: ParsedMTASTSPolicy
    warnings: list[str]


class MTASTSCheckSuccessWithPin(MTASTSCheckSuccess, total=False):
    # Present only when check_mta_sts() was given a pin
    pin: MTASTSPinVerification


class MTASTSCheckFailure(TypedDict):
    valid: Literal[False]
    error: str
    # Warnings gathered before the error: from the record lookup, and from
    # the record parse and policy download when those succeeded first
    warnings: list[str]


class MTASTSCheckFailureWithPin(MTASTSCheckFailure, total=False):
    # Present only when the failure came from a pin mismatch, so callers
    # can see exactly which fields conflicted
    pin: MTASTSPinVerification


MTASTSCheckResult = (
    MTASTSCheckSuccess
    | MTASTSCheckSuccessWithPin
    | MTASTSCheckFailure
    | MTASTSCheckFailureWithPin
)
# Deprecated alias for MTASTSCheckResult
MTASTSCheckResults = MTASTSCheckResult


class _STSGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for MTA-STS records

    RFC 8461 section 3.1 defines the record as a case-sensitive
    "v=STSv1" version tag followed by semicolon-delimited fields, with
    an optional trailing semicolon. No IGNORECASE flag: the field names
    and the version value are case-sensitive literals in the ABNF."""

    version_tag = pyleri.Regex(MTA_STS_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(MTA_STS_TAG_VALUE_REGEX_STRING)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


MTA_STS_TAGS = {
    "v": {
        "name": "Version",
        "required": True,
        "description": 'Currently, only "STSv1" is supported.',
    },
    "id": {
        "name": "id",
        "required": True,
        "description": "A short string used to track policy "
        "updates.  This string MUST uniquely identify "
        "a given instance of a policy, such that "
        "senders can determine when the policy has "
        'been updated by comparing to the "id" of a '
        "previously seen policy. There is no implied "
        'ordering of "id" fields between revisions.',
    },
}

# Deprecated alias for MTA_STS_TAGS
mta_sts_tags = MTA_STS_TAGS

STS_TAG_VALUE_REGEX = re.compile(MTA_STS_TAG_VALUE_REGEX_STRING)

_SPF_IN_MTA_STS_ERROR_MSG = (
    "Found an SPF record where an MTA-STS record "
    "should be; most likely, the _mta-sts "
    "subdomain record does not actually exist, "
    "and the request for TXT records was "
    "redirected to the base domain."
)


def query_mta_sts_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MTASTSQueryResult:
    """
    Queries DNS for an MTA-STS record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed MTA-STS record string
                     - ``warnings`` - warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordNotFound`
        :exc:`checkdmarc.mta_sts.MTASTSRecordInWrongLocation`
        :exc:`checkdmarc.mta_sts.MultipleMTASTSRecords`
        :exc:`checkdmarc.mta_sts.UnrelatedTXTRecordFoundAtMTASTS`

    """
    domain = normalize_domain(domain)
    logger.debug(f"Checking for an MTA-STS record on {domain}")
    warnings = []
    target = f"_mta-sts.{domain}"
    # RFC 8461 section 3.1: records that do not begin with "v=STSv1;" are
    # discarded, not treated as errors. The section's ABNF allows WSP on
    # either side of the ";" (sts-field-delim = *WSP ";" *WSP), so accept
    # that form here too; the parser warns that literal-minded senders may
    # discard it.
    txt_prefix = re.compile(rf"v=STSv1{WSP_REGEX}*;")
    sts_record = None
    sts_records = []
    unrelated_records = []

    try:
        records = query_dns(
            target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        for record in records:
            if txt_prefix.match(record) is not None:
                sts_records.append(record)
            else:
                unrelated_records.append(record)

        if len(sts_records) > 1:
            raise MultipleMTASTSRecords("Multiple MTA-STS records are not permitted.")
        if len(sts_records) == 0:
            # No MTA-STS record here at all. An SPF record at _mta-sts
            # usually means the query was redirected to the base domain,
            # so give that specific diagnostic.
            for record in unrelated_records:
                if record.lower().startswith("v=spf1"):
                    raise SPFRecordFoundWhereMTASTSRecordShouldBe(
                        _SPF_IN_MTA_STS_ERROR_MSG
                    )
            raise MTASTSRecordNotFound("An MTA-STS DNS record does not exist.")
        # Exactly one MTA-STS record: RFC 8461 section 3.1 says unrelated
        # TXT records are discarded, so they only warrant a warning
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            warnings.append(
                "Unrelated TXT records were discovered and ignored. "
                "These should be removed, as some receivers may not "
                "expect to find unrelated TXT records "
                f"at {target}\n\n{ur_str}"
            )
        sts_record = sts_records[0]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        try:
            records = query_dns(
                domain,
                "TXT",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
            )
            for record in records:
                if txt_prefix.match(record) is not None:
                    raise MTASTSRecordInWrongLocation(
                        f"The MTA-STS record must be located at {target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise MTASTSRecordNotFound("The domain does not exist.")
        except dns.exception.DNSException as error:
            raise MTASTSRecordNotFound(error)
    except dns.exception.DNSException as error:
        raise MTASTSRecordNotFound(error)

    if sts_record is None:
        raise MTASTSRecordNotFound("An MTA-STS DNS record does not exist.")

    # RFC 8461 section 3.1 lets _mta-sts be a CNAME (section 8.2 delegation),
    # but a TXT record next to it is a DNS-level conflict; a sender that gets
    # more than one MTA-STS record assumes there is no policy
    cname_warning = _txt_cname_conflict_warning(
        target,
        sts_record,
        record_kind="MTA-STS",
        is_record=lambda r: txt_prefix.match(r) is not None,
        multiple_records_outcome=(
            "assumes the domain has no MTA-STS policy (RFC 8461 section 3.1)"
        ),
        lookup=query_dns,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    if cname_warning is not None:
        warnings.append(cname_warning)
    results: MTASTSQueryResult = {"record": sts_record, "warnings": warnings}

    return results


def parse_mta_sts_record(
    record: str,
    *,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedMTASTSRecord:
    """
    Parses an MTA-STS record

    Args:
        record (str): An MTA-STS record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The marker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` mapping each MTA-STS tag to its string value
         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``include_tag_descriptions`` is accepted for API consistency
            with the other record parsers, but MTA-STS tag values are plain
            strings and no descriptions are currently added

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordSyntaxError`
        :exc:`checkdmarc.mta_sts.InvalidSTSTagValue`
        :exc:`checkdmarc.mta_sts.SPFRecordFoundWhereMTASTSRecordShouldBe`

    """
    logger.debug("Parsing the MTA-STS record")
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereMTASTSRecordShouldBe(_SPF_IN_MTA_STS_ERROR_MSG)
    if record.startswith("v=STSv1") and not record.startswith("v=STSv1;"):
        # The RFC 8461 section 3.1 ABNF allows WSP before the ";"
        # (sts-field-delim = *WSP ";" *WSP), but the same section's prose
        # discard rule keys on the literal string "v=STSv1;".
        warnings.append(
            'The record does not begin with the literal "v=STSv1;" '
            "(there is whitespace before the semicolon); senders that "
            "apply the RFC 8461 section 3.1 discard rule literally will "
            "ignore this record"
        )
    sts_syntax_checker = _STSGrammar()
    grammar_result = sts_syntax_checker.parse(record)
    if not grammar_result.is_valid:
        expecting = [str(x).strip('"') for x in list(grammar_result.expecting)]
        marked_record = (
            record[: grammar_result.pos]
            + syntax_error_marker
            + record[grammar_result.pos :]
        )
        expecting_str = " or ".join(expecting)
        raise MTASTSRecordSyntaxError(
            f"Error: Expected {expecting_str} "
            f"at position {grammar_result.pos} "
            f"(marked with {syntax_error_marker}) "
            f"in: {marked_record}"
        )

    pairs: list[tuple[str, str]] = STS_TAG_VALUE_REGEX.findall(record)
    tags = {}

    for pair in pairs:
        # Tag names are case-sensitive in the RFC 8461 section 3.1
        # grammar, so do not lowercase them
        tag = pair[0]
        tag_value = pair[1]
        if tag not in MTA_STS_TAGS:
            # RFC 8461 sections 3.1 and 3.2: unknown fields (such as
            # extension fields) SHALL be ignored, not rejected
            warnings.append(f"Unknown MTA-STS tag {tag} was ignored.")
            continue
        if tag in tags:
            # RFC 8461 section 3.2: when a non-repeated field is
            # duplicated, all entries except the first SHALL be ignored
            warnings.append(
                f"The MTA-STS record has duplicate {tag} tags. "
                "Only the first value is used."
            )
            continue
        if tag == "id" and MTA_STS_ID_REGEX.fullmatch(tag_value) is None:
            raise InvalidSTSTagValue(
                "The id value must be 1-32 letters or digits (RFC 8461 section 3.1)."
            )
        tags[tag] = tag_value

    # RFC 8461 section 3.1: the v and id fields are required
    for tag_name, tag_info in MTA_STS_TAGS.items():
        if tag_info["required"] and tag_name not in tags:
            raise MTASTSRecordSyntaxError(
                f"The MTA-STS record is missing the required {tag_name} tag."
            )

    results: ParsedMTASTSRecord = {"tags": tags, "warnings": warnings}

    return results


def download_mta_sts_policy(
    domain: str, *, http_timeout: float = DEFAULT_HTTP_TIMEOUT
) -> DownloadedMTASTSPolicy:
    """
    Downloads a domain's MTA-STS policy

    Args:
        domain (str): A domain name
        http_timeout (float): HTTP timeout in seconds

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``policy`` - The unparsed policy string
                     - ``warnings`` - A list of any warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPolicyDownloadError`
    """
    warnings = []
    headers = {"User-Agent": USER_AGENT}
    session = requests.Session()
    session.headers = headers  # pyright: ignore[reportAttributeAccessIssue]
    expected_content_type = "text/plain"
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    logger.debug(f"Attempting to download MTA-STS policy from {url}")
    try:
        # RFC 8461 section 3.3: HTTP 3xx redirects MUST NOT be followed,
        # and the policy is only valid if the response code is exactly 200
        response = session.get(url, timeout=http_timeout, allow_redirects=False)
        if response.status_code != 200:
            raise MTASTSPolicyDownloadError(
                "The MTA-STS policy fetch returned HTTP "
                f"{response.status_code}. RFC 8461 section 3.3 requires "
                "an HTTP 200 response, and redirects must not be followed."
            )
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"].split(";")[0]
            content_type = content_type.strip()
            if content_type != expected_content_type:
                warnings.append(
                    f"The Content-Type header should be "
                    f"{expected_content_type}, not {content_type}"
                )
        else:
            warnings.append(
                "The Content-Type header is missing. It should "
                f"be set to {expected_content_type}"
            )

    except requests.RequestException as e:
        raise MTASTSPolicyDownloadError(str(e))

    results: DownloadedMTASTSPolicy = {"policy": response.text, "warnings": warnings}

    return results


def parse_mta_sts_policy(policy: str) -> MTASTSPolicyParsingResults:
    """
    Parses an MTA-STS policy

    Args:
        policy (str): The policy

     Returns:
        dict: a ``dict`` with the following keys:
                     - ``policy`` - The parsed policy
                     - ``warnings`` - A list of any warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPolicySyntaxError`
    """
    warnings = []
    mx = []
    versions = ["STSv1"]
    modes = ["enforce", "testing", "none"]
    required_keys = ["version", "mode", "max_age"]
    known_keys = required_keys + ["mx"]
    # Collected values; required keys are checked against seen_keys after
    # the loop, so a missing key is reported instead of silently defaulted
    values: dict[str, str | int] = {}
    seen_keys: set[str] = set()
    # RFC 8461 section 3.2: each line may end with either LF or CRLF, so
    # mixed line endings within one policy file are acceptable. Split only
    # on LF and drop the one CR belonging to a CRLF: str.splitlines()
    # would also split on separators the RFC does not allow (vertical
    # tab, form feed, U+2028), and rstrip("\r") would remove every
    # trailing CR, hiding invalid endings such as CR CR LF. Any CR left
    # after removing the CRLF one is a stray control character the
    # sts-policy-value grammar forbids, so reject it here — the later
    # .strip() on each value would silently discard it otherwise.
    lines = []
    for line_index, raw_line in enumerate(policy.split("\n")):
        line = raw_line.removesuffix("\r")
        if "\r" in line:
            raise MTASTSPolicySyntaxError(
                f"Line {line_index + 1}: A carriage return that is not part "
                "of a CRLF line ending is not allowed (RFC 8461 section 3.2)."
            )
        lines.append(line)
    for i in range(len(lines)):
        line_number = i + 1
        if lines[i] == "":
            continue
        # Split on the first colon only, so values containing colons
        # (allowed in extension values) still form a key: value pair
        key_value = lines[i].split(":", 1)
        if len(key_value) != 2:
            raise MTASTSPolicySyntaxError(f"Line {line_number}: Not a key: value pair.")
        raw_key = key_value[0]
        key = raw_key.strip()
        # RFC 8461 section 3.2: the field delimiter is ":" *WSP, so
        # whitespace is allowed after the colon (and after the value, via
        # the record-level *WSP) but never before the field name or
        # between the name and the colon.
        if key != raw_key:
            raise MTASTSPolicySyntaxError(
                f"Line {line_number}: Whitespace is not allowed before a "
                "field name or between the name and the colon "
                "(RFC 8461 section 3.2)."
            )
        value = key_value[1].strip()
        if key not in known_keys:
            # RFC 8461 section 3.2: unknown fields SHALL be ignored, not
            # rejected — but only when they are syntactically valid
            # extension fields. A name or value outside the
            # sts-policy-extension grammar makes the line, and so the
            # policy, invalid.
            if MTA_STS_POLICY_EXT_NAME_REGEX.fullmatch(key) is None:
                raise MTASTSPolicySyntaxError(
                    f"Line {line_number}: {key} is not a valid extension "
                    "field name (RFC 8461 section 3.2)."
                )
            if MTA_STS_POLICY_EXT_VALUE_REGEX.fullmatch(value) is None:
                raise MTASTSPolicySyntaxError(
                    f"Line {line_number}: The value of the extension field "
                    f"{key} is not valid (RFC 8461 section 3.2)."
                )
            warnings.append(f"Line {line_number}: Unknown key {key} was ignored.")
            continue
        if key in seen_keys and key != "mx":
            # RFC 8461 section 3.2: when a non-repeated field is
            # duplicated, all entries except the first SHALL be ignored
            warnings.append(
                f"Line {line_number}: Duplicate {key} key. "
                "Only the first value is used."
            )
            continue
        seen_keys.add(key)
        if key == "version" and value not in versions:
            raise MTASTSPolicySyntaxError(
                f"Line {line_number}: Invalid version: {value}"
            )
        elif key == "mode" and value not in modes:
            raise MTASTSPolicySyntaxError(f"Line {line_number}: Invalid mode: {value}")
        elif key == "max_age":
            error_msg = (
                f"Line {line_number}: max_age must be an integer value "
                "between 0 and 31557600."
            )
            # RFC 8461 section 3.2: max_age is 1-10 plain digits, so
            # values int() would accept, like "1_000" or "+5", are invalid
            if re.fullmatch(r"[0-9]{1,10}", value) is None:
                raise MTASTSPolicySyntaxError(error_msg)
            max_age = int(value)
            if max_age > 31557600:
                raise MTASTSPolicySyntaxError(error_msg)
            values[key] = max_age
            continue
        if key != "mx":
            values[key] = value
        else:
            # fullmatch against the ["*."] Domain pattern from RFC 8461
            # section 3.2; an unanchored search accepts any value
            # containing a single legal character, e.g. "not a hostname!"
            if MTA_STS_MX_REGEX.fullmatch(value) is None:
                raise MTASTSPolicySyntaxError(
                    f"Line {line_number}: Invalid mx value: {value}"
                )
            mx.append(value)
    # RFC 8461 section 3.2: version, mode, and max_age are each required
    # exactly once
    for required_key in required_keys:
        if required_key not in seen_keys:
            raise MTASTSPolicySyntaxError(f"Missing required key: {required_key}.")

    if values["mode"] != "none" and len(mx) == 0:
        raise MTASTSPolicySyntaxError(
            f"{values['mode']} mode requires at least one mx value."
        )
    # The loop above validated each value against its allowed literals,
    # so this narrowing from plain str/int values is safe
    parsed_policy = cast(
        ParsedMTASTSPolicy,
        {
            "version": values["version"],
            "mode": values["mode"],
            "max_age": values["max_age"],
            "mx": mx,
        },
    )

    results: MTASTSPolicyParsingResults = {
        "policy": parsed_policy,
        "warnings": warnings,
    }
    return results


def mta_sts_policy_hash(policy: str | bytes) -> str:
    """Returns the lowercase hex SHA-256 digest of a policy body.

    The digest covers the exact bytes served over HTTPS (before any line
    ending or whitespace normalization), so two policies that parse to
    the same fields but differ in whitespace or ordering get different
    hashes. A ``str`` is encoded as UTF-8, which every valid policy uses
    (RFC 8461 section 3.2 values are visible ASCII or UTF-8).

    Args:
        policy (str | bytes): The raw policy body

    Returns:
        str: The lowercase hex SHA-256 digest
    """
    if isinstance(policy, str):
        policy = policy.encode("utf-8")
    return hashlib.sha256(policy).hexdigest()


def _normalize_mta_sts_pin(pin: MTASTSPin) -> MTASTSPin:
    """Validates a pin and returns a normalized copy.

    Normalization pins the same case and ordering rules used when
    comparing against a served policy, so the comparison is not affected
    by cosmetic differences in how the pin was written down.

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPinError`: the pin is missing a
            required field or carries an invalid value
    """
    required_fields = ("domain", "policy_hash", "mx", "max_age")
    missing = [field for field in required_fields if field not in pin]
    if missing:
        raise MTASTSPinError(
            "The MTA-STS pin is missing required field(s): " + ", ".join(missing) + "."
        )
    domain = normalize_domain(pin["domain"])
    policy_hash = pin["policy_hash"].strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", policy_hash) is None:
        raise MTASTSPinError(
            "The MTA-STS pin policy_hash must be a 64-character hex SHA-256 digest."
        )
    mx = pin["mx"]
    if not isinstance(mx, list) or len(mx) == 0:
        raise MTASTSPinError("The MTA-STS pin must list at least one mx value.")
    normalized_mx: list[str] = []
    for pattern in mx:
        if MTA_STS_MX_REGEX.fullmatch(pattern) is None:
            raise MTASTSPinError(f"The MTA-STS pin has an invalid mx value: {pattern}")
        normalized_mx.append(pattern.lower())
    max_age = pin["max_age"]
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
        raise MTASTSPinError(
            "The MTA-STS pin max_age must be a non-negative integer number of seconds."
        )
    normalized: MTASTSPin = {
        "domain": domain,
        "policy_hash": policy_hash,
        "mx": normalized_mx,
        "max_age": max_age,
    }
    return normalized


def verify_mta_sts_pin(
    *,
    domain: str,
    pin: MTASTSPin,
    policy_text: str,
    parsed_policy: ParsedMTASTSPolicy,
) -> MTASTSPinVerification:
    """Checks a served MTA-STS policy against a fixed publishing identity.

    The pin binds four pieces of evidence together: the SHA-256 hash of
    the policy body, the policy domain, the MX pattern set, and the
    max_age lifetime. A replacement policy or a policy served by a
    similar-looking domain cannot reuse trust granted to an earlier
    publication: any hard conflict is reported as a ``mismatch`` rather
    than silently accepted.

    Args:
        domain (str): The domain the policy was fetched for
        pin (MTASTSPin): The fixed offline publishing identity
        policy_text (str): The raw policy body served over HTTPS
        parsed_policy (ParsedMTASTSPolicy): The parsed served policy

    Returns:
        MTASTSPinVerification: A ``hit`` (the exact pinned policy is
            still served), ``compatible`` (the body changed, the MX set
            is unchanged, and the max_age was not shortened), or
            ``mismatch`` (the pin no longer holds) result with the
            observed values and the per-field conflicts

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPinError`: the pin itself is
            malformed
    """
    normalized_pin = _normalize_mta_sts_pin(pin)
    observed_hash = mta_sts_policy_hash(policy_text)
    observed: dict[str, object] = {
        "domain": normalize_domain(domain),
        "policy_hash": observed_hash,
        "mx": list(parsed_policy["mx"]),
        "max_age": parsed_policy["max_age"],
        "mode": parsed_policy["mode"],
    }
    conflicts: list[str] = []
    soft_warnings: list[str] = []

    # The domain is the HTTPS identity: a policy for another domain can
    # never be a compatible update, so this always fails closed.
    domain_mismatch = observed["domain"] != normalized_pin["domain"]
    if domain_mismatch:
        conflicts.append(
            f"Domain mismatch: the pin is for {normalized_pin['domain']} but "
            f"the policy was served for {observed['domain']}."
        )

    if observed_hash == normalized_pin["policy_hash"] and not domain_mismatch:
        # An exact body match means the parsed fields are the pinned
        # fields too; no further tolerance is needed or granted.
        return MTASTSPinVerification(
            status="hit",
            pinned=normalized_pin,
            observed=observed,
            conflicts=[],
            warnings=[],
        )

    # From here on the policy body has changed. Decide whether the change
    # stays within the pinned trust boundary or breaks it.
    pinned_mx = normalized_pin["mx"]
    served_mx = [pattern.lower() for pattern in parsed_policy["mx"]]
    # The MX set is part of the publishing identity, so the patterns are
    # compared as literal strings (a wildcard pattern is itself a literal
    # pin value, not a match to expand). Any added or removed pattern
    # changes the identity; ordering alone does not matter for a set.
    added_mx = [pattern for pattern in served_mx if pattern not in pinned_mx]
    removed_mx = [pattern for pattern in pinned_mx if pattern not in served_mx]
    if removed_mx or added_mx:
        conflicts.append(
            "MX set mismatch: the served MX pattern set differs from the "
            f"pinned set (removed: {', '.join(removed_mx) or 'none'}; "
            f"added: {', '.join(added_mx) or 'none'})."
        )

    if parsed_policy["max_age"] < normalized_pin["max_age"]:
        conflicts.append(
            "max_age mismatch: the served policy expires after "
            f"{parsed_policy['max_age']} seconds, shorter than the pinned "
            f"{normalized_pin['max_age']} seconds, so trust would expire earlier "
            "than the pin allows."
        )
    elif parsed_policy["max_age"] > normalized_pin["max_age"]:
        soft_warnings.append(
            "max_age increased from the pinned "
            f"{normalized_pin['max_age']} seconds to "
            f"{parsed_policy['max_age']} seconds."
        )

    if conflicts:
        status: Literal["hit", "compatible", "mismatch"] = "mismatch"
    else:
        status = "compatible"
        soft_warnings.append(
            "Policy body hash differs from the pin, but every pinned MX is "
            "still published and max_age was not shortened, so the change "
            "is compatible with the pinned publishing identity."
        )

    return MTASTSPinVerification(
        status=status,
        pinned=normalized_pin,
        observed=observed,
        conflicts=conflicts,
        warnings=soft_warnings,
    )


def check_mta_sts(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    pin: MTASTSPin | None = None,
) -> MTASTSCheckResult:
    """
    Returns a dictionary with a parsed MTA-STS policy or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        pin (MTASTSPin): An optional fixed, offline copy of the domain's
                         MTA-STS publishing identity. When given, the
                         served policy body hash, domain, MX set, and
                         max_age are checked against it; a mismatch fails
                         closed instead of trusting the replacement policy


    Returns:
        dict: a ``dict`` with the following keys:

                       - ``id`` - The MTA-STS DNS record ID
                       - ``policy`` - The parsed MTA-STS policy
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings
                       - ``pin`` - Pin verification results, present only
                         when ``pin`` was given; its ``status`` is one of
                         ``hit``, ``compatible``, or ``mismatch``

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - The error message
                      - ``valid`` - False
                      - ``warnings`` - warning conditions found before the error
    """
    domain = normalize_domain(domain)
    warnings: list[str] = []
    try:
        query_results = query_mta_sts_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        warnings = query_results["warnings"]
        parsed_record = parse_mta_sts_record(query_results["record"])
        warnings += parsed_record["warnings"]
        id_value = parsed_record["tags"]["id"]
        # The timeout parameter is the DNS timeout; the policy download uses
        # its own HTTP default, as the BIMI check does for its downloads
        download_results = download_mta_sts_policy(domain)
        warnings += download_results["warnings"]
        parsed_policy = parse_mta_sts_policy(download_results["policy"])
        warnings += parsed_policy["warnings"]

        pin_results: MTASTSPinVerification | None = None
        if pin is not None:
            pin_results = verify_mta_sts_pin(
                domain=domain,
                pin=pin,
                policy_text=download_results["policy"],
                parsed_policy=parsed_policy["policy"],
            )
            warnings += pin_results["warnings"]
            if pin_results["status"] == "mismatch":
                # Fail closed: a replacement policy or a similar policy
                # domain must not reuse trust the pin granted to the
                # original publishing identity
                conflict_summary = " ".join(pin_results["conflicts"])
                raise MTASTSPinError(
                    "The served MTA-STS policy does not match the pinned "
                    f"publishing identity. {conflict_summary}",
                    data={"pin": pin_results},
                )

        mta_sts_results: MTASTSCheckSuccessWithPin = {
            "valid": True,
            "id": id_value,
            "policy": parsed_policy["policy"],
            "warnings": warnings,
        }
        if pin_results is not None:
            mta_sts_results["pin"] = pin_results
        return mta_sts_results
    except MTASTSError as error:
        mta_sts_results_failure: MTASTSCheckFailureWithPin = {
            "valid": False,
            "error": str(error),
            "warnings": warnings,
        }
        if isinstance(error, MTASTSPinError) and error.data is not None:
            mta_sts_results_failure["pin"] = error.data["pin"]
        return mta_sts_results_failure


def mx_in_mta_sts_patterns(mx_hostname: str, mta_sts_mx_patterns: list[str]) -> bool:
    """
    Tests whether a given MX hostname is covered by a given list of MX
    patterns from an MTA-STS policy.

    Args:
        mx_hostname (str): The MX hostname to test
        mta_sts_mx_patterns (list): The list of MTA-STS MX patterns

    Returns: True if the MX hostname is included, False if not
    """
    for pattern in mta_sts_mx_patterns:
        # RFC 8461 section 4.1: a wildcard may only match the entire
        # left-most label, so "*.example.com" matches "mail.example.com"
        # but not "example.com" or "foo.bar.example.com". The whole
        # hostname must match the whole pattern (fullmatch, not a
        # substring search), so "example.com" does not match
        # "bad-example.com" or "mail.example.com.evil.com".
        if pattern.startswith("*."):
            regex_pattern = r"[A-Za-z0-9\-]+" + re.escape(pattern[1:])
        else:
            regex_pattern = re.escape(pattern)
        if re.fullmatch(regex_pattern, mx_hostname, re.IGNORECASE) is not None:
            return True
    return False
