"""Cross-reference :class:`RawFinding` records against vault fingerprints.

Given a list of findings from gitleaks/fileshunt and the current vault,
compute the HMAC-SHA256 fingerprint of each finding's value and check
for matches against stored :class:`KeyVersion` fingerprints. Each match
becomes a new :class:`Exposure` attached to the corresponding Key, and
that Key's ``exposure_status`` is flipped to ``CONFIRMED_LEAKED``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from keyguard.core.models import (
    Exposure,
    ExposureSeverity,
    ExposureSourceType,
    ExposureStatus,
    Vault,
    compute_fingerprint,
)
from keyguard.core.scanner.gitleaks import RawFinding

__all__ = ["match_findings"]

_SOURCE_MAP: dict[str, ExposureSourceType] = {
    "gitleaks": ExposureSourceType.GIT_HISTORY,
    "fileshunt": ExposureSourceType.FILESYSTEM,
}


def match_findings(
    findings: list[RawFinding],
    vault: Vault,
    fingerprint_key: bytes,
) -> list[Exposure]:
    """Return the newly-created :class:`Exposure` records.

    Mutates ``vault`` in place: appends to each matched
    :class:`keyguard.core.models.Key`'s ``exposures`` list and sets
    ``exposure_status = CONFIRMED_LEAKED``. De-duplicates: a key that
    already has an Exposure with the same fingerprint+location does not
    get a second copy.
    """
    new_exposures: list[Exposure] = []
    for finding in findings:
        fp = compute_fingerprint(finding.secret, fingerprint_key)
        source_type = _SOURCE_MAP.get(finding.source, ExposureSourceType.USER_REPORTED)
        location = f"{finding.file}:{finding.line}"
        for key in vault.keys:
            if not any(kv.fingerprint == fp for kv in key.versions):
                continue
            if any(exp.key_fingerprint == fp and exp.location == location for exp in key.exposures):
                continue
            exposure = Exposure(
                discovered_at=datetime.now(UTC),
                source_type=source_type,
                location=location,
                key_fingerprint=fp,
                severity=ExposureSeverity.HIGH,
            )
            key.exposures.append(exposure)
            key.exposure_status = ExposureStatus.CONFIRMED_LEAKED
            new_exposures.append(exposure)
            break  # one exposure per finding
    return new_exposures
