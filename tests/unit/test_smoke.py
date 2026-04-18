"""Placeholder smoke test so the pytest suite is non-empty on scaffold."""

import keyguard


def test_package_imports_and_exposes_version() -> None:
    assert isinstance(keyguard.__version__, str)
    assert keyguard.__version__
