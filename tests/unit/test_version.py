"""Distribution metadata lookup works in installed and source-only environments."""

import importlib.metadata
import runpy
from unittest.mock import Mock

import pytest

from src import version


@pytest.mark.parametrize("installed", [True, False])
def test_version_resolves_distribution_or_explicit_unknown(monkeypatch, installed):
    lookup = Mock(return_value="1.2.3")
    if not installed:
        lookup.side_effect = importlib.metadata.PackageNotFoundError("clearproof")
    monkeypatch.setattr(importlib.metadata, "version", lookup)
    original = version.VERSION
    # Execute in an isolated namespace, preserving the live API's imported value.
    isolated = runpy.run_path(version.__file__)
    assert isolated["VERSION"] == ("1.2.3" if installed else "unknown")
    lookup.assert_called_once_with("clearproof")
    assert version.VERSION == original
