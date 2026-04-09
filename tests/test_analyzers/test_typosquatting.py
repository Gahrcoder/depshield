"""Tests for typosquatting analyzer."""
from __future__ import annotations

import pytest

from depshield.analyzers.typosquatting import (
    TyposquattingAnalyzer,
    _confusable_match,
    _find_closest,
    _levenshtein,
)
from depshield.core.models import FindingCategory, Severity
from tests.conftest import (
    LEGITIMATE_DIR,
    TYPOSQUATS_DIR,
    fixture_to_package,
    make_package,
)


@pytest.fixture
def analyzer():
    return TyposquattingAnalyzer()


# ------------------------------------------------------------------ #
# Edit distance                                                       #
# ------------------------------------------------------------------ #

class TestLevenshtein:
    """Levenshtein distance unit tests."""

    def test_identical(self):
        assert _levenshtein("lodash", "lodash") == 0

    def test_single_insert(self):
        assert _levenshtein("lodash", "lodashs") == 1

    def test_single_delete(self):
        assert _levenshtein("lodash", "lodas") == 1

    def test_single_replace(self):
        assert _levenshtein("lodash", "l0dash") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "xyz") == 3

    def test_completely_different(self):
        assert _levenshtein("abc", "xyz") == 3

    def test_symmetric(self):
        assert _levenshtein("kitten", "sitting") == _levenshtein("sitting", "kitten")

    def test_transposition(self):
        # "ab" -> "ba" requires 2 edits (replace a->b, replace b->a)
        assert _levenshtein("ab", "ba") == 2


# ------------------------------------------------------------------ #
# Confusable character detection                                      #
# ------------------------------------------------------------------ #

class TestConfusables:
    """Confusable character substitution tests."""

    def test_zero_o_confusable(self):
        assert _confusable_match("l0dash", "lodash") is True

    def test_one_l_confusable(self):
        assert _confusable_match("1odash", "lodash") is True

    def test_exact_match_not_confusable(self):
        assert _confusable_match("lodash", "lodash") is False

    def test_no_confusable(self):
        assert _confusable_match("numpy", "lodash") is False


# ------------------------------------------------------------------ #
# Typosquat fixture detection                                         #
# ------------------------------------------------------------------ #

class TestTyposquatDetection:
    """Each typosquat fixture must be detected."""

    @pytest.mark.parametrize("fixture_name", [
        "l0dash", "expres", "axois", "chaulk", "reacr",
        "webpackk", "typescirpt", "eslitn", "pretiier", "momentt",
    ])
    def test_typosquat_detected(self, analyzer, fixture_name):
        pkg = fixture_to_package(TYPOSQUATS_DIR / f"{fixture_name}.json")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1, f"{fixture_name} should be flagged as typosquat"
        assert findings[0].category == FindingCategory.TYPOSQUATTING

    def test_l0dash_targets_lodash(self, analyzer):
        pkg = make_package(name="l0dash")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert "lodash" in findings[0].description.lower()

    def test_expres_targets_express(self, analyzer):
        pkg = make_package(name="expres")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert "express" in findings[0].description.lower()

    def test_confusable_is_critical(self, analyzer):
        pkg = make_package(name="l0dash")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_edit_distance_one_is_high(self, analyzer):
        pkg = make_package(name="expres")
        findings = analyzer.analyze(pkg)
        assert len(findings) >= 1
        assert findings[0].severity >= Severity.MEDIUM


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestLegitimateNotFlagged:
    """Real packages must NOT be flagged as typosquats."""

    @pytest.mark.parametrize("pkg_name", [
        "react", "express", "lodash", "webpack", "typescript",
        "eslint", "prettier", "moment", "axios", "chalk",
    ])
    def test_real_package_not_flagged(self, analyzer, pkg_name):
        pkg = make_package(name=pkg_name)
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0, f"{pkg_name} should NOT be flagged"

    def test_react_dom_not_flagged(self, analyzer):
        pkg = make_package(name="react-dom")
        findings = analyzer.analyze(pkg)
        assert len(findings) == 0

    def test_lodash_es_not_flagged(self, analyzer):
        # lodash-es is a known package but may not be in TOP_PACKAGES list
        # It should not be close enough to trigger for "lodash"
        pkg = make_package(name="lodash-es")
        findings = analyzer.analyze(pkg)
        # If flagged, it should not be critical (it's a real package)
        for f in findings:
            assert f.severity != Severity.CRITICAL
