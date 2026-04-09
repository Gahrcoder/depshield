"""Tests for the XSS detector."""
from __future__ import annotations

import os

import pytest

from depshield.analyzers.xss_detector import XSSDetector
from depshield.core.models import FindingCategory, Severity


@pytest.fixture
def analyzer():
    return XSSDetector()


# ------------------------------------------------------------------ #
# Template literal HTML interpolation                                 #
# ------------------------------------------------------------------ #

class TestTemplateInjection:
    """Detect template literal interpolation into HTML."""

    def test_title_interpolation(self, analyzer):
        code = 'const html = `<html><title>${title}</title></html>`;'
        findings = analyzer.analyze_file(code, "server.js")
        assert len(findings) >= 1
        assert any("template" in f.title.lower() for f in findings)

    def test_body_interpolation(self, analyzer):
        code = 'const page = `<div class="content">${body}</div>`;'
        findings = analyzer.analyze_file(code, "render.js")
        assert len(findings) >= 1

    def test_server_context_is_high(self, analyzer):
        code = """const express = require('express');
app.get('/page', (req, res) => {
    const html = `<h1>${req.query.title}</h1>`;
    res.send(html);
});"""
        findings = analyzer.analyze_file(code, "routes.js")
        template_findings = [f for f in findings if "template" in f.title.lower()]
        assert any(f.severity == Severity.HIGH for f in template_findings)


# ------------------------------------------------------------------ #
# innerHTML assignment                                                #
# ------------------------------------------------------------------ #

class TestInnerHTML:
    """Detect innerHTML with unsanitized input."""

    def test_innerhtml_assignment(self, analyzer):
        code = 'element.innerHTML = userContent;'
        findings = analyzer.analyze_file(code, "widget.js")
        assert len(findings) >= 1
        assert any("innerhtml" in f.title.lower() for f in findings)

    def test_innerhtml_with_variable(self, analyzer):
        code = 'document.getElementById("output").innerHTML = data;'
        findings = analyzer.analyze_file(code, "render.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# dangerouslySetInnerHTML                                             #
# ------------------------------------------------------------------ #

class TestDangerouslySetInnerHTML:
    """Detect dangerouslySetInnerHTML in React."""

    def test_dangerous_set_inner_html(self, analyzer):
        code = 'return <div dangerouslySetInnerHTML={{ __html: props.content }} />;'
        findings = analyzer.analyze_file(code, "Component.jsx")
        assert len(findings) >= 1
        assert any("dangerously" in f.title.lower() for f in findings)


# ------------------------------------------------------------------ #
# String concatenation into HTML                                      #
# ------------------------------------------------------------------ #

class TestHtmlConcatenation:
    """Detect string concatenation into HTML."""

    def test_html_concat(self, analyzer):
        code = "const card = '<div>' + username + '</div>';"  # noqa: E501
        findings = analyzer.analyze_file(code, "render.js")
        assert len(findings) >= 1
        assert any("concatenation" in f.title.lower() for f in findings)


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestFalsePositives:
    """Ensure sanitized output is not flagged."""

    def test_escaped_output_fixture(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "xss", "escaped_output.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        assert len(findings) == 0

    def test_template_injection_fixture_flagged(self, analyzer):
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "xss", "template_injection.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# Category validation                                                 #
# ------------------------------------------------------------------ #

class TestCategory:
    """Verify finding category."""

    def test_all_findings_have_correct_category(self, analyzer):
        code = 'element.innerHTML = data;'
        findings = analyzer.analyze_file(code, "page.js")
        for f in findings:
            assert f.category == FindingCategory.XSS
