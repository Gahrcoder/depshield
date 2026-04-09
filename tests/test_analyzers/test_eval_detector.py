"""Tests for the dangerous eval detector."""
from __future__ import annotations

import pytest

from depshield.analyzers.eval_detector import EvalDetector
from depshield.core.models import FindingCategory, Severity


@pytest.fixture
def analyzer():
    return EvalDetector()


# ------------------------------------------------------------------ #
# Indirect eval detection                                             #
# ------------------------------------------------------------------ #

class TestIndirectEval:
    """Detect (0, eval)() pattern."""

    def test_indirect_eval_detected(self, analyzer):
        code = 'const result = (0, eval)(code);'
        findings = analyzer.analyze_file(code, "workflow.js")
        assert len(findings) >= 1
        assert any("indirect eval" in f.title.lower() or "(0, eval)" in f.title for f in findings)

    def test_indirect_eval_in_deserialize_is_critical(self, analyzer):
        code = """function deserialize(payload) {
    const parsed = JSON.parse(payload);
    return (0, eval)(parsed.code);
}"""
        findings = analyzer.analyze_file(code, "parser.js")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_indirect_eval_outside_deser_is_high(self, analyzer):
        code = 'const x = (0, eval)(expr);'
        findings = analyzer.analyze_file(code, "utils.js")
        assert any(f.severity == Severity.HIGH for f in findings)


# ------------------------------------------------------------------ #
# Direct dynamic eval                                                 #
# ------------------------------------------------------------------ #

class TestDynamicEval:
    """Detect eval() with non-literal arguments."""

    def test_eval_with_variable(self, analyzer):
        code = 'const result = eval(userCode);'
        findings = analyzer.analyze_file(code, "exec.js")
        assert len(findings) >= 1

    def test_eval_with_concatenation(self, analyzer):
        code = 'eval(prefix + input);'
        findings = analyzer.analyze_file(code, "exec.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# new Function() detection                                            #
# ------------------------------------------------------------------ #

class TestNewFunction:
    """Detect new Function() constructor."""

    def test_new_function_detected(self, analyzer):
        code = "const fn = new Function('a', 'b', body);"
        findings = analyzer.analyze_file(code, "compiler.js")
        assert len(findings) >= 1
        assert any("function" in f.title.lower() for f in findings)

    def test_new_function_in_parse_is_critical(self, analyzer):
        code = """function compile(template) {
    const parsed = parseTemplate(template);
    return new Function('ctx', parsed.body);
}"""
        findings = analyzer.analyze_file(code, "template.js")
        assert any(f.severity == Severity.CRITICAL for f in findings)


# ------------------------------------------------------------------ #
# setTimeout/setInterval with string                                  #
# ------------------------------------------------------------------ #

class TestSetTimeoutString:
    """Detect setTimeout/setInterval with string argument."""

    def test_settimeout_with_variable(self, analyzer):
        code = 'setTimeout(codeString, 1000);'
        findings = analyzer.analyze_file(code, "timer.js")
        assert len(findings) >= 1

    def test_setinterval_with_variable(self, analyzer):
        code = 'setInterval(handler, 500);'
        findings = analyzer.analyze_file(code, "poller.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# vm.runInContext detection                                           #
# ------------------------------------------------------------------ #

class TestVmRun:
    """Detect vm.runInContext and related."""

    def test_vm_runincontext(self, analyzer):
        code = 'const result = vm.runInContext(code, sandbox);'
        findings = analyzer.analyze_file(code, "sandbox.js")
        assert len(findings) >= 1

    def test_vm_runinnewcontext(self, analyzer):
        code = 'vm.runInNewContext(untrustedCode, {});'
        findings = analyzer.analyze_file(code, "sandbox.js")
        assert len(findings) >= 1


# ------------------------------------------------------------------ #
# False positive prevention                                           #
# ------------------------------------------------------------------ #

class TestFalsePositives:
    """Ensure comments, strings, and safe patterns are NOT flagged."""

    def test_eval_in_comment_not_flagged(self, analyzer):
        code = '// eval(userInput) is dangerous, do not use'
        findings = analyzer.analyze_file(code, "safe.js")
        assert len(findings) == 0

    def test_eval_in_block_comment_not_flagged(self, analyzer):
        code = '/* eval(code) is disabled */'
        findings = analyzer.analyze_file(code, "safe.js")
        assert len(findings) == 0

    def test_eval_string_mention_not_flagged(self, analyzer):
        code = 'const msg = "Do not use eval() in production";'
        findings = analyzer.analyze_file(code, "safe.js")
        assert len(findings) == 0

    def test_fixture_safe_eval_not_flagged(self, analyzer):
        import os
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "eval", "safe_eval.js"
        )
        with open(fixture) as f:
            content = f.read()
        findings = analyzer.analyze_file(content, fixture)
        assert len(findings) == 0

    def test_fixture_indirect_eval_flagged(self, analyzer):
        import os
        fixture = os.path.join(
            os.path.dirname(__file__), "..", "fixtures", "eval", "indirect_eval.js"
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
        code = 'const x = (0, eval)(code); new Function(body);'
        findings = analyzer.analyze_file(code, "mixed.js")
        for f in findings:
            assert f.category == FindingCategory.DANGEROUS_EVAL
