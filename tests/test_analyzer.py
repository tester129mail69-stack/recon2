"""Tests for godrecon.ai.analyzer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from godrecon.ai.analyzer import AnalysisReport, ScanAnalyzer


def _sample_scan_result() -> dict:
    """Return a minimal scan result dict that mimics ScanEngine output."""
    from godrecon.modules.base import Finding, ModuleResult

    critical = Finding(
        title="RCE Vulnerability", description="Remote code execution", severity="critical", data={}, tags=[]
    )
    high = Finding(title="SQLi", description="SQL injection", severity="high", data={}, tags=[])
    medium = Finding(title="XSS", description="Cross-site scripting", severity="medium", data={}, tags=[])
    low = Finding(title="Info Leak", description="Info leakage", severity="low", data={}, tags=[])
    info = Finding(title="Open Port", description="Port 80 open", severity="info", data={}, tags=[])

    mr = ModuleResult(module_name="vulns", target="example.com", findings=[critical, high, medium, low, info])
    return {
        "target": "example.com",
        "module_results": {"vulns": mr},
        "errors": [],
    }


def test_local_provider_returns_report():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert isinstance(result, AnalysisReport)


def test_risk_score_calculation():
    """critical*25 + high*15 + medium*5 + low*1 = 25+15+5+1 = 46."""
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert result.risk_score == 46


def test_risk_score_capped_at_100():
    from godrecon.modules.base import Finding, ModuleResult

    findings = [Finding(title=f"F{i}", description="", severity="critical", data={}, tags=[]) for i in range(10)]
    mr = ModuleResult(module_name="vulns", target="t", findings=findings)
    scan_result = {"target": "t", "module_results": {"vulns": mr}, "errors": []}
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(scan_result)
    assert result.risk_score == 100


def test_executive_summary_contains_target():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert "example.com" in result.executive_summary


def test_executive_summary_mentions_critical_and_high():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert "1 critical" in result.executive_summary
    assert "1 high" in result.executive_summary


def test_risk_level_from_score():
    from godrecon.ai.analyzer import _risk_level_from_score

    assert _risk_level_from_score(0) == "info"
    assert _risk_level_from_score(10) == "low"
    assert _risk_level_from_score(30) == "medium"
    assert _risk_level_from_score(60) == "high"
    assert _risk_level_from_score(80) == "critical"


def test_top_risks_sorted_by_severity():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert result.top_risks[0]["severity"] == "critical"


def test_remediation_priorities_non_empty():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert len(result.remediation_priorities) > 0
    assert result.remediation_priorities[0]["priority"] == 1


def test_module_summaries_present():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert "vulns" in result.module_summaries
    assert "vulns" in result.module_summaries["vulns"]


def test_attack_surface_summary():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze(_sample_scan_result())
    assert "total_findings" in result.attack_surface_summary
    assert result.attack_surface_summary["total_findings"] == 5


def test_empty_scan_results():
    analyzer = ScanAnalyzer(provider="local")
    result = analyzer.analyze({"target": "empty.com", "module_results": {}, "errors": []})
    assert result.risk_score == 0
    assert result.risk_level == "info"
    assert "empty.com" in result.executive_summary


def test_openai_provider_fallback_on_error():
    """If OpenAI call fails, should fall back to local analysis."""
    analyzer = ScanAnalyzer(api_key="fake-key", provider="openai")
    # _analyze_openai will raise because the URL is unreachable; should fall back
    result = analyzer.analyze(_sample_scan_result())
    assert isinstance(result, AnalysisReport)
    assert result.risk_score >= 0


@pytest.mark.asyncio
async def test_openai_provider_mock():
    """Mock the OpenAI HTTP call and verify the report is parsed correctly."""
    import json

    mock_response_data = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "executive_summary": "Mock summary",
                            "risk_score": 55,
                            "risk_level": "high",
                            "top_risks": [{"title": "T", "severity": "high", "description": "D", "explanation": "E"}],
                            "remediation_priorities": [  # noqa: E501
                                {"priority": 1, "title": "T", "severity": "high", "recommended_action": "Fix it"},
                            ],
                            "attack_surface_summary": {"total_findings": 1},
                            "module_summaries": {"vulns": "1 finding"},
                        }
                    )
                }
            }
        ]
    }

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value=mock_response_data)
    mock_resp.raise_for_status = MagicMock()

    mock_resp_cm = MagicMock()
    mock_resp_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp_cm.__aexit__ = AsyncMock(return_value=False)

    mock_session = MagicMock()
    mock_session.post = MagicMock(return_value=mock_resp_cm)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    analyzer = ScanAnalyzer(api_key="fake-key", provider="openai")
    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = await analyzer._analyze_openai(_sample_scan_result())

    assert result.executive_summary == "Mock summary"
    assert result.risk_score == 55
    assert result.risk_level == "high"
