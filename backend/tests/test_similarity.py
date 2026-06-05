import pytest
from app.models import Alert
from app.services.similarity import _tokenize, _jaccard_similarity, calculate_similarity


def test_tokenize():
    text = "explorer.exe -> cmd.exe /c powershell.exe -enc abc"
    tokens = _tokenize(text)
    assert "explorer" in tokens
    assert "cmd" in tokens
    assert "powershell" in tokens
    assert "enc" in tokens
    assert "abc" in tokens
    assert len(tokens) == 7


def test_jaccard_similarity():
    set_a = {"powershell", "encoded", "malicious"}
    set_b = {"powershell", "encoded", "payload"}
    # intersection: 2, union: 4 -> 0.5
    assert _jaccard_similarity(set_a, set_b) == 0.5
    
    assert _jaccard_similarity(set(), set()) == 1.0
    assert _jaccard_similarity(set_a, set()) == 0.0


def test_calculate_similarity():
    alert_a = Alert(
        title="Suspicious Powershell Execution",
        category="Malware / Endpoint",
        severity="High",
        affected_asset="WKST-042",
        affected_user="john.doe",
        process_tree="explorer.exe -> cmd.exe -> powershell.exe"
    )
    
    # Identical alert
    score, details = calculate_similarity(alert_a, alert_a)
    assert score == 100
    assert details["title_match"] == 100
    assert details["category_match"] == 100
    assert details["asset_match"] == 100
    assert details["user_match"] == 100
    assert details["script_match"] == 100

    # Partially matching alert
    alert_b = Alert(
        title="Powershell run on WKST-042",
        category="Malware / Endpoint",
        severity="High",
        affected_asset="WKST-042",
        affected_user="jane.smith",
        process_tree="cmd.exe -> powershell.exe"
    )
    score_b, details_b = calculate_similarity(alert_a, alert_b)
    # user matches: 0%, title matches: part, asset matches: 100%
    assert score_b > 25
    assert details_b["asset_match"] == 100
    assert details_b["user_match"] == 0
