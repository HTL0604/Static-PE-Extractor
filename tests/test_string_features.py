from app.features.string_features import extract_string_features


def test_string_feature_extracts_ascii_and_url() -> None:
    blob = b"http://example.com AAAA C:\\Windows\\Temp\\x.exe powershell"
    result = extract_string_features(blob, preview_limit=5)
    assert result["ascii_string_count"] >= 1
    assert any("http://example.com" in s for s in result["url_strings"])
    assert any("powershell" in s.lower() for s in result["suspicious_strings"])

