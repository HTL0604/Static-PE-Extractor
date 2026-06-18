from app.features.section_features import extract_section_features


class _Section:
    def __init__(self, name: bytes, data: bytes) -> None:
        self.Name = name
        self._data = data
        self.Misc_VirtualSize = len(data)
        self.SizeOfRawData = len(data)
        self.Characteristics = 0x60000020

    def get_data(self) -> bytes:
        return self._data


class _Pe:
    def __init__(self) -> None:
        self.sections = [_Section(b".text\x00", b"A" * 200), _Section(b"UPX0\x00", bytes(range(64)))]


def test_section_feature_detects_suspicious_name() -> None:
    result = extract_section_features(_Pe(), high_entropy_threshold=5.0, suspicious_names={"upx0"})
    assert result["section_count"] == 2
    assert "UPX0" in result["suspicious_section_names"]

