"""Tests for deterministic sanctions tree building."""

from scripts.build_sanctions_tree import normalize_address, BUILD_SCRIPT_VERSION, SANCTIONS_DOMAIN_TAG


class TestAddressNormalization:
    def test_lowercase(self):
        assert normalize_address("0xABCDEF1234567890abcdef1234567890ABCDEF12") == \
            "0xabcdef1234567890abcdef1234567890abcdef12"

    def test_adds_0x_prefix(self):
        assert normalize_address("abcdef1234567890abcdef1234567890abcdef12").startswith("0x")

    def test_strips_whitespace(self):
        assert normalize_address("  0xabc123  ") == normalize_address("0xabc123")

    def test_zero_pads_short_address(self):
        result = normalize_address("0xabc")
        assert len(result) == 42  # 0x + 40 hex
        assert result.startswith("0x")

    def test_deterministic(self):
        """Same input always produces same output."""
        addr = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
        assert normalize_address(addr) == normalize_address(addr)

    def test_checksummed_and_lowercase_same_result(self):
        """EIP-55 checksummed and lowercase produce identical normalized form."""
        checksummed = "0x8589427373D6D84E98730D7795D8f6f8731FDA16"
        lowered = "0x8589427373d6d84e98730d7795d8f6f8731fda16"
        assert normalize_address(checksummed) == normalize_address(lowered)


class TestBuildConfig:
    def test_version_exists(self):
        assert BUILD_SCRIPT_VERSION == "1.0.0"

    def test_domain_tag(self):
        assert SANCTIONS_DOMAIN_TAG == 1

    def test_sorted_output_is_deterministic(self):
        """Sorting normalized addresses is deterministic."""
        addrs = [
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "0x0000000000000000000000000000000000000001",
            "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
        ]
        normalized = sorted(normalize_address(a) for a in addrs)
        normalized2 = sorted(normalize_address(a) for a in reversed(addrs))
        assert normalized == normalized2
