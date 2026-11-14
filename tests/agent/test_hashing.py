"""
Tests for Content Hashing — AgentShield
Verifies Unicode NFC normalization, newline normalization, and SHA-256 integrity.
"""

import hashlib
import pytest

from backend.agent.hashing import (
    hash_content,
    normalize_content,
    verify_content_hash,
    is_valid_sha256_hex,
)


class TestContentNormalizationAndHashing:

    def test_empty_string_hash(self):
        """Empty string produces standard SHA-256 digest."""
        expected = hashlib.sha256(b"").hexdigest()
        assert hash_content("") == expected
        assert expected == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_unicode_nfc_normalization(self):
        """
        Decomposed Unicode (e + combining acute accent) and precomposed Unicode
        must produce identical SHA-256 digests.
        """
        decomposed = "cafe\u0301"  # 'e' + combining acute accent
        precomposed = "caf\u00e9"  # single precomposed 'é'

        assert decomposed != precomposed
        assert normalize_content(decomposed) == normalize_content(precomposed)
        assert hash_content(decomposed) == hash_content(precomposed)

    def test_newline_normalization(self):
        """
        Windows (CRLF), old Mac (CR), and Unix (LF) line endings must produce
        identical SHA-256 digests.
        """
        lf = "line1\nline2\nline3"
        crlf = "line1\r\nline2\r\nline3"
        cr = "line1\rline2\rline3"
        mixed = "line1\r\nline2\rline3\n"

        assert hash_content(lf) == hash_content(crlf)
        assert hash_content(lf) == hash_content(cr)
        assert hash_content(lf + "\n") == hash_content(mixed)

    def test_combined_unicode_and_newline_normalization(self):
        """Combined Unicode decomposition and CRLF produces identical hash to precomposed LF."""
        text_a = "Header:\r\nResume: cafe\u0301\r\nSummary: Done"
        text_b = "Header:\nResume: caf\u00e9\nSummary: Done"
        assert hash_content(text_a) == hash_content(text_b)

    def test_multilingual_and_emoji_support(self):
        """Validates hashing over Devanagari, CJK, and emoji content."""
        hindi = "सुरक्षा एजेंट शील्ड"
        cjk = "安全代理护盾"
        emoji = "🛡️ AI Agent Security"

        h_hindi = hash_content(hindi)
        h_cjk = hash_content(cjk)
        h_emoji = hash_content(emoji)

        assert is_valid_sha256_hex(h_hindi)
        assert is_valid_sha256_hex(h_cjk)
        assert is_valid_sha256_hex(h_emoji)
        assert len({h_hindi, h_cjk, h_emoji}) == 3

    def test_type_error_on_non_string_input(self):
        """Non-string inputs must raise TypeError."""
        for invalid in [None, 12345, b"bytes_not_allowed", ["list"], {"dict": 1}]:
            with pytest.raises(TypeError) as exc_info:
                hash_content(invalid)  # type: ignore[arg-type]
            assert "Content must be a string" in str(exc_info.value)

    def test_verify_content_hash_success(self):
        """verify_content_hash returns True on exact match (case-insensitive for expected digest)."""
        content = "Confidential sanitized report [PERSON_1]"
        h = hash_content(content)
        assert verify_content_hash(content, h) is True
        assert verify_content_hash(content, h.upper()) is True

    def test_verify_content_hash_mismatch(self):
        """verify_content_hash returns False when content differs or digest is wrong."""
        content = "Original report"
        tampered = "Tampered report"
        h = hash_content(content)
        assert verify_content_hash(tampered, h) is False
        assert verify_content_hash(content, "0" * 64) is False
        assert verify_content_hash(content, "invalid_hex") is False

    def test_is_valid_sha256_hex(self):
        """is_valid_sha256_hex validates 64-character lowercase hexadecimal format."""
        valid_digest = "a" * 64
        assert is_valid_sha256_hex(valid_digest) is True
        assert is_valid_sha256_hex("0123456789abcdef" * 4) is True

        # Invalid: uppercase
        assert is_valid_sha256_hex("A" * 64) is False
        # Invalid: length 63 or 65
        assert is_valid_sha256_hex("a" * 63) is False
        assert is_valid_sha256_hex("a" * 65) is False
        # Invalid: non-hex characters
        assert is_valid_sha256_hex("g" * 64) is False
        # Invalid: non-string
        assert is_valid_sha256_hex(None) is False  # type: ignore[arg-type]
        assert is_valid_sha256_hex(12345) is False  # type: ignore[arg-type]
