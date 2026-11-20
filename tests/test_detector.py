import pytest

from pii_redactor import detect, redact, summarize
from pii_redactor.detector import luhn_valid

# All values below are fake. 4111 1111 1111 1111 is a standard test card number.


def types_in(text):
    return [f.pii_type for f in detect(text)]


def test_detects_ssn():
    assert types_in("SSN: 123-45-6789") == ["SSN"]


@pytest.mark.parametrize("bad_ssn", ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000"])
def test_ignores_invalid_ssns(bad_ssn):
    assert "SSN" not in types_in(bad_ssn)


def test_detects_email():
    assert types_in("Contact jane.doe@example.com today") == ["EMAIL"]


@pytest.mark.parametrize("phone", ["(215) 555-0123", "215-555-0123", "215.555.0123", "+1 215 555 0123"])
def test_detects_phone_formats(phone):
    assert types_in(f"Call {phone} now") == ["PHONE"]


def test_detects_valid_credit_card():
    assert types_in("Card 4111 1111 1111 1111 on file") == ["CREDIT_CARD"]


def test_ignores_number_that_fails_luhn():
    assert "CREDIT_CARD" not in types_in("Order 4111 1111 1111 1112")


def test_luhn():
    assert luhn_valid("4111-1111-1111-1111")
    assert not luhn_valid("1234 5678 9012 3456")


def test_detects_ip_address():
    assert types_in("Login from 192.168.10.25") == ["IP_ADDRESS"]


def test_plain_text_has_no_findings():
    assert detect("The meeting is on 11/20/2026 in room 405.") == []


def test_redact_replaces_values_with_labels():
    cleaned, findings = redact("Email a@b.com or call 215-555-0123.")
    assert cleaned == "Email [EMAIL] or call [PHONE]."
    assert len(findings) == 2


def test_mask_keeps_last_four_digits():
    cleaned, _ = redact("SSN 123-45-6789, card 4111-1111-1111-1111", mode="mask")
    assert cleaned == "SSN ***-6789, card ***-1111"


def test_mask_email_keeps_domain():
    cleaned, _ = redact("jane.doe@example.com", mode="mask")
    assert cleaned == "j***@example.com"


def test_redacted_text_contains_no_original_values():
    text = "Jane, 123-45-6789, jane@example.com, (215) 555-0123"
    cleaned, findings = redact(text)
    for finding in findings:
        assert finding.value not in cleaned


def test_summarize_counts_by_type_without_values():
    _, findings = redact("a@b.com c@d.com 123-45-6789")
    assert summarize(findings) == {"EMAIL": 2, "SSN": 1}


def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        redact("text", mode="hide")
