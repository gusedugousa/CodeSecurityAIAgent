from app.core.security import redact_dict, redact_secrets


def test_redacts_aws_access_key():
    text = "aws_key = AKIAIOSFODNN7EXAMPLE"
    assert "AKIAIOSFODNN7EXAMPLE" not in redact_secrets(text)


def test_redacts_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    result = redact_secrets(text)
    assert "MIIB" not in result
    assert "[REDACTED]" in result


def test_redacts_bearer_token():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    result = redact_secrets(text)
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in result


def test_redacts_key_value_assignment():
    text = 'api_key = "sk-1234567890abcdef1234567890"'
    result = redact_secrets(text)
    assert "sk-1234567890abcdef1234567890" not in result


def test_leaves_ordinary_code_untouched():
    text = "def add(a, b):\n    return a + b\n"
    assert redact_secrets(text) == text


def test_empty_string_passthrough():
    assert redact_secrets("") == ""


def test_redact_dict_redacts_secret_shaped_keys():
    data = {"username": "alice", "password": "hunter2", "nested": {"api_token": "xyz123abc"}}
    result = redact_dict(data)
    assert result["username"] == "alice"
    assert result["password"] == "[REDACTED]"
    assert result["nested"]["api_token"] == "[REDACTED]"


def test_redact_dict_recurses_into_lists():
    data = {"items": [{"secret": "abc123def456"}, {"secret": None}]}
    result = redact_dict(data)
    assert result["items"][0]["secret"] == "[REDACTED]"
    assert result["items"][1]["secret"] is None
