from app.langchain_utils.parsers import parse_json_response
from app.langchain_utils.prompts import build_secrets_triage_prompt


def test_secrets_prompt_requests_the_keys_the_agent_reads():
    prompt = build_secrets_triage_prompt("title=aws key file=app.py")
    assert '"is_placeholder"' in prompt
    assert '"rationale"' in prompt


def test_secrets_verdict_round_trips_through_parser():
    parsed = parse_json_response(
        '```json\n{"is_placeholder": true, "confidence": "high", "rationale": "example"}\n```'
    )
    assert parsed["is_placeholder"] is True
