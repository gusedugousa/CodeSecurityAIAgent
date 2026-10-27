import pytest

from app.models.litellm_client import LiteLLMModelClient
from app.models.routing import ModelRouter
from app.models.schemas import ModelRequest

MODELS_CONFIG = {
    "default_profile": "default",
    "mock_mode": True,
    "profiles": {
        "default": {
            "roles": {
                "analysis_model": "anthropic/claude-sonnet-4",
                "remediation_model": "anthropic/claude-sonnet-4",
            }
        },
        "mock": {
            "roles": {
                "analysis_model": "mock/mock-analysis",
            }
        },
    },
    "cost_table_per_1k_tokens": {
        "anthropic/claude-sonnet-4": {"input": 0.003, "output": 0.015},
    },
}


@pytest.mark.asyncio
async def test_mock_mode_never_calls_network_and_returns_deterministic_response():
    client = LiteLLMModelClient(MODELS_CONFIG, mock_mode=True)
    request = ModelRequest(
        messages=[{"role": "user", "content": "review this code"}],
        role="analysis_model",
        analysis_id="test-1",
    )
    response = await client.call(request, model_name="anthropic/claude-sonnet-4")
    assert response.metadata.mock is True
    assert response.metadata.cost_estimate == 0.0
    assert response.content


@pytest.mark.asyncio
async def test_mock_prefixed_model_forces_mock_even_if_global_mock_mode_false():
    client = LiteLLMModelClient(MODELS_CONFIG, mock_mode=False)
    request = ModelRequest(
        messages=[{"role": "user", "content": "x"}], role="analysis_model", analysis_id="t"
    )
    response = await client.call(request, model_name="mock/mock-analysis")
    assert response.metadata.mock is True


def test_model_router_resolves_role_for_profile():
    router = ModelRouter(MODELS_CONFIG)
    resolved = router.resolve("analysis_model", model_profile="default")
    assert resolved == "anthropic/claude-sonnet-4"


def test_model_router_falls_back_to_default_profile_for_unknown_profile():
    router = ModelRouter(MODELS_CONFIG)
    resolved = router.resolve("analysis_model", model_profile="nonexistent-profile")
    assert resolved == "anthropic/claude-sonnet-4"
