"""Resolves a role (e.g. analysis_model) to a concrete LiteLLM model name for a model_profile."""

from __future__ import annotations

from typing import Any

from app.core.errors import ConfigurationError


class ModelRouter:
    def __init__(self, models_config: dict[str, Any]) -> None:
        self._config = models_config
        self._profiles: dict[str, Any] = models_config.get("profiles", {})
        self._default_profile: str = models_config.get("default_profile", "default")

    def resolve(self, role: str, model_profile: str = "default") -> str:
        profile = self._profiles.get(model_profile)
        if profile is None:
            profile = self._profiles.get(self._default_profile)
        if profile is None:
            raise ConfigurationError(
                f"no model profile '{model_profile}' or default profile "
                f"'{self._default_profile}' found in models config",
                config_key="models.profiles",
            )

        roles = profile.get("roles", {})
        model_name = roles.get(role)
        if model_name is None:
            default_profile = self._profiles.get(self._default_profile, {})
            model_name = default_profile.get("roles", {}).get(role)
        if model_name is None:
            raise ConfigurationError(
                f"role '{role}' is not resolvable in profile '{model_profile}' "
                f"or default profile '{self._default_profile}'",
                config_key=f"models.profiles.{model_profile}.roles.{role}",
            )
        return model_name
