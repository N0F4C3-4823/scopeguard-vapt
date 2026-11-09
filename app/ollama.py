from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .models import TriageModel


@dataclass(frozen=True)
class OllamaStatus:
    reachable: bool
    model_available: bool
    model: str
    url: str
    message: str
    runtime_version: str | None = None
    memory_available_bytes: int | None = None
    memory_sufficient: bool = False
    ready: bool = False


# The 1.5B Q4 model is already resident when triage runs. Keep a meaningful
# headroom gate without disabling inference on the target 7.6 GiB WSL profile
# after the model itself has loaded.
MIN_MEMORY_BYTES = 768 * 1024 * 1024


def available_memory_bytes() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


class OllamaClient:
    def __init__(self, url: str, model: str):
        self.url = url.rstrip("/")
        self.model = model

    def status(self) -> OllamaStatus:
        memory = available_memory_bytes()
        memory_sufficient = memory is None or memory >= MIN_MEMORY_BYTES
        try:
            response = httpx.get(f"{self.url}/api/tags", timeout=2.0)
            response.raise_for_status()
            payload = response.json()
            names = {item.get("name", "") for item in payload.get("models", [])}
            available = self.model in names
            version = None
            try:
                version_response = httpx.get(f"{self.url}/api/version", timeout=2.0)
                if version_response.is_success:
                    version = version_response.json().get("version")
            except Exception:
                pass
            if not available:
                message = f"Exact model {self.model} is not installed"
            elif not memory_sufficient:
                message = "Exact model is installed but available memory is below the safe inference threshold"
            else:
                message = "Ollama responded and the exact model is ready"
            return OllamaStatus(
                True,
                available,
                self.model,
                self.url,
                message,
                runtime_version=version,
                memory_available_bytes=memory,
                memory_sufficient=memory_sufficient,
                ready=available and memory_sufficient,
            )
        except Exception as error:
            return OllamaStatus(
                False,
                False,
                self.model,
                self.url,
                str(error),
                memory_available_bytes=memory,
                memory_sufficient=memory_sufficient,
            )

    def triage(self, *, testcase_id: str, observation_ids: list[str], evidence: str) -> TriageModel:
        status = self.status()
        if not status.ready:
            raise RuntimeError(status.message)
        prompt = json.dumps({
            "task": "Return only the requested JSON object. Explain only the supplied validated observations; do not classify, invent facts, or execute commands.",
            "testcase_id": testcase_id,
            "observation_ids": observation_ids,
            "evidence": evidence[:6000],
            "rules": [
                "Copy testcase_id exactly.",
                "observation_ids must be selected only from the supplied list.",
                "suggested_action_id must be null unless a safe action is directly supported.",
                "Do not add arbitrary object keys.",
            ],
        })
        schema = TriageModel.model_json_schema()
        schema["properties"]["suggested_action_id"] = {
            "anyOf": [
                {"type": "string", "enum": ["collect_safe_banner", "retry_safe_probe", "inspect_existing_evidence"]},
                {"type": "null"},
            ]
        }
        response = httpx.post(
            f"{self.url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": schema,
                "keep_alive": "5m",
                "options": {"num_ctx": 2048, "num_predict": 256, "temperature": 0},
            },
            timeout=90.0,
        )
        response.raise_for_status()
        generated = response.json().get("response", "")
        payload: dict[str, Any] = json.loads(generated)
        triage = TriageModel.model_validate(payload)
        allowed_actions = {None, "collect_safe_banner", "retry_safe_probe", "inspect_existing_evidence"}
        if (
            triage.testcase_id != testcase_id
            or not set(triage.observation_ids).issubset(observation_ids)
            or triage.suggested_action_id not in allowed_actions
        ):
            raise ValueError("Ollama response referenced unknown testcase or observation")
        return triage
