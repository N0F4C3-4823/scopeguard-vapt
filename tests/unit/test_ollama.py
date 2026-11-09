from __future__ import annotations

import json

import pytest

import app.ollama as ollama_module
from app.ollama import OllamaClient


class FakeResponse:
    status_code = 200
    is_success = True

    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def _tags(model: str = "qwen2.5:1.5b-instruct"):
    return FakeResponse({"models": [{"name": model}]})


def test_ollama_requires_exact_model_identifier(monkeypatch):
    client = OllamaClient("http://127.0.0.1:11434", "qwen2.5:1.5b-instruct")
    monkeypatch.setattr(ollama_module, "available_memory_bytes", lambda: 2_000 * 1024 * 1024)
    monkeypatch.setattr(
        ollama_module.httpx,
        "get",
        lambda url, timeout: _tags("qwen2.5:1.5b-instruct-q5_0")
        if url.endswith("/api/tags")
        else FakeResponse({"version": "0.40.15"}),
    )
    status = client.status()
    assert status.reachable is True
    assert status.model_available is False
    assert status.ready is False


def test_ollama_validates_schema_and_observation_references(monkeypatch):
    client = OllamaClient("http://127.0.0.1:11434", "qwen2.5:1.5b-instruct")
    monkeypatch.setattr(ollama_module, "available_memory_bytes", lambda: 2_000 * 1024 * 1024)
    monkeypatch.setattr(
        ollama_module.httpx,
        "get",
        lambda url, timeout: _tags() if url.endswith("/api/tags") else FakeResponse({"version": "0.40.15"}),
    )
    valid = {
        "testcase_id": "08",
        "observation_ids": ["obs-1"],
        "interpretation": "The output describes a supplied observation.",
        "suggested_action_id": None,
        "explanation": "Evidence-grounded explanation.",
        "limitations": [],
        "requires_additional_evidence": False,
    }
    monkeypatch.setattr(
        ollama_module.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse({"response": json.dumps(valid)}),
    )
    result = client.triage(testcase_id="08", observation_ids=["obs-1"], evidence="captured")
    assert result.observation_ids == ["obs-1"]

    hallucinated = {**valid, "observation_ids": ["obs-not-present"]}
    monkeypatch.setattr(
        ollama_module.httpx,
        "post",
        lambda *args, **kwargs: FakeResponse({"response": json.dumps(hallucinated)}),
    )
    with pytest.raises(ValueError, match="unknown testcase or observation"):
        client.triage(testcase_id="08", observation_ids=["obs-1"], evidence="captured")


def test_ollama_fails_closed_when_memory_is_below_threshold(monkeypatch):
    client = OllamaClient("http://127.0.0.1:11434", "qwen2.5:1.5b-instruct")
    monkeypatch.setattr(ollama_module, "available_memory_bytes", lambda: 128 * 1024 * 1024)
    monkeypatch.setattr(ollama_module.httpx, "get", lambda url, timeout: _tags())
    status = client.status()
    assert status.model_available is True
    assert status.memory_sufficient is False
    assert status.ready is False
    with pytest.raises(RuntimeError, match="below the safe inference threshold"):
        client.triage(testcase_id="08", observation_ids=[], evidence="captured")
