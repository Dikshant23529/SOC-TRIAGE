"""Optional AI providers — only invoked when AI is enabled and an API key is configured."""

from __future__ import annotations

import httpx


class AIProviderError(Exception):
    pass


async def complete_investigation(
    *,
    provider: str,
    model: str,
    api_key: str,
    base_url: str | None,
    system_prompt: str,
    user_prompt: str,
) -> str:
    provider = provider.lower().strip()

    if provider == "openai":
        return await _openai_compatible(
            url=(base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions",
            api_key=api_key,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    if provider == "anthropic":
        return await _anthropic(api_key=api_key, model=model, system_prompt=system_prompt, user_prompt=user_prompt)
    if provider in ("ollama", "openai_compatible", "custom"):
        url = (base_url or "http://localhost:11434/v1").rstrip("/") + "/chat/completions"
        return await _openai_compatible(
            url=url,
            api_key=api_key or "ollama",
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    raise AIProviderError(f"Unsupported provider: {provider}")


async def _openai_compatible(
    *, url: str, api_key: str, model: str, system_prompt: str, user_prompt: str
) -> str:
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code >= 400:
            raise AIProviderError(f"AI API error {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError) as exc:
        raise AIProviderError("Unexpected AI response format") from exc


async def _anthropic(*, api_key: str, model: str, system_prompt: str, user_prompt: str) -> str:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)
        if resp.status_code >= 400:
            raise AIProviderError(f"Anthropic error {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
    try:
        return data["content"][0]["text"].strip()
    except (KeyError, IndexError) as exc:
        raise AIProviderError("Unexpected Anthropic response format") from exc
