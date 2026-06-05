"""Parallel investigation agents — rule-based by default; optional AI when configured."""

from __future__ import annotations

import asyncio
import json
import random
import string
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto_util import decrypt_secret
from app.database import SessionLocal
from app.models import Alert, AppSettings, Investigation, utcnow
from app.services.ai_providers import AIProviderError, complete_investigation

_running: set[str] = set()

SYSTEM_PROMPT = """You are a senior SOC analyst. Analyze the alert evidence (process tree, timeline logs, IOCs, raw logs).
Produce a structured investigation report in Markdown with sections:
Executive Summary, Timeline Analysis, Process Tree Review, IOC Assessment, Hypothesis, Recommended Actions, Confidence Level.
Be factual; flag uncertainty. Do not invent hosts or hashes not present in the evidence."""


def _gen_alert_id() -> str:
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"ALT-{suffix}"


def _append_message(messages: list[dict], role: str, content: str) -> None:
    messages.append(
        {
            "role": role,
            "content": content,
            "ts": utcnow().isoformat(),
        }
    )


async def _load_settings(session: AsyncSession) -> AppSettings:
    row = await session.get(AppSettings, 1)
    if not row:
        row = AppSettings(id=1)
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row


async def _persist_messages(inv: Investigation, messages: list[dict], **fields) -> None:
    inv.messages_json = json.dumps(messages)
    for key, value in fields.items():
        setattr(inv, key, value)


def _build_evidence_block(alert: Alert) -> str:
    parts = [
        f"Alert ID: {alert.alert_id}",
        f"Title: {alert.title}",
        f"Severity: {alert.severity}",
        f"Category: {alert.category}",
        f"Asset: {alert.affected_asset}",
        f"User: {alert.affected_user or 'N/A'}",
        f"Description: {alert.description or 'N/A'}",
        f"IOCs:\n{alert.ioc_list or 'None'}",
        f"Process Tree:\n{alert.process_tree or 'Not provided'}",
        f"Timeline Logs:\n{alert.timeline_logs or 'Not provided'}",
        f"Raw Log:\n{alert.raw_log or 'Not provided'}",
    ]
    return "\n\n".join(parts)


def _rule_based_report(alert: Alert) -> str:
    tree_lines = (alert.process_tree or "").strip().splitlines()
    timeline_lines = (alert.timeline_logs or "").strip().splitlines()
    ioc_lines = (alert.ioc_list or "").strip().splitlines()

    return f"""# Investigation Report — {alert.alert_id}

> **Mode:** Rule-based analysis (AI disabled or not configured). Enable AI in Settings and provide an API key for LLM-assisted investigation.

## Executive Summary
Alert **{alert.title}** ({alert.severity}) on asset **{alert.affected_asset}** requires analyst review. Automated triage parsed {len(tree_lines)} process-tree lines, {len(timeline_lines)} timeline entries, and {len(ioc_lines)} IOC lines.

## Timeline Analysis
{chr(10).join(f'- {line}' for line in timeline_lines[:20]) if timeline_lines else '- No timeline logs supplied.'}

## Process Tree Review
{chr(10).join(f'- `{line.strip()}`' for line in tree_lines[:25]) if tree_lines else '- No process tree pasted.'}

## IOC Assessment
{chr(10).join(f'- {line}' for line in ioc_lines[:30]) if ioc_lines else '- No IOCs listed.'}

## Hypothesis
Based on category **{alert.category}**, prioritize validating execution context on **{alert.affected_asset}** and correlating timeline events with the parent process chain.

## Recommended Actions
1. Confirm with resource owner whether activity was authorized.
2. Isolate host if unauthorized execution is confirmed.
3. Hunt for same IOCs / parent process across fleet.
4. Document outcome (TP/FP) and tune detection.

## Confidence Level
**Medium** — human validation required; enable AI investigation for deeper script/log interpretation when API key is configured.
"""


async def run_investigation(investigation_id: str) -> None:
    if investigation_id in _running:
        return
    _running.add(investigation_id)

    try:
        async with SessionLocal() as session:
            inv = await session.get(Investigation, investigation_id)
            if not inv:
                return
            alert = await session.get(Alert, inv.alert_id)
            if not alert:
                return

            settings = await _load_settings(session)
            messages: list[dict] = json.loads(inv.messages_json or "[]")

            inv.status = "running"
            inv.started_at = utcnow()
            inv.current_step = "Initializing agent"
            inv.progress_pct = 5
            _append_message(messages, "system", f"Investigation agent started for {alert.alert_id}")
            await _persist_messages(inv, messages)
            await session.commit()

            steps = [
                (15, "Ingesting alert metadata", "agent", f"Loaded alert {alert.alert_id} — {alert.severity} / {alert.category}"),
                (30, "Parsing process tree", "agent", _summarize_process_tree(alert.process_tree)),
                (50, "Correlating timeline logs", "agent", _summarize_timeline(alert.timeline_logs)),
                (65, "Evaluating IOCs and raw logs", "agent", _summarize_iocs(alert.ioc_list, alert.raw_log)),
                (80, "Building investigation narrative", "agent", "Synthesizing findings into report structure…"),
            ]

            for pct, step_label, role, content in steps:
                await asyncio.sleep(0.6)
                inv.current_step = step_label
                inv.progress_pct = pct
                _append_message(messages, role, content)
                await _persist_messages(inv, messages, current_step=step_label, progress_pct=pct)
                await session.commit()

            ai_used = False
            report: str

            if settings.ai_enabled and settings.api_key_encrypted:
                inv.current_step = "Calling AI provider"
                inv.progress_pct = 90
                _append_message(
                    messages,
                    "agent",
                    f"AI enabled — querying {settings.ai_provider} ({settings.ai_model})…",
                )
                await _persist_messages(inv, messages, current_step=inv.current_step, progress_pct=90)
                await session.commit()

                try:
                    api_key = decrypt_secret(settings.api_key_encrypted)
                    report = await complete_investigation(
                        provider=settings.ai_provider,
                        model=settings.ai_model,
                        api_key=api_key,
                        base_url=settings.api_base_url,
                        system_prompt=SYSTEM_PROMPT,
                        user_prompt=_build_evidence_block(alert),
                    )
                    ai_used = True
                    _append_message(messages, "result", "AI investigation completed successfully.")
                except AIProviderError as exc:
                    report = _rule_based_report(alert)
                    _append_message(messages, "agent", f"AI call failed, fallback to rule-based report: {exc}")
            else:
                report = _rule_based_report(alert)
                _append_message(
                    messages,
                    "agent",
                    "AI disabled — generated rule-based investigation report. Enable AI in Settings to use your API key.",
                )

            inv.status = "completed"
            inv.progress_pct = 100
            inv.current_step = "Complete"
            inv.report_markdown = report
            inv.ai_used = ai_used
            inv.completed_at = utcnow()
            _append_message(messages, "result", "Investigation report ready.")
            await _persist_messages(inv, messages)
            await session.commit()
    except Exception as exc:
        async with SessionLocal() as session:
            inv = await session.get(Investigation, investigation_id)
            if inv:
                inv.status = "failed"
                inv.error = str(exc)
                inv.completed_at = utcnow()
                msgs = json.loads(inv.messages_json or "[]")
                _append_message(msgs, "agent", f"Investigation failed: {exc}")
                inv.messages_json = json.dumps(msgs)
                await session.commit()
    finally:
        _running.discard(investigation_id)


def _summarize_process_tree(text: str | None) -> str:
    if not text or not text.strip():
        return "No process tree provided — recommend pasting Sysmon/EDR process lineage."
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    suspicious = [ln for ln in lines if any(k in ln.lower() for k in ("powershell", "cmd", "wscript", "rundll32", "encoded"))]
    summary = f"Parsed {len(lines)} process nodes."
    if suspicious:
        summary += f" Flagged {len(suspicious)} potentially suspicious entries (script hosts / encoded commands)."
    return summary


def _summarize_timeline(text: str | None) -> str:
    if not text or not text.strip():
        return "No timeline logs provided — paste SIEM/EDR chronological events for correlation."
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    return f"Indexed {len(lines)} timeline events for sequential correlation."


def _summarize_iocs(iocs: str | None, raw: str | None) -> str:
    ioc_n = len([ln for ln in (iocs or "").splitlines() if ln.strip()])
    raw_n = len((raw or "").splitlines()) if raw else 0
    return f"Catalogued {ioc_n} IOC lines and {raw_n} raw log lines for enrichment."


async def start_investigation_for_alert(session: AsyncSession, alert: Alert) -> Investigation:
    inv = Investigation(alert_id=alert.id, status="queued", messages_json="[]")
    session.add(inv)
    await session.commit()
    await session.refresh(inv)
    asyncio.create_task(run_investigation(inv.id))
    return inv
