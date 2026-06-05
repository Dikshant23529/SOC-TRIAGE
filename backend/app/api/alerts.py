import csv
import io
import json
import random
import re
import string
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.auth import get_current_user
from app.database import get_db
from app.models import Alert, Investigation, AlertMatch
from app.schemas import AgentMessage, AlertCreate, AlertOut, AlertUpdate, InvestigationOut, AlertMatchOut, TriageLikelihood
from app.services.investigation import start_investigation_for_alert

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
    dependencies=[Depends(get_current_user)]
)


def _gen_alert_id() -> str:
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"ALT-{suffix}"


def _inv_to_out(inv: Investigation) -> InvestigationOut:
    messages = json.loads(inv.messages_json or "[]")
    return InvestigationOut(
        id=inv.id,
        alert_id=inv.alert_id,
        status=inv.status,
        progress_pct=inv.progress_pct,
        current_step=inv.current_step,
        messages=[AgentMessage(**m) for m in messages],
        report_markdown=inv.report_markdown,
        error=inv.error,
        ai_used=inv.ai_used,
        started_at=inv.started_at,
        completed_at=inv.completed_at,
        created_at=inv.created_at,
    )


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    q: str | None = Query(None, description="Full-text search across title, host, user, IOCs, description"),
    status: str | None = Query(None, description="Filter by status: pending, tp, fp, unclear"),
    resolved: bool | None = Query(None, description="True=show only tp/fp, False=show only open/pending"),
    tag: str | None = Query(None, description="Filter alerts containing this tag"),
    severity: str | None = Query(None, description="Filter by severity: Critical, High, Medium, Low"),
    category: str | None = Query(None, description="Filter by category"),
):
    query = select(Alert).order_by(Alert.created_at.desc())

    # Status filter
    if status:
        query = query.where(Alert.status == status)
    elif resolved is True:
        query = query.where(Alert.status.in_(["tp", "fp"]))
    elif resolved is False:
        query = query.where(Alert.status.in_(["pending", "unclear"]))

    # Severity / category filter
    if severity:
        query = query.where(Alert.severity == severity)
    if category:
        query = query.where(Alert.category == category)

    # Tag filter
    if tag:
        query = query.where(Alert.tags.contains(tag))

    result = await db.execute(query)
    alerts_all = result.scalars().all()

    # Full-text search (applied in Python to support SQLite's lack of FTS)
    if q:
        q_lower = q.lower()
        alerts_all = [
            a for a in alerts_all
            if q_lower in (a.title or "").lower()
            or q_lower in (a.affected_asset or "").lower()
            or q_lower in (a.affected_user or "").lower()
            or q_lower in (a.description or "").lower()
            or q_lower in (a.ioc_list or "").lower()
            or q_lower in (a.alert_id or "").lower()
            or q_lower in (a.tags or "").lower()
        ]

    return alerts_all


@router.post("", response_model=AlertOut, status_code=201)
async def create_alert(payload: AlertCreate, db: AsyncSession = Depends(get_db)):
    alert = Alert(
        alert_id=payload.alert_id or _gen_alert_id(),
        title=payload.title,
        severity=payload.severity,
        category=payload.category,
        source=payload.source,
        timestamp=payload.timestamp,
        affected_asset=payload.affected_asset,
        affected_user=payload.affected_user,
        owner_team=payload.owner_team,
        owner_email=payload.owner_email,
        description=payload.description,
        ioc_list=payload.ioc_list,
        raw_log=payload.raw_log,
        process_tree=payload.process_tree,
        timeline_logs=payload.timeline_logs,
        status=payload.status,
        notes=payload.notes,
        tags=payload.tags,
        validation_json=payload.validation_json,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)

    try:
        from app.services.similarity import find_and_save_matches
        await find_and_save_matches(db, alert)
    except Exception:
        pass

    return alert


@router.get("/export/csv")
async def export_all_alerts_csv(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).order_by(Alert.created_at.desc()))
    alerts_list = result.scalars().all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    fields = [
        "id", "alert_id", "title", "severity", "category", "source", 
        "timestamp", "affected_asset", "affected_user", "owner_team", 
        "owner_email", "status", "created_at"
    ]
    writer.writerow(fields)
    for a in alerts_list:
        writer.writerow([getattr(a, f) for f in fields])
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=all_alerts.csv"}
    )


@router.get("/{alert_pk}", response_model=AlertOut)
async def get_alert(alert_pk: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_pk}", response_model=AlertOut)
async def update_alert(alert_pk: str, payload: AlertUpdate, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(alert, key, value)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.delete("/{alert_pk}", status_code=204)
async def delete_alert(alert_pk: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
    await db.delete(alert)
    await db.commit()


@router.get("/{alert_pk}/investigations", response_model=list[InvestigationOut])
async def list_investigations(alert_pk: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
    result = await db.execute(
        select(Investigation)
        .where(Investigation.alert_id == alert_pk)
        .order_by(Investigation.created_at.desc())
    )
    return [_inv_to_out(i) for i in result.scalars().all()]


@router.post("/{alert_pk}/investigate", response_model=InvestigationOut, status_code=202)
async def trigger_investigation(alert_pk: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert).where(Alert.id == alert_pk).options(selectinload(Alert.investigations))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    inv = await start_investigation_for_alert(db, alert)
    return _inv_to_out(inv)


@router.get("/{alert_pk}/matches", response_model=list[AlertMatchOut])
async def list_matches(alert_pk: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AlertMatch)
        .where(AlertMatch.alert_id == alert_pk)
        .order_by(AlertMatch.score.desc())
    )
    matches = result.scalars().all()
    
    out = []
    for m in matches:
        matched_alert = await db.get(Alert, m.matched_alert_id)
        out.append(AlertMatchOut(
            id=m.id,
            alert_id=m.alert_id,
            matched_alert_id=m.matched_alert_id,
            score=m.score,
            details_json=m.details_json,
            created_at=m.created_at,
            matched_alert_title=matched_alert.title if matched_alert else None,
            matched_alert_status=matched_alert.status if matched_alert else None
        ))
    return out


@router.get("/{alert_pk}/likelihood", response_model=TriageLikelihood)
async def get_likelihood(alert_pk: str, db: AsyncSession = Depends(get_db)):
    """Calculate TP/FP probability based on historical matching incidents."""
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")

    result = await db.execute(
        select(AlertMatch).where(AlertMatch.alert_id == alert_pk).order_by(AlertMatch.score.desc())
    )
    matches = result.scalars().all()

    if not matches:
        return TriageLikelihood(
            tp_probability=70, fp_probability=30,
            assessment="new_threat",
            reason="No historical matches found. New or unique alert pattern — treat as suspicious until proven otherwise.",
            total_matches=0, tp_matches=0, fp_matches=0
        )

    # Only consider significant matches (>=40%)
    significant = [m for m in matches if m.score >= 40]
    if not significant:
        return TriageLikelihood(
            tp_probability=60, fp_probability=40,
            assessment="uncertain",
            reason=f"Found {len(matches)} weak matches (all <40% similarity). Insufficient historical data to make a strong prediction.",
            total_matches=len(matches), tp_matches=0, fp_matches=0
        )

    # Count TP and FP among matched historical alerts
    tp_count = 0
    fp_count = 0
    for m in significant:
        matched = await db.get(Alert, m.matched_alert_id)
        if matched:
            if matched.status == "tp":
                tp_count += 1
            elif matched.status == "fp":
                fp_count += 1

    total = tp_count + fp_count
    if total == 0:
        return TriageLikelihood(
            tp_probability=55, fp_probability=45,
            assessment="uncertain",
            reason=f"Found {len(significant)} similar historical alerts, but none have been resolved yet (all pending/unclear).",
            total_matches=len(significant), tp_matches=0, fp_matches=0
        )

    # Weighted by similarity score
    tp_weight = sum(m.score for m in significant if (await db.get(Alert, m.matched_alert_id) and (await db.get(Alert, m.matched_alert_id)).status == "tp"))
    fp_weight = sum(m.score for m in significant if (await db.get(Alert, m.matched_alert_id) and (await db.get(Alert, m.matched_alert_id)).status == "fp"))

    total_weight = tp_weight + fp_weight if (tp_weight + fp_weight) > 0 else 1
    tp_prob = int(round(tp_weight / total_weight * 100))
    fp_prob = 100 - tp_prob

    if fp_prob >= 65:
        assessment = "likely_fp"
        reason = (
            f"Found {len(significant)} similar historical alerts: {fp_count} were False Positive, {tp_count} were True Positive. "
            f"High FP probability ({fp_prob}%) — this may be expected/authorized activity. Verify with change management or asset owner."
        )
    elif tp_prob >= 65:
        assessment = "likely_tp"
        reason = (
            f"Found {len(significant)} similar historical alerts: {tp_count} were True Positive, {fp_count} were False Positive. "
            f"High TP probability ({tp_prob}%) — this pattern has been confirmed malicious before. Escalate for investigation."
        )
    else:
        assessment = "uncertain"
        reason = (
            f"Found {len(significant)} similar historical alerts (TP: {tp_count}, FP: {fp_count}). "
            f"Mixed historical resolution — analyst review recommended. Complete the validation checklist for more context."
        )

    return TriageLikelihood(
        tp_probability=tp_prob, fp_probability=fp_prob,
        assessment=assessment, reason=reason,
        total_matches=len(significant), tp_matches=tp_count, fp_matches=fp_count
    )


@router.get("/{alert_pk}/export/csv")
async def export_single_alert_csv(alert_pk: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
        
    output = io.StringIO()
    writer = csv.writer(output)
    
    fields = [
        "id", "alert_id", "title", "severity", "category", "source", 
        "timestamp", "affected_asset", "affected_user", "owner_team", 
        "owner_email", "description", "ioc_list", "raw_log", 
        "process_tree", "timeline_logs", "status", "notes", "created_at"
    ]
    writer.writerow(fields)
    writer.writerow([getattr(alert, f) for f in fields])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=alert_{alert.alert_id}.csv"}
    )


def parse_md_inline_tags(text: str) -> str:
    import html
    text = html.escape(text)
    text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\*(.*?)\*", r"<i>\1</i>", text)
    text = re.sub(r"`(.*?)`", r"<font face='Courier'>\1</font>", text)
    return text


def markdown_to_flowables(md_text: str, styles, normal_text, heading_style):
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.styles import ParagraphStyle
    flowables = []
    if not md_text:
        return flowables
        
    lines = md_text.split("\n")
    
    h1 = ParagraphStyle("MDH1", parent=heading_style, fontSize=14, spaceBefore=10, spaceAfter=6)
    h2 = ParagraphStyle("MDH2", parent=heading_style, fontSize=12, spaceBefore=8, spaceAfter=4)
    h3 = ParagraphStyle("MDH3", parent=heading_style, fontSize=10.5, spaceBefore=6, spaceAfter=2)
    blockquote_style = ParagraphStyle("MDBQ", parent=normal_text, fontName="Helvetica-Oblique", leftIndent=12, spaceAfter=6)
    
    for line in lines:
        stripped = line.strip()
        if not stripped:
            flowables.append(Spacer(1, 6))
            continue
            
        if stripped.startswith("# "):
            flowables.append(Paragraph(parse_md_inline_tags(stripped[2:]), h1))
        elif stripped.startswith("## "):
            flowables.append(Paragraph(parse_md_inline_tags(stripped[3:]), h2))
        elif stripped.startswith("### "):
            flowables.append(Paragraph(parse_md_inline_tags(stripped[4:]), h3))
        elif stripped.startswith("> "):
            content = parse_md_inline_tags(stripped[2:])
            flowables.append(Paragraph(content, blockquote_style))
        elif stripped.startswith("- ") or stripped.startswith("* "):
            content = parse_md_inline_tags(stripped[2:])
            flowables.append(Paragraph(f"&bull; {content}", normal_text))
        elif re.match(r"^\d+\.\s", stripped):
            match = re.match(r"^(\d+)\.\s(.*)", stripped)
            num = match.group(1)
            content = parse_md_inline_tags(match.group(2))
            flowables.append(Paragraph(f"{num}. {content}", normal_text))
        else:
            content = parse_md_inline_tags(stripped)
            flowables.append(Paragraph(content, normal_text))
            
    return flowables


def _generate_alert_pdf(alert: Alert, investigation: Investigation | None) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    import html
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    primary_color = colors.HexColor("#0f172a")
    secondary_color = colors.HexColor("#1e3a5f")
    text_color = colors.HexColor("#334155")
    
    title_style = ParagraphStyle(
        "PDFTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        textColor=primary_color,
        alignment=0,
        spaceAfter=15
    )
    
    section_heading = ParagraphStyle(
        "PDFSectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=secondary_color,
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    normal_text = ParagraphStyle(
        "PDFNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=text_color,
        leading=14,
        spaceAfter=6
    )
    
    label_style = ParagraphStyle(
        "PDFLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=colors.HexColor("#1e293b")
    )
    
    value_style = ParagraphStyle(
        "PDFValue",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#475569")
    )
    
    story = []
    
    story.append(Paragraph(f"SOC Investigation Report — {alert.alert_id}", title_style))
    story.append(Paragraph(f"Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", value_style))
    story.append(Spacer(1, 10))
    
    meta_data = [
        [
            Paragraph("Alert ID", label_style), Paragraph(alert.alert_id, value_style),
            Paragraph("Status", label_style), Paragraph(alert.status.upper(), value_style)
        ],
        [
            Paragraph("Severity", label_style), Paragraph(alert.severity, value_style),
            Paragraph("Category", label_style), Paragraph(alert.category, value_style)
        ],
        [
            Paragraph("Affected Host", label_style), Paragraph(alert.affected_asset, value_style),
            Paragraph("Affected User", label_style), Paragraph(alert.affected_user or "N/A", value_style)
        ],
        [
            Paragraph("Timestamp", label_style), Paragraph(alert.timestamp or "N/A", value_style),
            Paragraph("Source", label_style), Paragraph(alert.source or "N/A", value_style)
        ]
    ]
    
    meta_table = Table(meta_data, colWidths=[90, 160, 90, 164])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    
    story.append(meta_table)
    story.append(Spacer(1, 15))
    
    if alert.description:
        story.append(Paragraph("Description", section_heading))
        story.append(Paragraph(alert.description, normal_text))
        story.append(Spacer(1, 10))
    
    # Add validation results if available
    if alert.validation_json:
        try:
            import json
            validation_data = json.loads(alert.validation_json)
            answers = validation_data.get("answers", {})
            notes = validation_data.get("notes", "")
            
            if answers:
                story.append(Paragraph("Validation Checklist Results", section_heading))
                yes_answers = [k for k, v in answers.items() if v == "yes"]
                no_answers = [k for k, v in answers.items() if v == "no"]
                
                if yes_answers:
                    story.append(Paragraph("✓ Confirmed Items:", normal_text))
                    for ans in yes_answers:
                        story.append(Paragraph(f"• {ans.replace('_', ' ').title()}", normal_text))
                    story.append(Spacer(1, 6))
                
                if no_answers:
                    story.append(Paragraph("✗ Items Not Confirmed:", normal_text))
                    for ans in no_answers:
                        story.append(Paragraph(f"• {ans.replace('_', ' ').title()}", normal_text))
                    story.append(Spacer(1, 6))
                
                if notes:
                    story.append(Paragraph("Analyst Notes", normal_text))
                    story.append(Paragraph(notes, normal_text))
                    story.append(Spacer(1, 10))
        except Exception:
            pass
        
    if alert.process_tree:
        story.append(Paragraph("Process Tree Execution Lineage", section_heading))
        lines = alert.process_tree.strip().splitlines()
        for ln in lines:
            code_style = ParagraphStyle(
                "PDFCode",
                parent=normal_text,
                fontName="Courier",
                fontSize=8.5,
                textColor=colors.HexColor("#0f172a"),
                leftIndent=15,
                spaceAfter=3
            )
            story.append(Paragraph(html.escape(ln), code_style))
        story.append(Spacer(1, 10))
        
    story.append(Paragraph("Triage & Investigation Narrative", section_heading))
    if investigation and investigation.report_markdown:
        md_flowables = markdown_to_flowables(investigation.report_markdown, styles, normal_text, section_heading)
        story.extend(md_flowables)
    else:
        story.append(Paragraph("No investigation report has been completed for this alert yet.", normal_text))
        
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


@router.get("/{alert_pk}/export/pdf")
async def export_pdf(alert_pk: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_pk)
    if not alert:
        raise HTTPException(404, "Alert not found")
        
    result = await db.execute(
        select(Investigation)
        .where(Investigation.alert_id == alert_pk)
        .order_by(Investigation.created_at.desc())
    )
    latest_inv = result.scalars().first()
    
    pdf_bytes = _generate_alert_pdf(alert, latest_inv)
    
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report_{alert.alert_id}.pdf"}
    )
