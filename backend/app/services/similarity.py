import json
import re
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Alert, AlertMatch


def _tokenize(text: str) -> set[str]:
    """Split text into lowercase alphanumeric tokens for similarity comparison."""
    if not text:
        return set()
    # Replace non-alphanumeric with spaces and split
    words = re.findall(r'[a-zA-Z0-9]+', text.lower())
    # Exclude very common words if necessary, but for SOC titles/commands, keeping them is usually fine
    return set(words)


def _jaccard_similarity(set_a: set[str], set_b: set[str]) -> float:
    """Calculate the Jaccard similarity coefficient between two token sets."""
    if not set_a and not set_b:
        return 1.0  # Both empty
    if not set_a or not set_b:
        return 0.0
    return len(set_a.intersection(set_b)) / len(set_a.union(set_b))


def calculate_similarity(alert_a: Alert, alert_b: Alert) -> tuple[int, dict]:
    """
    Calculate similarity score (0 to 100) between two alerts and return details.
    
    Weights:
    - Title: 25% (Jaccard similarity on tokens)
    - Category: 15% (Exact match)
    - Severity: 10% (Exact: 1.0, Adjacent: 0.5, else 0.0)
    - Asset: 20% (Exact match)
    - User: 10% (Exact match)
    - Script/Process Tree: 20% (Jaccard similarity on command line tokens)
    """
    # 1. Title Similarity
    tokens_title_a = _tokenize(alert_a.title)
    tokens_title_b = _tokenize(alert_b.title)
    title_score = _jaccard_similarity(tokens_title_a, tokens_title_b)

    # 2. Category Similarity
    cat_score = 1.0 if alert_a.category == alert_b.category else 0.0

    # 3. Severity Similarity
    sev_a = alert_a.severity.lower() if alert_a.severity else ""
    sev_b = alert_b.severity.lower() if alert_b.severity else ""
    if sev_a == sev_b:
        sev_score = 1.0
    elif (sev_a in ("critical", "high") and sev_b in ("critical", "high")) or \
         (sev_a in ("medium", "low") and sev_b in ("medium", "low")):
        sev_score = 0.5
    else:
        sev_score = 0.0

    # 4. Asset Similarity
    asset_a = (alert_a.affected_asset or "").strip().lower()
    asset_b = (alert_b.affected_asset or "").strip().lower()
    asset_score = 1.0 if asset_a == asset_b and asset_a else 0.0

    # 5. User Similarity
    user_a = (alert_a.affected_user or "").strip().lower()
    user_b = (alert_b.affected_user or "").strip().lower()
    if not user_a and not user_b:
        user_score = 1.0
    elif user_a == user_b and user_a:
        user_score = 1.0
    else:
        user_score = 0.0

    # 6. Script / Process Tree Similarity
    proc_a = alert_a.process_tree or ""
    proc_b = alert_b.process_tree or ""
    tokens_proc_a = _tokenize(proc_a)
    tokens_proc_b = _tokenize(proc_b)
    
    # Also integrate timeline logs if process tree is short
    if len(tokens_proc_a) < 5 and alert_a.timeline_logs:
        tokens_proc_a.update(_tokenize(alert_a.timeline_logs))
    if len(tokens_proc_b) < 5 and alert_b.timeline_logs:
        tokens_proc_b.update(_tokenize(alert_b.timeline_logs))

    script_score = _jaccard_similarity(tokens_proc_a, tokens_proc_b)

    # Adjust weights dynamically if process trees are completely empty for both
    has_scripts = bool(proc_a.strip() or proc_b.strip())
    
    weights = {
        "title": 0.25,
        "category": 0.15,
        "severity": 0.10,
        "asset": 0.20,
        "user": 0.10,
        "script": 0.20 if has_scripts else 0.0
    }
    
    total_weight = sum(weights.values())
    
    weighted_score = (
        title_score * weights["title"] +
        cat_score * weights["category"] +
        sev_score * weights["severity"] +
        asset_score * weights["asset"] +
        user_score * weights["user"] +
        script_score * weights["script"]
    ) / total_weight

    score_pct = int(round(weighted_score * 100))

    details = {
        "title_match": int(round(title_score * 100)),
        "category_match": int(round(cat_score * 100)),
        "severity_match": int(round(sev_score * 100)),
        "asset_match": int(round(asset_score * 100)),
        "user_match": int(round(user_score * 100)),
        "script_match": int(round(script_score * 100)),
        "has_scripts": has_scripts
    }

    return score_pct, details


async def find_and_save_matches(db: AsyncSession, new_alert: Alert, threshold: int = 25) -> list[AlertMatch]:
    """Compare a new alert against all existing alerts in the DB and save matches above threshold."""
    # Fetch all alerts except the new one
    result = await db.execute(
        select(Alert).where(Alert.id != new_alert.id)
    )
    existing_alerts = result.scalars().all()
    
    saved_matches = []
    
    # Delete any existing matches for this alert (if re-calculating)
    # Note: normally we clean up first
    delete_q = select(AlertMatch).where(AlertMatch.alert_id == new_alert.id)
    existing_matches = (await db.execute(delete_q)).scalars().all()
    for em in existing_matches:
        await db.delete(em)
    await db.commit()

    for old_alert in existing_alerts:
        score, details = calculate_similarity(new_alert, old_alert)
        if score >= threshold:
            match = AlertMatch(
                alert_id=new_alert.id,
                matched_alert_id=old_alert.id,
                score=score,
                details_json=json.dumps(details)
            )
            db.add(match)
            saved_matches.append(match)
            
    if saved_matches:
        await db.commit()
        
    return saved_matches
