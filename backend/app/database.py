from collections.abc import AsyncGenerator
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import select

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
engine = create_async_engine(settings.database_url, echo=False)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


async def init_db() -> None:
    from app import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def seed_test_data() -> None:
    """Create admin user and test alerts for initial setup"""
    from app.models import User, Alert
    from app.api.auth import hash_password
    
    async with SessionLocal() as session:
        # Create admin user if doesn't exist
        admin = await session.scalar(select(User).where(User.username == "admin"))
        if not admin:
            admin = User(
                id=str(uuid.uuid4()),
                username="admin",
                password_hash=hash_password("admin"),
                mfa_enabled=False
            )
            session.add(admin)
            await session.flush()
        
        # Create test alerts if none exist
        existing_alerts = await session.scalars(select(Alert))
        if len(list(existing_alerts)) == 0:
            test_alerts = [
                {
                    "alert_id": "ALT-001",
                    "title": "Suspicious PowerShell Execution",
                    "severity": "High",
                    "category": "Malware / Endpoint",
                    "source": "EDR Agent",
                    "affected_asset": "WORKSTATION-42",
                    "affected_user": "john.smith@acme.com",
                    "owner_team": "IT Operations",
                    "owner_email": "it-ops@acme.com",
                    "description": "PowerShell process spawned with obfuscated command line arguments detected on WORKSTATION-42. Process tree shows parent process from Microsoft Office application.",
                    "process_tree": "explorer.exe\n  └─ winword.exe\n      └─ powershell.exe -enc VwByAGsAZQByACAALQBXAGkAbgBkAG8AdwBTAHQAeQBsAGUAIABIaWRkZW4=",
                    "ioc_list": "powershell.exe hash:d41d8cd98f00b204e9800998ecf8427e\nC:\\Users\\john.smith\\AppData\\Local\\Temp\\suspicious.exe",
                    "status": "pending",
                    "tags": "office, obfuscated-command, edr-alert"
                },
                {
                    "alert_id": "ALT-002",
                    "title": "Unauthorized AWS IAM Role Creation",
                    "severity": "Critical",
                    "category": "Cloud / IAM",
                    "source": "CloudTrail",
                    "affected_asset": "arn:aws:iam::123456789012:role/UnauthorizedRole",
                    "affected_user": "svc-automation@acme.com",
                    "owner_team": "Cloud Security",
                    "owner_email": "cloud-sec@acme.com",
                    "description": "New IAM role created with overly permissive trust relationship. Role allows assumption from any principal in the AWS account.",
                    "raw_log": '{"eventName":"CreateRole","principalId":"AIDACKCEVSQ6C2EXAMPLE","resources":[{"ARN":"arn:aws:iam::123456789012:role/UnauthorizedRole"}],"sourceIPAddress":"10.0.1.100"}',
                    "status": "pending",
                    "tags": "iam, privilege-escalation, cloud"
                },
                {
                    "alert_id": "ALT-003",
                    "title": "Phishing Email with Malicious Attachment",
                    "severity": "High",
                    "category": "Phishing / Email",
                    "source": "Email Security Gateway",
                    "affected_asset": "mail.acme.com",
                    "affected_user": "sarah.jones@acme.com",
                    "owner_team": "Security Awareness",
                    "owner_email": "security@acme.com",
                    "description": "Email spoofing Microsoft Office support address contains .exe attachment. User clicked link but did not download attachment.",
                    "ioc_list": "sender:support@microsof.com\nattachment:invoice-2024.exe\nURL:http://malicious-domain.ru/phish",
                    "status": "pending",
                    "tags": "phishing, trojan, email-security"
                },
                {
                    "alert_id": "ALT-004",
                    "title": "Lateral Movement Detected - SMB Share Access",
                    "severity": "Medium",
                    "category": "Lateral Movement",
                    "source": "Network IDS",
                    "affected_asset": "FILE-SERVER-01",
                    "affected_user": "svc-backup@acme.com",
                    "owner_team": "IT Operations",
                    "owner_email": "it-ops@acme.com",
                    "description": "Service account attempting to access hidden administrative shares on file server from unusual network segment.",
                    "raw_log": 'EventID: 4688\nParentImage: C:\\Windows\\System32\\svchost.exe\nImage: C:\\Windows\\System32\\net.exe\nCommandLine: net use \\\\FILE-SERVER-01\\c$ password /user:svc-backup',
                    "status": "pending",
                    "tags": "lateral-movement, svc-account, smb"
                },
                {
                    "alert_id": "ALT-005",
                    "title": "Data Exfiltration - Large Volume Download",
                    "severity": "Critical",
                    "category": "Data Exfiltration",
                    "source": "DLP Engine",
                    "affected_asset": "ANALYST-PC-15",
                    "affected_user": "mike.chen@acme.com",
                    "owner_team": "Compliance",
                    "owner_email": "compliance@acme.com",
                    "description": "Unusual large file transfer detected from analyst workstation to personal cloud storage (OneDrive) containing sensitive PII database export.",
                    "raw_log": "Source: 192.168.1.150:52341\nDestination: 1.44.89.45:443 (OneDrive CDN)\nBytes: 2.3GB\nFile: customer_pii_2024_export.sql.gz",
                    "status": "pending",
                    "tags": "data-exfiltration, cloud-storage, pii"
                }
            ]
            
            for alert_data in test_alerts:
                alert = Alert(
                    id=str(uuid.uuid4()),
                    alert_id=alert_data["alert_id"],
                    title=alert_data["title"],
                    severity=alert_data["severity"],
                    category=alert_data["category"],
                    source=alert_data.get("source"),
                    affected_asset=alert_data["affected_asset"],
                    affected_user=alert_data.get("affected_user"),
                    owner_team=alert_data.get("owner_team"),
                    owner_email=alert_data.get("owner_email"),
                    description=alert_data.get("description"),
                    ioc_list=alert_data.get("ioc_list"),
                    raw_log=alert_data.get("raw_log"),
                    process_tree=alert_data.get("process_tree"),
                    status=alert_data.get("status", "pending"),
                    tags=alert_data.get("tags"),
                    created_at=datetime.now(timezone.utc)
                )
                session.add(alert)
        
        await session.commit()
