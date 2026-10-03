from datetime import datetime
from models import db
import secrets


class ShareableReport(db.Model):
    __tablename__ = "shareable_reports"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    report_token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_hex(16)
    )

    reporter_name = db.Column(
        db.String(255)
    )

    reporter_email = db.Column(
        db.String(255)
    )

    recipient = db.Column(
        db.String(255)
    )

    target = db.Column(
        db.String(255)
    )

    ssl_status = db.Column(
        db.String(50)
    )

    risk_level = db.Column(
        db.String(50)
    )

    subject = db.Column(
        db.String(255)
    )

    email_body = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=True
    )

    def to_dict(self):
        return {
            "report_token": self.report_token,
            "reporter_name": self.reporter_name,
            "reporter_email": self.reporter_email,
            "recipient": self.recipient,
            "target": self.target,
            "ssl_status": self.ssl_status,
            "risk_level": self.risk_level,
            "subject": self.subject,
            "email_body": self.email_body,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "expires_at": (
                self.expires_at.isoformat()
                if self.expires_at
                else None
            )
        }