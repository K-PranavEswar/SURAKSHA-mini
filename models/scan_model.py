from datetime import datetime
from models import db


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    target = db.Column(
        db.String(255),
        nullable=False
    )

    scan_type = db.Column(
        db.String(100),
        nullable=False
    )

    severity = db.Column(
        db.String(50),
        nullable=False
    )

    status = db.Column(
        db.String(50),
        default="Completed"
    )

    open_ports = db.Column(
        db.Integer,
        default=0
    )

    details = db.Column(
        db.Text,
        nullable=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    user = db.relationship(
        "User",
        backref="scans"
    )

    def __init__(
        self,
        target,
        scan_type,
        severity,
        user_id,
        status="Completed",
        open_ports=0,
        details=None
    ):
        self.target = target
        self.scan_type = scan_type
        self.severity = severity
        self.user_id = user_id
        self.status = status
        self.open_ports = open_ports
        self.details = details