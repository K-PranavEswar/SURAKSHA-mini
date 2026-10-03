from flask_login import UserMixin
from models import db
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, username: str, email: str, password: str, **kwargs):
        super(User, self).__init__(**kwargs)
        self.username = username
        self.email = email
        self.password = password
        self.created_at = datetime.utcnow()