from datetime import datetime
from app import db
from sqlalchemy_utils import UUIDType
import uuid

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUIDType(binary=False), default=uuid.uuid4, unique=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    pseudo_identity = db.Column(db.String(64), unique=True, nullable=False)
    signing_public_key = db.Column(db.Text, nullable=False)
    exchange_public_key = db.Column(db.Text, nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    sessions = db.relationship('Session', backref='user', lazy=True)
    health_data = db.relationship('HealthData', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.email}>' 