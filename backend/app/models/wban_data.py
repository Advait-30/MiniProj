from datetime import datetime
from app import db
import uuid

class WBANData(db.Model):
    __tablename__ = 'wban_data'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_id = db.Column(db.String(64), nullable=False)  # Sensor/device identifier
    data_type = db.Column(db.String(32), nullable=False)  # e.g., 'heart_rate', 'temperature'
    encrypted_data = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.String(24), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    session_id = db.Column(db.String(64), nullable=False)  # For unlinkability
    
    # Metadata for anonymous analytics
    data_category = db.Column(db.String(32))  # General category without identifying info
    anonymized_location = db.Column(db.String(32))  # General area, not specific location 