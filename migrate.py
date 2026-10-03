from app import app
from models import db
from models.shareable_report_model import ShareableReport

with app.app_context():
    db.create_all()
    print("Database migration completed. 'shareable_reports' table should now exist.")
