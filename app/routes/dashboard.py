from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ..models import Document, AuditLog

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    doc_count = Document.query.filter_by(user_id=current_user.id).count()
    recent    = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).limit(5).all()
    logs      = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard/index.html', doc_count=doc_count, recent=recent, logs=logs)
