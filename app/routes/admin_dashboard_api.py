from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity
from functools import wraps
from datetime import datetime

from ..models import db, User, Role, Document, AuditLog

# ─────────────────────────────────────────────────────────────────
# Dashboard Blueprint
# ─────────────────────────────────────────────────────────────────
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@login_required
def index():
    doc_count  = Document.query.filter_by(user_id=current_user.id).count()
    recent     = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).limit(5).all()
    logs       = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard/index.html',
                           doc_count=doc_count, recent=recent, logs=logs)


# ─────────────────────────────────────────────────────────────────
# Admin Blueprint
# ─────────────────────────────────────────────────────────────────
admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/')
@login_required
@admin_required
def index():
    users      = User.query.all()
    docs       = Document.query.order_by(Document.uploaded_at.desc()).all()
    logs       = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    roles      = Role.query.all()
    return render_template('admin/index.html',
                           users=users, docs=docs, logs=logs, roles=roles)


@admin_bp.route('/users')
@login_required
@admin_required
def users():
    all_users = User.query.all()
    all_roles = Role.query.all()
    return render_template('admin/users.html', users=all_users, roles=all_roles)


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't deactivate yourself.", 'danger')
        return redirect(url_for('admin.users'))
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    user      = User.query.get_or_404(user_id)
    role_name = request.form.get('role')
    role      = Role.query.filter_by(name=role_name).first()

    if not role:
        flash('Role not found.', 'danger')
        return redirect(url_for('admin.users'))

    # Clear existing roles and assign new one
    for r in list(user.roles):
        user.roles.remove(r)
    user.roles.append(role)
    db.session.commit()

    flash(f'{user.username} is now a {role_name}.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't delete yourself.", 'danger')
        return redirect(url_for('admin.users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted.', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin/logs.html', logs=all_logs)


# ─────────────────────────────────────────────────────────────────
# API Blueprint (JWT Protected)
# ─────────────────────────────────────────────────────────────────
api_bp = Blueprint('api', __name__)

@api_bp.route('/me')
@jwt_required()
def api_me():
    user_id = get_jwt_identity()
    user    = User.query.get(int(user_id))
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id':       user.id,
        'username': user.username,
        'email':    user.email,
        'roles':    [r.name for r in user.roles],
        '2fa':      user.is_2fa_enabled,
    })


@api_bp.route('/documents')
@jwt_required()
def api_documents():
    user_id = int(get_jwt_identity())
    user    = User.query.get(user_id)
    if user.is_admin():
        docs = Document.query.all()
    else:
        docs = Document.query.filter_by(user_id=user_id).all()

    return jsonify([{
        'id':                d.id,
        'filename':          d.original_filename,
        'size':              d.file_size,
        'type':              d.file_type,
        'sha256':            d.sha256_hash,
        'encrypted':         d.is_encrypted,
        'verified':          d.is_verified,
        'uploaded_at':       d.uploaded_at.isoformat() if d.uploaded_at else None,
    } for d in docs])


@api_bp.route('/documents/<int:doc_id>/verify')
@jwt_required()
def api_verify(doc_id):
    user_id = int(get_jwt_identity())
    doc     = Document.query.get_or_404(doc_id)

    if doc.user_id != user_id:
        user = User.query.get(user_id)
        if not user.is_admin():
            return jsonify({'error': 'Access denied'}), 403

    return jsonify({
        'document_id':    doc.id,
        'filename':       doc.original_filename,
        'sha256':         doc.sha256_hash,
        'signature':      doc.digital_signature[:32] + '...' if doc.digital_signature else None,
        'is_verified':    doc.is_verified,
    })
