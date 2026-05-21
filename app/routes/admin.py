from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from functools import wraps
from ..models import db, User, Role, Document, AuditLog

admin_bp = Blueprint('admin', __name__)


# =========================
# Admin Access Protection
# =========================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


# =========================
# Admin Dashboard
# =========================
@admin_bp.route('/')
@login_required
@admin_required
def index():
    users = User.query.all()
    docs = Document.query.order_by(Document.uploaded_at.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    roles = Role.query.all()

    return render_template(
        'admin/index.html',
        users=users,
        docs=docs,
        logs=logs,
        roles=roles
    )


# =========================
# Users Page
# =========================
@admin_bp.route('/users')
@login_required
@admin_required
def users():
    all_users = User.query.all()
    all_roles = Role.query.all()

    return render_template(
        'admin/users.html',
        users=all_users,
        roles=all_roles
    )


# =========================
# Activate / Deactivate User
# =========================
@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)

    # منع تعطيل نفسك
    if user.id == current_user.id:
        flash("You can't deactivate yourself.", 'danger')
        return redirect(url_for('admin.users'))

    user.is_active = not user.is_active
    db.session.commit()

    flash(
        f'User {user.username} {"activated" if user.is_active else "deactivated"}.',
        'success'
    )
    return redirect(url_for('admin.users'))


# =========================
# Change User Role
# =========================
@admin_bp.route('/users/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    user = User.query.get_or_404(user_id)

    new_role_name = request.form.get('role')
    new_role = Role.query.filter_by(name=new_role_name).first()

    if not new_role:
        flash('Role not found.', 'danger')
        return redirect(url_for('admin.users'))

    # منع الأدمن إنه يشيل الأدمن من نفسه
    if user.id == current_user.id and new_role.name != 'admin':
        flash("You can't remove admin role from yourself.", 'danger')
        return redirect(url_for('admin.users'))

    # امسح كل الرولات القديمة (بدل clear)
    for role in user.roles.all():
        user.roles.remove(role)

    # ضيف الرول الجديد
    user.roles.append(new_role)

    db.session.commit()

    flash(
        f'{user.username} role changed to {new_role.name}.',
        'success'
    )
    return redirect(url_for('admin.users'))


# =========================
# Delete User
# =========================
@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # منع حذف نفسك
    if user.id == current_user.id:
        flash("You can't delete yourself.", 'danger')
        return redirect(url_for('admin.users'))

    db.session.delete(user)
    db.session.commit()

    flash(f'User {user.username} deleted.', 'success')
    return redirect(url_for('admin.users'))


# =========================
# Audit Logs
# =========================
@admin_bp.route('/logs')
@login_required
@admin_required
def logs():
    all_logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        'admin/logs.html',
        logs=all_logs
    )