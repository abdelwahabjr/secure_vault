import os
import uuid
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app, jsonify
from flask_login import login_required, current_user
import io

from ..models import db, Document, AuditLog
from ..utils.crypto import encrypt_file, decrypt_file, compute_sha256, sign_hash, verify_signature

documents_bp = Blueprint('documents', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx', 'xlsx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def log_action(action, target=None, details=None):
    log = AuditLog(
        user_id=current_user.id,
        action=action,
        target=target,
        ip_address=request.remote_addr,
        details=details
    )
    db.session.add(log)
    db.session.commit()


# ── Upload ────────────────────────────────────────────────────────────────────
@documents_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)

        file = request.files['file']
        description = request.form.get('description', '')

        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash(f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', 'danger')
            return redirect(request.url)

        file_bytes = file.read()

        # Size check (16 MB)
        if len(file_bytes) > 16 * 1024 * 1024:
            flash('File too large. Maximum size is 16MB.', 'danger')
            return redirect(request.url)

        # SHA-256 hash of original
        file_hash = compute_sha256(file_bytes)

        # Digital signature
        signature = sign_hash(file_hash, current_user.id)

        # AES-256 encryption
        enc_key = current_app.config['ENCRYPTION_KEY']
        encrypted_bytes, iv_hex = encrypt_file(file_bytes, enc_key)

        # Save encrypted file
        stored_name = f"{uuid.uuid4().hex}.enc"
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, stored_name)

        with open(file_path, 'wb') as f:
            f.write(encrypted_bytes)

        # Save metadata to DB
        doc = Document(
            user_id=current_user.id,
            original_filename=file.filename,
            stored_filename=stored_name,
            file_size=len(file_bytes),
            file_type=file.content_type,
            is_encrypted=True,
            iv=iv_hex,
            sha256_hash=file_hash,
            digital_signature=signature,
            description=description
        )
        db.session.add(doc)
        db.session.commit()

        log_action('upload', target=file.filename, details=f'hash={file_hash[:16]}...')
        flash('Document uploaded and encrypted successfully!', 'success')
        return redirect(url_for('documents.list_documents'))

    return render_template('documents/upload.html')


# ── List ──────────────────────────────────────────────────────────────────────
@documents_bp.route('/')
@login_required
def list_documents():
    if current_user.is_admin():
        docs = Document.query.order_by(Document.uploaded_at.desc()).all()
    else:
        docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
    return render_template('documents/list.html', documents=docs)


# ── Download ──────────────────────────────────────────────────────────────────
@documents_bp.route('/download/<int:doc_id>')
@login_required
def download(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != current_user.id and not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('documents.list_documents'))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.stored_filename)
    if not os.path.exists(file_path):
        flash('File not found on server.', 'danger')
        return redirect(url_for('documents.list_documents'))

    with open(file_path, 'rb') as f:
        encrypted_bytes = f.read()

    enc_key = current_app.config['ENCRYPTION_KEY']
    file_bytes = decrypt_file(encrypted_bytes, doc.iv, enc_key)

    doc.last_accessed = datetime.utcnow()
    db.session.commit()

    log_action('download', target=doc.original_filename)
    return send_file(
        io.BytesIO(file_bytes),
        download_name=doc.original_filename,
        as_attachment=True,
        mimetype=doc.file_type or 'application/octet-stream'
    )


# ── Delete ────────────────────────────────────────────────────────────────────
@documents_bp.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != current_user.id and not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('documents.list_documents'))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.stored_filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    log_action('delete', target=doc.original_filename)
    db.session.delete(doc)
    db.session.commit()

    flash('Document deleted successfully.', 'success')
    return redirect(url_for('documents.list_documents'))


# ── Verify Integrity ──────────────────────────────────────────────────────────
@documents_bp.route('/verify/<int:doc_id>')
@login_required
def verify(doc_id):
    doc = Document.query.get_or_404(doc_id)

    if doc.user_id != current_user.id and not current_user.is_manager():
        flash('Access denied.', 'danger')
        return redirect(url_for('documents.list_documents'))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.stored_filename)
    if not os.path.exists(file_path):
        flash('File not found on server.', 'danger')
        return redirect(url_for('documents.list_documents'))

    # Decrypt and recompute hash
    with open(file_path, 'rb') as f:
        encrypted_bytes = f.read()

    enc_key    = current_app.config['ENCRYPTION_KEY']
    file_bytes = decrypt_file(encrypted_bytes, doc.iv, enc_key)
    current_hash = compute_sha256(file_bytes)

    hash_match = current_hash == doc.sha256_hash
    sig_valid  = verify_signature(doc.sha256_hash, doc.digital_signature, doc.user_id)

    doc.is_verified = hash_match and sig_valid
    db.session.commit()

    log_action('verify', target=doc.original_filename,
               details=f'hash_match={hash_match}, sig_valid={sig_valid}')

    return render_template('documents/verify.html', doc=doc,
                           hash_match=hash_match, sig_valid=sig_valid,
                           current_hash=current_hash)


# ── Metadata ──────────────────────────────────────────────────────────────────
@documents_bp.route('/metadata/<int:doc_id>')
@login_required
def metadata(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.user_id != current_user.id and not current_user.is_admin():
        flash('Access denied.', 'danger')
        return redirect(url_for('documents.list_documents'))
    return render_template('documents/metadata.html', doc=doc)
