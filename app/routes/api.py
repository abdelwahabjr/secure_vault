from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Document

api_bp = Blueprint('api', __name__)

@api_bp.route('/me')
@jwt_required()
def api_me():
    user = User.query.get(int(get_jwt_identity()))
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'id': user.id, 'username': user.username, 'email': user.email,
                    'roles': [r.name for r in user.roles], '2fa': user.is_2fa_enabled})

@api_bp.route('/documents')
@jwt_required()
def api_documents():
    user = User.query.get(int(get_jwt_identity()))
    docs = Document.query.all() if user.is_admin() else Document.query.filter_by(user_id=user.id).all()
    return jsonify([{'id': d.id, 'filename': d.original_filename, 'size': d.file_size,
                     'sha256': d.sha256_hash, 'verified': d.is_verified} for d in docs])
