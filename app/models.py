from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin

db = SQLAlchemy()
bcrypt = Bcrypt()

# ──────────────────────────────────────────
# Association Table: User ↔ Role
# ──────────────────────────────────────────
user_roles = db.Table(
    'user_roles',
    db.Column('user_id',  db.Integer, db.ForeignKey('users.id'),  primary_key=True),
    db.Column('role_id',  db.Integer, db.ForeignKey('roles.id'),  primary_key=True)
)


# ──────────────────────────────────────────
# Role Model
# ──────────────────────────────────────────
class Role(db.Model):
    __tablename__ = 'roles'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(50), unique=True, nullable=False)   # admin / manager / user
    description = db.Column(db.String(200))

    def __repr__(self):
        return f'<Role {self.name}>'


# ──────────────────────────────────────────
# User Model
# ──────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id               = db.Column(db.Integer, primary_key=True)
    username         = db.Column(db.String(80),  unique=True, nullable=False)
    email            = db.Column(db.String(120), unique=True, nullable=False)
    password_hash    = db.Column(db.String(255))                      # bcrypt hash
    oauth_provider   = db.Column(db.String(50))                       # 'github' / 'google' / None
    oauth_id         = db.Column(db.String(200))                      # provider user id
    is_active        = db.Column(db.Boolean, default=True)
    is_2fa_enabled   = db.Column(db.Boolean, default=False)
    totp_secret      = db.Column(db.String(32))                       # for pyotp
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    last_login       = db.Column(db.DateTime)

    # Relationships
    roles     = db.relationship('Role', secondary=user_roles, backref='users', lazy='dynamic')
    documents = db.relationship('Document', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    # ── Password helpers ──────────────────
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, password)

    # ── Role helpers ──────────────────────
    def has_role(self, role_name):
        return self.roles.filter_by(name=role_name).first() is not None

    def is_admin(self):
        return self.has_role('admin')

    def is_manager(self):
        return self.has_role('manager') or self.has_role('admin')

    def __repr__(self):
        return f'<User {self.username}>'


# ──────────────────────────────────────────
# Document Model
# ──────────────────────────────────────────
class Document(db.Model):
    __tablename__ = 'documents'

    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # File info
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename   = db.Column(db.String(255), nullable=False)   # UUID-based encrypted filename
    file_size         = db.Column(db.Integer)                       # bytes
    file_type         = db.Column(db.String(50))                    # mime type

    # Encryption
    is_encrypted      = db.Column(db.Boolean, default=True)
    iv                = db.Column(db.String(32))                    # AES initialization vector (hex)

    # Integrity & Signature
    sha256_hash       = db.Column(db.String(64))                    # SHA-256 of original file
    digital_signature = db.Column(db.Text)                         # RSA/ECDSA signature (base64)
    is_verified       = db.Column(db.Boolean, default=False)

    # Metadata
    description       = db.Column(db.String(500))
    uploaded_at       = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed     = db.Column(db.DateTime)

    def __repr__(self):
        return f'<Document {self.original_filename}>'


# ──────────────────────────────────────────
# AuditLog Model  (track all actions)
# ──────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'))
    action     = db.Column(db.String(100), nullable=False)  # e.g. 'upload', 'download', 'login'
    target     = db.Column(db.String(200))                  # e.g. filename or user email
    ip_address = db.Column(db.String(45))
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow)
    details    = db.Column(db.Text)

    user = db.relationship('User', backref='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.action} by user {self.user_id}>'
