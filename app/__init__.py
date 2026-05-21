from flask import Flask, app, redirect, url_for
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from .models import db, bcrypt, User, Role

login_manager = LoginManager()
jwt = JWTManager()
mail = Mail()


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)

    # ── Config ────────────────────────────
    from config import Config
    app.config.from_object(Config)

    if config:
        app.config.update(config)
    # ── Extensions ────────────────────────
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Blueprints ────────────────────────
    from .routes.auth import auth_bp
    from .routes.dashboard import dashboard_bp
    from .routes.documents import documents_bp
    from .routes.admin import admin_bp
    from .routes.api import api_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(documents_bp, url_prefix='/documents')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')

    # ── الصفحة الرئيسية → يحولك على صفحة اللوجين ──
    @app.route('/')
    def home():
        return redirect(url_for('auth.login'))

    # ── Create DB & seed roles ─────────────
    with app.app_context():
        db.create_all()
        _seed_roles()

    return app


def _seed_roles():
    """Create default roles if they don't exist."""
    for role_name in ('admin', 'manager', 'user'):
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name))
    db.session.commit()