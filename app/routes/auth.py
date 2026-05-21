import re
import pyotp
import qrcode
import io
import base64
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import create_access_token
from datetime import datetime
import requests as http_requests

from ..models import db, User, Role, AuditLog

auth_bp = Blueprint('auth', __name__)


# ── Password Policy ───────────────────────────────────────────────────────────
def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("At least 8 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("At least one uppercase letter")
    if not re.search(r'[a-z]', password):
        errors.append("At least one lowercase letter")
    if not re.search(r'\d', password):
        errors.append("At least one number")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("At least one special character")
    return errors


def log_action(action, target=None, details=None):
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        target=target,
        ip_address=request.remote_addr,
        details=details
    )
    db.session.add(log)
    db.session.commit()


# ── Register ──────────────────────────────────────────────────────────────────
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        # Validations
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('auth/register.html')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')

        policy_errors = validate_password(password)
        if policy_errors:
            flash('Password must have: ' + ', '.join(policy_errors), 'danger')
            return render_template('auth/register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('auth/register.html')

        # Create user
        user = User(username=username, email=email)
        user.set_password(password)

        # Assign default 'user' role
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.roles.append(user_role)

        # First registered user becomes admin
        if User.query.count() == 0:
            admin_role = Role.query.filter_by(name='admin').first()
            if admin_role:
                user.roles.append(admin_role)

        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')


# ── Login ─────────────────────────────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'danger')
            log_action('failed_login', target=email)
            return render_template('auth/login.html')

        if not user.is_active:
            flash('Your account has been deactivated.', 'danger')
            return render_template('auth/login.html')

        # 2FA check
        if user.is_2fa_enabled:
            session['2fa_user_id'] = user.id
            return redirect(url_for('auth.verify_2fa'))

        # Login success
        login_user(user, remember=True)
        user.last_login = datetime.utcnow()
        db.session.commit()
        log_action('login', target=user.email)

        next_page = request.args.get('next')
        return redirect(next_page or url_for('dashboard.index'))

    return render_template('auth/login.html')


# ── 2FA Verify ────────────────────────────────────────────────────────────────
@auth_bp.route('/2fa/verify', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        totp  = pyotp.TOTP(user.totp_secret)

        if totp.verify(token):
            session.pop('2fa_user_id', None)
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()
            log_action('login_2fa', target=user.email)
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')

    return render_template('auth/2fa_verify.html')


# ── 2FA Setup ─────────────────────────────────────────────────────────────────
@auth_bp.route('/2fa/setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        secret = session.get('totp_secret')

        if not secret:
            flash('Session expired. Please try again.', 'danger')
            return redirect(url_for('auth.setup_2fa'))

        totp = pyotp.TOTP(secret)
        if totp.verify(token):
            current_user.totp_secret   = secret
            current_user.is_2fa_enabled = True
            db.session.commit()
            session.pop('totp_secret', None)
            flash('2FA enabled successfully!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid code. Please scan QR again.', 'danger')

    # Generate new secret & QR
    secret = pyotp.random_base32()
    session['totp_secret'] = secret
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=current_user.email, issuer_name='SecureVault')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template('auth/2fa_setup.html', qr_code=qr_b64, secret=secret)


# ── 2FA Disable ───────────────────────────────────────────────────────────────
@auth_bp.route('/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    current_user.is_2fa_enabled = False
    current_user.totp_secret    = None
    db.session.commit()
    flash('2FA has been disabled.', 'warning')
    return redirect(url_for('dashboard.index'))


# ── Logout ────────────────────────────────────────────────────────────────────
@auth_bp.route('/logout')
@login_required
def logout():
    log_action('logout', target=current_user.email)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ── JWT Token (API) ───────────────────────────────────────────────────────────
@auth_bp.route('/token', methods=['POST'])
def get_token():
    email    = request.json.get('email')
    password = request.json.get('password')
    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': token, 'user': user.username})


# ── OAuth GitHub ──────────────────────────────────────────────────────────────
@auth_bp.route('/oauth/github')
def oauth_github():
    from flask import current_app
    client_id = current_app.config.get('GITHUB_CLIENT_ID')
    redirect_uri = url_for('auth.oauth_github_callback', _external=True)
    return redirect(f'https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=user:email')


@auth_bp.route('/oauth/github/callback')
def oauth_github_callback():
    from flask import current_app
    code = request.args.get('code')
    if not code:
        flash('OAuth failed.', 'danger')
        return redirect(url_for('auth.login'))

    # Exchange code for token
    resp = http_requests.post('https://github.com/login/oauth/access_token', json={
        'client_id':     current_app.config['GITHUB_CLIENT_ID'],
        'client_secret': current_app.config['GITHUB_CLIENT_SECRET'],
        'code':          code,
    }, headers={'Accept': 'application/json'})

    access_token = resp.json().get('access_token')
    if not access_token:
        flash('GitHub OAuth failed.', 'danger')
        return redirect(url_for('auth.login'))

    # Get user info
    user_resp  = http_requests.get('https://api.github.com/user',   headers={'Authorization': f'token {access_token}'})
    email_resp = http_requests.get('https://api.github.com/user/emails', headers={'Authorization': f'token {access_token}'})

    gh_user    = user_resp.json()
    emails     = email_resp.json()
    primary_email = next((e['email'] for e in emails if e.get('primary')), None) or gh_user.get('email')

    return _oauth_login_or_register('github', str(gh_user['id']), gh_user.get('login'), primary_email)


# ── OAuth Google ──────────────────────────────────────────────────────────────
@auth_bp.route('/oauth/google')
def oauth_google():
    from flask import current_app

    client_id = current_app.config['GOOGLE_CLIENT_ID']
    redirect_uri = url_for('auth.oauth_google_callback', _external=True)

    print("CLIENT ID =", client_id)
    print("REDIRECT URI =", redirect_uri)

    scope = 'openid email profile'

    google_url = (
        f'https://accounts.google.com/o/oauth2/v2/auth'
        f'?client_id={client_id}'
        f'&redirect_uri={redirect_uri}'
        f'&response_type=code'
        f'&scope={scope}'
    )

    print("FULL URL =", google_url)

    return redirect(google_url)
@auth_bp.route('/oauth/google/callback')
def oauth_google_callback():
    from flask import current_app
    code = request.args.get('code')
    if not code:
        flash('OAuth failed.', 'danger')
        return redirect(url_for('auth.login'))

    redirect_uri = url_for('auth.oauth_google_callback', _external=True)
    token_resp = http_requests.post('https://oauth2.googleapis.com/token', data={
        'code':          code,
        'client_id':     current_app.config['GOOGLE_CLIENT_ID'],
        'client_secret': current_app.config['GOOGLE_CLIENT_SECRET'],
        'redirect_uri':  redirect_uri,
        'grant_type':    'authorization_code',
    })
    token_data   = token_resp.json()
    access_token = token_data.get('access_token')

    info = http_requests.get('https://www.googleapis.com/oauth2/v2/userinfo',
                              headers={'Authorization': f'Bearer {access_token}'}).json()

    return _oauth_login_or_register('google', str(info['id']), info.get('name', '').replace(' ', '_'), info.get('email'))


def _oauth_login_or_register(provider, oauth_id, username, email):
    user = User.query.filter_by(oauth_provider=provider, oauth_id=oauth_id).first()

    if not user and email:
        user = User.query.filter_by(email=email).first()

    if not user:
        # Register new OAuth user
        base = username or email.split('@')[0]
        uname = base
        counter = 1
        while User.query.filter_by(username=uname).first():
            uname = f'{base}{counter}'
            counter += 1

        user = User(username=uname, email=email, oauth_provider=provider, oauth_id=oauth_id)
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.roles.append(user_role)
        db.session.add(user)
        db.session.commit()

    user.oauth_provider = provider
    user.oauth_id       = oauth_id
    user.last_login     = datetime.utcnow()
    db.session.commit()

    login_user(user, remember=True)
    flash(f'Logged in with {provider.title()}!', 'success')
    return redirect(url_for('dashboard.index'))
