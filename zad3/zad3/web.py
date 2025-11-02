from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

import re
import hashlib
import requests

import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hashed_password = db.Column(db.String(80), unique=False, nullable=False)
    salt = db.Column(db.String(80), unique=False, nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    account_locked_until = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

    def is_account_locked(self):
        if self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return True
        return False

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.account_locked_until = None
        db.session.commit()

    def increment_failed_attempts(self):
        # Reset ak posledný pokus bol pred viac ako 1 hodinou
        if self.last_failed_login:
            time_since_last = datetime.utcnow() - self.last_failed_login
            if time_since_last > timedelta(hours=1):
                self.failed_login_attempts = 0  # Reset počítadla

        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()

        # Zamkni účet po 5 neúspešných pokusoch na 15 minút
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=1)

        db.session.commit()


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 môže byť dlhšia
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)

    @staticmethod
    def get_recent_attempts(ip_address, minutes=1):
        """Získaj počet pokusov z IP za posledných X minút"""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        return LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.timestamp > cutoff,
            LoginAttempt.success == False
        ).count()

    @staticmethod
    def cleanup_old_attempts(days=7):
        """Vyčisti staré záznamy"""
        cutoff = datetime.utcnow() - timedelta(days=days)
        LoginAttempt.query.filter(LoginAttempt.timestamp < cutoff).delete()
        db.session.commit()

def get_client_ip():
    """Získaj IP adresu klienta (aj cez proxy)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


# Funkcia pre výpočet oneskorenia (exponenciálne)
def calculate_delay(failed_attempts):
    """Vypočítaj oneskorenie na základe počtu neúspešných pokusov"""
    if failed_attempts <= 0:
        return 0
    # Exponenciálne oneskorenie: 2^(attempts-1) sekúnd, max 30s
    delay = min(2 ** (failed_attempts - 1), 30)
    return delay

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)


@app.route('/debug/users')
def show_users():
    users = User.query.all()
    return "ID | Username | Hashed_password | Salt | Failed_last_login | Last_failed_login | Account_locked_until<br>" + 180*'-' + "<br>" + "<br>".join([f"{u.id} | {u.username} | {u.hashed_password} | {u.salt} | {u.failed_login_attempts} | {u.last_failed_login} | {u.account_locked_until}" for u in users])


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if request.method == 'GET':
        session_lockout = session.get('session_lockout_until')
        if session_lockout:
            lockout_time = datetime.fromisoformat(session_lockout)
            if datetime.utcnow() < lockout_time:
                remaining_seconds = int((lockout_time - datetime.utcnow()).total_seconds())
                return render_template('login.html', form=form,
                                       locked_until=session_lockout,
                                       remaining_seconds=remaining_seconds)
            else:
                session.pop('session_lockout_until', None)
                session.pop('session_failed_attempts', None)

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        client_ip = get_client_ip()

        # 1. Kontrola IP rate limiting (max 10 pokusov za 15 minút)
        ip_attempts = LoginAttempt.get_recent_attempts(client_ip, minutes=15)
        if ip_attempts >= 10:
            flash('Too many login attempts from your IP address. Please try again later.', 'error')
            return render_template('login.html', form=form)

        # 2. Skontroluj univerzálny session lockout
        session_lockout = session.get('session_lockout_until')
        if session_lockout:
            lockout_time = datetime.fromisoformat(session_lockout)
            if datetime.utcnow() < lockout_time:
                remaining_seconds = int((lockout_time - datetime.utcnow()).total_seconds())
                return render_template('login.html', form=form,
                                       locked_until=session_lockout,
                                       remaining_seconds=remaining_seconds)

        # 3. Vyhľadaj používateľa
        user = User.query.filter_by(username=username).first()

        # 3,5. Vytvorenie salted hashu hesla
        hashed_password = ''
        if user:
            salted_password = (password + user.salt).encode('utf-8')
            hashed_password = hashlib.sha256(salted_password).hexdigest()

        # 4. Overenie hesla
        login_successful = False
        if user and (hashed_password == user.hashed_password):
            login_successful = True

        if login_successful:
            # Úspešné prihlásenie
            if user:
                user.reset_failed_attempts()

            attempt = LoginAttempt(ip_address=client_ip, success=True)
            db.session.add(attempt)
            db.session.commit()

            # Vyčisti session
            session.pop('session_failed_attempts', None)
            session.pop('session_lockout_until', None)

            login_user(user)
            return redirect(url_for('home'))
        else:
            # Neúspešné prihlásenie
            attempt = LoginAttempt(ip_address=client_ip, success=False)
            db.session.add(attempt)
            db.session.commit()

            session_attempts = session.get('session_failed_attempts', 0)
            session_attempts += 1
            session['session_failed_attempts'] = session_attempts

            if user:
                user.increment_failed_attempts()

            if session_attempts >= 5:
                # Zamkni session na 15 minút
                lockout_until = datetime.utcnow() + timedelta(minutes=15)
                session['session_lockout_until'] = lockout_until.isoformat()

                remaining_seconds = 15 * 60
                return render_template('login.html', form=form,
                                       locked_until=lockout_until.isoformat(),
                                       remaining_seconds=remaining_seconds)
            else:
                remaining_attempts = 5 - session_attempts
                flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'error')

    return render_template('login.html', form=form)


def is_password_strong(password):
    # Heslo ma aspon 15 znakov
    if len(password) >= 15:
        return True, "OK"

    # heslo ma aspon 8 znakov a dodržiava LUDS composition policy
    if len(password) >= 8:
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(re.match(r'\W', c) for c in password)

        if has_lower and has_upper and has_digit and has_symbol:
            return True, "OK"

    return False, "Password must be at least 15 characters OR at least 8 characters with upper, lower, digit, and symbol."


def is_password_compromised(password):
    # konvertovanie hesiel zo zahashovaneho formatu  do uppercase utf8 bajtov
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Kvoli bezpecnosti - sluzba nevidi nase cele heslo
    prefix, suffix = sha1[:5], sha1[5:]
    # Pouzita Have I Been Pwned API
    url = f'https://api.pwnedpasswords.com/range/{prefix}'

    try:
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            return False  # neda sa teraz zistit, heslo sa bude povazovat za nekompromitovane
        # api vracia hash suffixy spolu s poctom v data breach-och
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            # porovnava suffix kontrolovaneho hesla s kazdym suffixom vratenych z api
            if h == suffix:
                return True  # kompromitovane heslo
    except Exception:
        return False
    return False


@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Skontroluj, či užívateľ s týmto username už existuje
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html', form=form)

        # Skontroluj silu hesla
        ok, msg = is_password_strong(password)
        if not ok:
            flash(msg, 'error')
            return render_template('register.html', form=form)

        # Skontroluj, či heslo nebolo kompromitované (Have I Been Pwned)
        if is_password_compromised(password):
            flash('This password was found in data breaches. Please choose another.', 'error')
            return render_template('register.html', form=form)

        # Vygenerovanie saltu a nasledny hash salted hesla
        salt = os.urandom(16)
        salted_password = (password + salt.hex()).encode('utf-8')
        hashed_password = hashlib.sha256(salted_password).hexdigest()

        # Vytvor účet
        new_user = User(username=username, hashed_password=hashed_password, salt=salt.hex())
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.before_request
def periodic_cleanup():
    """Cleanup starých login attempts každých ~100 requestov"""
    import random
    if random.randint(1, 1000) == 1:
        try:
            LoginAttempt.cleanup_old_attempts(days=7)
        except:
            pass  # Ignoruj chyby v cleanup


if __name__ == '__main__':
    app.run(port=1337)