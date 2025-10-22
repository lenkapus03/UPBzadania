from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

import re
import hashlib
import requests
from werkzeug.security import generate_password_hash

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
    password = db.Column(db.String(80), unique=False, nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()
    
    # test_user = User(username='test', password='test')
    # db.session.add(test_user)
    # db.session.commit()


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

@app.route('/login', methods=['GET','POST'])
def login():
    '''
        TODO: doimplementovat
    '''

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username == 'test' and password == 'test':
            login_user(User.query.filter_by(username=username).first())
            return redirect(url_for('home'))

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

        # Vytvor účet
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
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

if __name__ == '__main__':
    app.run(port=1337)