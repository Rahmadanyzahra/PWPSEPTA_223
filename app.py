from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Menyimpan file SQLite di folder yang sama dengan app.py
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Inisialisasi Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"  # Menetapkan tampilan login untuk pengguna yang tidak terautentikasi

# Model Database untuk User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Form untuk Registrasi dan Login
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

# Route untuk Halaman Registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Akun berhasil dibuat!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# Route untuk Halaman Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)  # Menggunakan Flask-Login untuk login pengguna
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login gagal. Periksa username dan password Anda.', 'danger')
    return render_template('login.html', form=form)

# Route untuk Halaman Dashboard (Setelah Login)
@app.route('/dashboard')
@login_required  # Hanya bisa diakses jika pengguna sudah login
def dashboard():
    return render_template('dashboard.html')

# Route untuk Logout
@app.route('/logout')
def logout():
    logout_user()  # Menggunakan Flask-Login untuk logout pengguna
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

# Inisialisasi database dalam konteks aplikasi
def init_db():
    with app.app_context():  # Membungkus db.create_all() dalam konteks aplikasi
        db.create_all()

# Menggunakan Flask-Login untuk memuat pengguna yang sedang login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if __name__ == "__main__":
    init_db()  # Memanggil fungsi untuk membuat database
    app.run(debug=True)
