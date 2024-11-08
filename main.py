# import libraries
from fileinput import filename

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from jedi.plugins import flask
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

# create an instance of flask
app = Flask(__name__)

# create an instance of login manager
login_manager = LoginManager()

# configure it
login_manager.init_app(app)

# secret key
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


# config the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# create an instance of SQLAlchemy
db = SQLAlchemy(model_class=Base)

# initialize the SQLAlchemy
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)


# config the creation of the table
with app.app_context():
    db.create_all()


# create user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        encrypted_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        user = User.query.filter_by(email=email).first()
        if user:
            flash('You have already signed up with that email, log in instead')
            return render_template('login.html')
        else:
            new_user = User(name=name, email=email, password=encrypted_password)
            db.session.add(new_user)
            db.session.commit()
            return render_template('secrets.html', user=new_user)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    # check the request method
    if request.method == "POST":
        # grab the email-password from the login form
        email = request.form['email']
        password = request.form['password']
        # check if these credentials exist to the database
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash('Invalid email or password', 'error')
    return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    pass


@app.route('/download/<path:name>', methods=['GET', 'POST'])
def download(name):
    return send_from_directory('static/files', name)


if __name__ == "__main__":
    app.run(debug=True)
