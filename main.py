from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config.update()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    # def validate_email(self, input_email):
    #     existing_username = db.session.execute(db.Select(User).where(User.email == input_email)).scalar()
    #     if existing_username:
    #         return render_template("existing_email.html")


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        password = request.form.get("password")
        entered_email = request.form.get("email")
        user_exist = db.session.execute(db.Select(User).where(User.email == entered_email)).scalar()
        if user_exist:
            flash("you already signed up! ")
            return redirect(url_for("login"))
        new_user = User(
            email=request.form.get("email"),
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=10),
            name=request.form.get("name")
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash("you are logged in!", "info")

        return redirect(url_for('secrets'))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        result = db.session.execute(db.Select(User).where(User.email == email))
        user = result.scalar()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                flash("You are successfully logged in!", "info")
                return redirect(url_for('secrets'))
            else:
                flash("sorry! wrong Password!")
                return redirect(url_for("login"))
        else:
            flash("sorry! wrong Email. Try Again!")
            return redirect(url_for("login"))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html",logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    flash('You are logged out successfully!')
    return redirect(url_for("home"))


@app.route('/download', methods=["GET", "POST"])
@login_required
def download():
    return send_from_directory("static", path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)

