from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
import smtplib
from email.message import EmailMessage

# Initialize the app, database, bcrypt, and login manager
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisnexapoints_secretkey'

# Initialize the database, bcrypt, and login manager
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login page if not logged in

csrf = CSRFProtect(app)


# User model (for authentication)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    course = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(13), nullable=True)


# User Loader function for login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(min=6, max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    phone = StringField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Enter a mobile number"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError('That email is already in use. Please use a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Check your username and/or password.", "danger")
    return render_template('login.html', form=form)

# Dashboard route (requires login)
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    course = request.args.get('course', 'general')  # Default to 'general' if not provided

    if form.validate_on_submit():
        selected_course = request.form.get("course")  # ← gets the hidden input
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            course = selected_course,
            password = hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"Account created successfully for {selected_course.replace('-', ' ').title()}!", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form, course=course)
# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Users route (to list all registered users)
@app.route('/users')
@login_required
def users():
    users_list = User.query.all()
    return render_template('users.html', users=users_list)

# Education route
@app.route('/education')
def education():
    return render_template('education.html')

# Delete user route (admin only or owner)
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f"User {user_to_delete.username} deleted.", "info")
    return redirect(url_for('users'))


# Route for contact form
@app.route("/", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        first = request.form.get("first_name")
        last = request.form.get("last_name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        message = request.form.get("message")

        # Compose email
        msg = EmailMessage()
        msg["Subject"] = "New Contact Form Submission"
        msg["From"] = email
        msg["To"] = "info@nexapoint.co.uk"  # your Zoho inbox

        msg.set_content(f"""
        Name: {first} {last}
        Email: {email}
        Phone: {phone}

        Message:
        {message}
        """)

        try:
            # Connect to Zoho's SMTP
            with smtplib.SMTP_SSL("smtp.zoho.eu", 465) as smtp:
                smtp.login("info@nexapoint.co.uk", os.environ.get("ZOHO_APP_PASSWORD"))
                smtp.send_message(msg)
            flash("Your message has been sent successfully!", "success")
        except Exception as e:
            print("Error sending email:", e)
            flash("There was an error sending your message. Please try again later.", "danger")

        return redirect("/")

    return render_template("form.html")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create all the tables in the database
    app.run(debug=True)
