from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Setup the database URI and configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    date_registered = db.Column(db.DateTime, default=db.func.current_timestamp())

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Users route (to list all registered users)
@app.route('/users')
def users():
    users_list = User.query.all()  # Query all users from the database
    return render_template('users.html', users=users_list)

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Create new user instance
        new_user = User(name=name, email=email, password=password)

        # Add user to the database
        db.session.add(new_user)
        db.session.commit()

        # Redirect to home page after successful registration
        return redirect(url_for('home'))

    return render_template('register.html')

# Delete user route
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)  # Find the user by their ID
    if user_to_delete:
        db.session.delete(user_to_delete)  # Delete the user
        db.session.commit()  # Commit the changes to the database
    return redirect(url_for('users'))  # Redirect back to the users list page

if __name__ == '__main__':
    db.create_all()  # Create database tables if they don't exist already
    app.run(debug=True)
