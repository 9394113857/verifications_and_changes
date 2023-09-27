import configparser  # Added to read the configuration file
import re
import sqlite3
from random import randint

from authy.api import AuthyApiClient
from flask import Flask, render_template, request, redirect, url_for, session
from flask_jwt_extended import JWTManager
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash

# Load email and Authy API credentials from the configuration file
config = configparser.ConfigParser()
config.read('config.ini')

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Authy Configuration
authy_api_key = config['authy']['API_KEY']
api = AuthyApiClient(authy_api_key)


# SQLite Configuration
# Function to create the database and table
def create_database():
    # Establish a connection to the database file
    conn = sqlite3.connect('verfications_database.db')
    c = conn.cursor()

    # Create the 'users' table if it doesn't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT,
            password TEXT,
            email TEXT,
            firstname TEXT,
            lastname TEXT,
            phonenumber TEXT,

            email_verified BOOLEAN DEFAULT FALSE,
            phone_verified BOOLEAN DEFAULT FALSE
        )
    ''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()


# Configure email settings for sending OTP
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = config['email']['USERNAME']
app.config['MAIL_PASSWORD'] = config['email']['PASSWORD']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Initialize Flask-Mail
mail = Mail(app)

# Initialize the JWTManager
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)

@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    # Your code for handling GET and POST requests here
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']

        # Establish a connection to your SQLite database file.
        connection = sqlite3.connect("verfications_database.db")
        # Create a cursor using the connection.
        cursor = connection.cursor()
        # Define your SQL query with a placeholder for the username.
        query = "SELECT * FROM accounts WHERE username = ?"
        # Execute the query with the username parameter.
        cursor.execute(query, (username,))
        # Fetch the first row (if any) as a tuple.
        details = cursor.fetchone()

        if details is not None:
            hashed_password = details[2]  # Assuming password is at index 2 in the tuple
            password_match = check_password_hash(hashed_password, password)

            if password_match:
                session['loggedin'] = True
                session['id'] = details[0]  # Assuming ID is at index 0 in the tuple
                session['username'] = details[1]  # Assuming username is at index 1 in the tuple

                if not details[7]:  # Assuming email_verified is at index 7 in the tuple
                    return redirect(url_for('phone_verification'))

                return redirect(url_for('home'))
            else:
                msg = 'Incorrect username/password!'
        else:
            msg = 'Incorrect username/password!'

    return render_template('index.html', title="Login")


@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form \
            and 'firstname' in request.form and 'lastname' in request.form and 'phonenumber' in request.form:
        username = request.form['username']
        password = request.form['password']
        hassedpassword = generate_password_hash(password)
        email = request.form['email']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        phonenumber = request.form['phonenumber']

        # Establish a connection to your SQLite database file.
        connection = sqlite3.connect("verfications_database.db")
        # Create a cursor using the connection.
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))

        account = cursor.fetchone()

        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email or not firstname or not lastname or not phonenumber:
            msg = 'Please fill out the form!'
        else:
            cursor.execute(
                'INSERT INTO accounts(username, password, email, firstname, lastname, phonenumber, phone_verified) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (username, hassedpassword, email, firstname, lastname, phonenumber, False))

            connection.commit()

            session['registered'] = True
            session['username'] = username
            session['phone_number'] = phonenumber

            api.phones.verification_start(phonenumber, country_code='US', via='sms')

            return redirect(url_for('phone_verification'))
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/pythonlogin/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/pythonlogin/home')
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/pythonlogin/profile')
def profile():
    if 'loggedin' in session:
        # Debugging: Print session ID
        print("Session ID:", session['id'])

        # Establish a connection to your SQLite database file.
        connection = sqlite3.connect("verfications_database.db")
        # Create a cursor using the connection.
        cursor = connection.cursor()
        # Define your SQL query with a placeholder for the session ID.
        query = "SELECT * FROM accounts WHERE id = ?"
        # Execute the query with the session ID parameter.
        cursor.execute(query, (session['id'],))
        # Fetch the user details.
        account = cursor.fetchone()

        # Debugging: Print account data
        print("Account Data:", account)

        return render_template('profile.html', account=account)
    return redirect(url_for('login'))


@app.route("/phone_verification", methods=["GET", "POST"])
def phone_verification():
    if request.method == "POST":
        # Get the email address from the submitted form
        email = request.form['email']

        # Store the email also in the session for later validation
        session['user_email'] = email


        # Generate a new 6-digit OTP
        otp = ''.join([str(randint(0, 9)) for _ in range(6)])

        # Store the OTP in the session for later validation
        session['user_otp'] = otp

        # Customize the email message with your website name and a message
        email_message = f"Hello, This is TestSite.com. You are receiving this email to verify your account. Your OTP is below:<br><br>"
        email_message += f'<h1 style="color: red; font-size: 36px; font-weight: bold;">{otp}</h1>'
        email_message += "<br><br>Please use this OTP to validate your account on TestSite.com."

        # Create a message containing the customized email message and send it to the specified email
        msg = Message(subject='OTP Verification for TestSite.com', sender='TestSite.com', recipients=[email])
        msg.html = email_message
        mail.send(msg)

        # Redirect to the verification page
        return redirect(url_for("verify"))

    return render_template("phone_verification.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        user_otp = request.form['otp']

        # Retrieve the stored OTP from the session
        stored_otp = session.get('user_otp')

        # Retrieve the stored user_email from the session
        user_email = session.get('user_email')

        # Check if the user-entered OTP matches the stored OTP
        if user_otp == stored_otp:
            # message = "Email verification successful"
            # Update phone_verified in the database
            # Establish a connection to your SQLite database file.
            connection = sqlite3.connect("verfications_database.db")
            # Create a cursor using the connection.
            cursor = connection.cursor()
            cursor.execute("UPDATE accounts SET email_verified = ? WHERE email = ?", (True, user_email))
            connection.commit()

            # Phone verified successfully, redirect to login page
            return redirect(url_for('login'))
        else:
            # Verification failed, render verify.html with error message
            error_message = "Invalid verification code. Please try again."
            return render_template("verify.html", error_message=error_message)

    return render_template("verify.html")

##########

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        if 'username' in request.form and 'email' in request.form:
            username = request.form['username']
            user_email = request.form['email']
            # Establish a connection to your SQLite database file.
            connection = sqlite3.connect("verfications_database.db")
            # Create a cursor using the connection.
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM accounts WHERE (username = %s AND email = %s)", (username, user_email))
            details = cursor.fetchone()
            if details is None:
                return ({"message": "Invalid username or phone number"}), 401
            else:
                # api.phones.verification_start(phonenumber, country_code='91', via='sms')  # Hardcoded values, via='call'  via='sms'

                session['username'] = username
                session['user_email'] = user_email
                return redirect(url_for('password_reset_verification'))
        else:
            return ({"message": "Invalid request"}), 400

    # Display the form for GET requests
    return render_template('password_reset.html')

@app.route("/password_reset_verification", methods=["GET", "POST"])
def password_reset_verification():
    if request.method == "POST":
        phone_number = session.get("phone_number")
        country_code = 91
        token = request.form.get("token")

        # Check verification
        verification = api.phones.verification_check(phone_number,
                                                     country_code,
                                                     token)

        if verification.ok():
            return redirect(url_for('display_reset_password'))
        else:
            error_message = "Invalid verification code. Please try again."
            return render_template("password_reset_verification.html", error_message=error_message)

    return render_template("password_reset_verification.html")

@app.route('/display_reset_password')
def display_reset_password():
    return render_template('reset_password.html')


@app.route('/reset_password', methods=['POST'])
def reset_password():
    if 'new_password' in request.form and 'confirm_password' in request.form:
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            hashed_password = generate_password_hash(new_password)

            username = session['username']
            # Establish a connection to your SQLite database file.
            connection = sqlite3.connect("verfications_database.db")
            # Create a cursor using the connection.
            cursor = connection.cursor()
            cursor.execute("UPDATE accounts SET password = %s WHERE username = %s", (hashed_password, username))
            connection.commit()

            return redirect(url_for('login'))
        else:
            return {"message": "Passwords do not match"}, 400
    else:
        return {"message": "Invalid request"}, 400




###############


if __name__ == "__main__":
    app.run(debug=True)

    # # Check if a custom port was provided as a command-line argument
    # if len(sys.argv) > 1:
    #     custom_port = sys.argv[1]
    # else:
    #     custom_port = input("Enter port number (Press Enter for default 5000): ").strip()
    #
    # port = int(custom_port) if custom_port else 5000

    # app.run(debug=True, port=port)
