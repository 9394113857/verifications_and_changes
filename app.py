import configparser  # Added to read the configuration file
import datetime
import re
import sqlite3
from random import randint
from zxcvbn import zxcvbn

from authy.api import AuthyApiClient
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
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

# Create a new table to track password changes
def create_password_history_table():
    conn = sqlite3.connect('verfications_database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            password_hash TEXT,
            change_timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES accounts (id)
        )
    ''')

    conn.commit()
    conn.close()

# Call this function to create the new table
create_password_history_table()

# Create a new table to track location history
def create_location_history_table():
    conn = sqlite3.connect('verfications_database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS location_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            latitude REAL,
            longitude REAL,
            access_granted BOOLEAN DEFAULT FALSE,
            timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES accounts (id)
        )
    ''')

    conn.commit()
    conn.close()

# Call this function to create the new table
create_location_history_table()

# Create a new table to track login/logout history
def create_login_history_table():
    conn = sqlite3.connect('verfications_database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_info TEXT,
            login_timestamp DATETIME,
            logout_timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES accounts (id)
        )
    ''')

    conn.commit()
    conn.close()

# Call this function to create the new table
create_login_history_table()


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
            if details[7]:  # Check if the email is registered and verified
                hashed_password = details[2]  # Assuming password is at index 2 in the tuple
                password_match = check_password_hash(hashed_password, password)

                if password_match:
                    session['loggedin'] = True
                    session['id'] = details[0]  # Assuming ID is at index 0 in the tuple
                    session['username'] = details[1]  # Assuming username is at index 1 in the tuple

                    # Check if it's time for the user to change their password
                    if is_password_change_required(session['id']):
                        return redirect(url_for('change_password'))
                    else:
                        return redirect(url_for('home'))
                else:
                    flash('Incorrect username/password!')
            else:
                flash('Email is not registered or not verified. Please use a registered and verified email.')
        else:
            flash('Incorrect username/password!')

    return render_template('index.html', title="Login")


# Function to log login history
def log_login_history(user_id, device_info):
    connection = sqlite3.connect("verfications_database.db")
    cursor = connection.cursor()
    login_timestamp = datetime.datetime.now()
    cursor.execute(
        "INSERT INTO login_history (user_id, device_info, login_timestamp) VALUES (?, ?, ?)",
        (user_id, device_info, login_timestamp))
    connection.commit()
    connection.close()


@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        phonenumber = request.form.get('phonenumber')  # Get phone number (may be None)

        # Check password strength using zxcvbn
        password_strength = zxcvbn(password)

        # Check if the username already exists in the database
        connection = sqlite3.connect("verfications_database.db")
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM accounts WHERE username = ?', (username,))
        existing_username = cursor.fetchone()

        # Check for duplicate email if provided
        cursor.execute('SELECT * FROM accounts WHERE email = ?', (email,))
        existing_email = cursor.fetchone()

        # Check for duplicate phone number if provided
        existing_phonenumber = None
        if phonenumber:
            cursor.execute('SELECT * FROM accounts WHERE phonenumber = ?', (phonenumber,))
            existing_phonenumber = cursor.fetchone()

        if existing_username:
            msg = 'Username already exists. Please choose a different username.'
        elif existing_email:
            msg = 'Email is already registered. Please use a different email.'
        elif existing_phonenumber:
            msg = 'Phone number already exists. Please choose a different phone number.'
        elif password_strength['score'] < 3:
            msg = 'Password is too weak. Please use a stronger password.'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email or not firstname or not lastname:
            msg = 'Please fill out the form.'
        else:
            # Email, username, and phone number are not registered, proceed with registration
            hashed_password = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO accounts(username, password, email, firstname, lastname, phonenumber, phone_verified) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (username, hashed_password, email, firstname, lastname, phonenumber, False))
            connection.commit()

            session['registered'] = True
            session['username'] = username
            if phonenumber:
                session['phone_number'] = phonenumber  # Store phone number if provided

            return redirect(url_for('phone_verification'))

    return render_template('register.html', msg=msg)

@app.route('/pythonlogin/logout')
def logout():
    if 'loggedin' in session:
        # Log the logout timestamp
        user_id = session.get('id')
        device_info = request.user_agent.string
        logout_timestamp = datetime.datetime.now()

        connection = sqlite3.connect("verfications_database.db")
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO login_history (user_id, device_info, login_timestamp, logout_timestamp) VALUES (?, ?, ?, ?)",
            (user_id, device_info, session.get('login_time'), logout_timestamp))
        connection.commit()
        connection.close()

        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    return redirect(url_for('login'))


@app.route('/pythonlogin/home', methods=['GET', 'POST'])
def home():
    if 'loggedin' in session:
        # Log the login timestamp
        session['login_time'] = datetime.datetime.now()

        # Retrieve the user's ID
        user_id = session.get('id')

        # Retrieve the user's device information
        device_info = request.user_agent.string

        # Log the login history
        log_login_history(user_id, device_info)

        if request.method == 'POST':
            if 'latitude' in request.form and 'longitude' in request.form:
                latitude = request.form.get('latitude')  # Get latitude from the form
                longitude = request.form.get('longitude')  # Get longitude from the form

                if latitude and longitude:
                    # Store the location in the database
                    store_location_history(user_id, latitude, longitude)

                    # Redirect to a success page or perform other actions
                    return render_template('location_access_granted.html', username=session['username'])

            # Handle the case where the user denied location access
            return render_template('location_access_denied.html', username=session['username'])

        else:
            return render_template('home.html', username=session['username'])

    return redirect(url_for('login'))

# Function to store location history in the database
def store_location_history(user_id, latitude, longitude):
    try:
        connection = sqlite3.connect("verfications_database.db")
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO location_history (user_id, latitude, longitude, access_granted, timestamp) VALUES (?, ?, ?, ?, ?)",
            (user_id, latitude, longitude, True, datetime.datetime.now()))
        connection.commit()
    except Exception as e:
        print(str(e))
    finally:
        connection.close()

@app.route('/store_location', methods=['POST'])
def store_location():
    if 'loggedin' in session:
        try:
            data = request.get_json()
            latitude = data['latitude']
            longitude = data['longitude']

            # Store the location data in the database
            store_location_history(session['id'], latitude, longitude)

            return jsonify({"success": True})
        except Exception as e:
            print(str(e))
            return jsonify({"success": False, "error": str(e)})
    else:
        return jsonify({"success": False, "error": "User not logged in"})

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
            user_name = request.form['username']
            user_email = request.form['email']
            # Establish a connection to your SQLite database file.
            connection = sqlite3.connect("verfications_database.db")
            # Create a cursor using the connection.
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM accounts WHERE username = ? AND email = ?", (user_name, user_email))
            details = cursor.fetchone()
            if details is None:
                return ({"message": "Invalid username or email address"}), 401
            else:
                # api.phones.verification_start(phonenumber, country_code='91', via='sms')  # Hardcoded values, via='call'  via='sms'
                session['username'] = user_name
                session['user_email'] = user_email

                # Generate a new 6-digit OTP
                otp = ''.join([str(randint(0, 9)) for _ in range(6)])

                # Store the OTP in the session for later validation
                session['user_otp'] = otp

                # Customize the email message with your website name and a message
                email_message = f"Hello, This is TestSite.com. You are receiving this email to verify your account. Your OTP is below:<br><br>"
                email_message += f'<h1 style="color: red; font-size: 36px; font-weight: bold;">{otp}</h1>'
                email_message += "<br><br>Please use this OTP to validate your account on TestSite.com."

                # Create a message containing the customized email message and send it to the specified email
                msg = Message(subject='OTP Verification for TestSite.com', sender='TestSite.com', recipients=[user_email])
                msg.html = email_message
                mail.send(msg)

                return redirect(url_for('password_reset_verification'))
        else:
            return ({"message": "Invalid request"}), 400

    # Display the form for GET requests
    return render_template('password_reset.html')


@app.route("/password_reset_verification", methods=["GET", "POST"])
def password_reset_verification():
    if request.method == "POST":

        user_otp = request.form.get("token")

        # Retrieve the stored OTP from the session
        stored_otp = session.get('user_otp')

        # Check if the user-entered OTP matches the stored OTP
        if user_otp == stored_otp:
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
            cursor.execute("UPDATE accounts SET password = ? WHERE username = ?", (hashed_password, username))
            connection.commit()

            return redirect(url_for('login'))
        else:
            return {"message": "Passwords do not match"}, 400
    else:
        return {"message": "Invalid request"}, 400


# Function to check if a password change is required for a user
def is_password_change_required(user_id):
    # Add your logic here to determine if the user needs to change their password
    # For example, you can check the timestamp of the last password change and
    # compare it to a certain time interval to decide if a change is required.

    # For demonstration purposes, let's assume password change is required every 90 days.
    # You should adjust this logic based on your requirements and database schema.

    connection = sqlite3.connect("verfications_database.db")
    cursor = connection.cursor()
    cursor.execute(
        "SELECT change_timestamp FROM password_history WHERE user_id = ? ORDER BY change_timestamp DESC LIMIT 1",
        (user_id,))
    last_password_change = cursor.fetchone()

    if last_password_change:
        last_change_date = datetime.datetime.strptime(last_password_change[0], "%Y-%m-%d %H:%M:%S")
        current_date = datetime.datetime.now()
        delta = current_date - last_change_date
        connection.close()

        # Check if it's been more than 90 days since the last password change
        if delta.days > 90:
            return True

    return False

# Function to check if a password is in the password history
def is_password_in_history(user_id, new_password):
    connection = sqlite3.connect("verfications_database.db")
    cursor = connection.cursor()

    cursor.execute("SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY change_timestamp DESC LIMIT 5", (user_id,))
    previous_password_hashes = cursor.fetchall()

    connection.close()

    for password_hash in previous_password_hashes:
        if check_password_hash(password_hash[0], new_password):
            return True

    return False

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'loggedin' in session:
        if request.method == 'POST':
            if 'new_password' in request.form and 'confirm_password' in request.form:
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']

                if new_password == confirm_password:
                    user_id = session['id']

                    # Check if the new password is not in the password history
                    if not is_password_in_history(user_id, new_password):
                        hashed_password = generate_password_hash(new_password)

                        # Update the password in the 'accounts' table
                        connection = sqlite3.connect("verfications_database.db")
                        cursor = connection.cursor()
                        cursor.execute("UPDATE accounts SET password = ? WHERE id = ?", (hashed_password, user_id))

                        # Insert the new password into the 'password_history' table
                        cursor.execute("INSERT INTO password_history (user_id, password) VALUES (?, ?)", (user_id, new_password))

                        connection.commit()
                        connection.close()

                        return redirect(url_for('home'))
                    else:
                        flash("You cannot reuse a previous password!")
                else:
                    flash("Passwords do not match!")
            else:
                flash("Invalid request!")

        return render_template('change_password.html', title="Change Password")
    return redirect(url_for('login'))


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
