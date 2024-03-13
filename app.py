import logging
import os
import configparser  # Added to read the configuration file
from datetime import date, timedelta
import datetime
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText

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

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = config['email']['USERNAME']
app.config['MAIL_PASSWORD'] = config['email']['PASSWORD']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'  # Your default sender email address

# Initialize Flask-Mail
mail = Mail(app)

# Initialize the JWTManager
app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)


# Set up logger configuration
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')

# Get the current year and month
current_year = date.today().strftime('%Y')
current_month = date.today().strftime('%m')

# Create directories for the current year and month
year_month_dir = os.path.join(logs_dir, current_year, current_month)
os.makedirs(year_month_dir, exist_ok=True)

# Define the log file name using today's date
log_file = os.path.join(year_month_dir, f'{date.today()}.log')

# Create a RotatingFileHandler with log file rotation settings
log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))

# Create a logger and set its level to INFO
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add the RotatingFileHandler to the logger
logger.addHandler(log_handler)


# SQLite Configuration
# Function to create the database and table
def create_accounts():
    # Establish a connection to the database file
    conn = sqlite3.connect('verifications_database.db')
    c = conn.cursor()

    # Create the 'accounts' table if it doesn't exist
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
            phone_verified BOOLEAN DEFAULT FALSE,
            blocked BOOLEAN DEFAULT FALSE,  -- Added 'blocked' column
            created_on DATETIME
        )
    ''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Create table called accounts:
create_accounts()

# Create a new table to track password changes
def create_password_history_table():
    conn = sqlite3.connect('verifications_database.db')
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
    conn = sqlite3.connect('verifications_database.db')
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
    conn = sqlite3.connect('verifications_database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_info TEXT,
            login_timestamp DATETIME,
            logout_timestamp DATETIME,
            ip_address TEXT,  -- Add the ip_address column as TEXT
            FOREIGN KEY (user_id) REFERENCES accounts (id)
        )
    ''')

    conn.commit()
    conn.close()


# Call this function to create the new table
create_login_history_table()

# Configure email settings for sending OTP# Call this function to create the new table
create_location_history_table()


# Create a new table to track password change history
def create_password_change_history_table():
    conn = sqlite3.connect('verifications_database.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS password_change_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            change_timestamp DATETIME,
            FOREIGN KEY (user_id) REFERENCES accounts (id)
        )
    ''')

    conn.commit()
    conn.close()


# Call this function to create the new table
create_password_change_history_table()


# Function to create a new table to track login attempts and block status
def create_login_attempts_table():
    # Connect to the SQLite database or create it if it doesn't exist
    conn = sqlite3.connect('verifications_database.db')

    # Create a cursor object to interact with the database
    c = conn.cursor()

    # Create the 'login_attempts' table if it doesn't already exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_blocked INTEGER DEFAULT 0
        )
    ''')

    # Commit the changes to the database
    conn.commit()
    # Close the database connection
    conn.close()

# Call this function to create the new 'login_attempts' table
create_login_attempts_table()


# Function to calculate the remaining block time for a user
def get_remaining_block_time(username):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    # Query the database to get the timestamp of the user's last block
    cursor.execute(
        "SELECT MAX(timestamp) FROM login_attempts WHERE username = ? AND is_blocked = 1",
        (username,)
    )
    block_timestamp = cursor.fetchone()

    if block_timestamp is None:
        connection.close()
        return "User has not been blocked before"

    # Convert the block_timestamp string to a datetime object
    block_time = datetime.datetime.strptime(block_timestamp[0], "%Y-%m-%d %H:%M:%S.%f")


    # Calculate the remaining time until the block expires (e.g., 5 minutes)
    current_time = datetime.datetime.now()
    time_difference = block_time + datetime.timedelta(minutes=5) - current_time

    # Check if the remaining time is negative, meaning the block has expired
    if time_difference.total_seconds() < 0:
        reset_login_attempts(username)  # Reset login attempts after 5 minutes
        connection.close()
        return "Block has expired"

    # Return the remaining time in seconds
    remaining_time = time_difference.total_seconds()

    connection.close()

    return remaining_time




def send_alert_email(subject, body, recipient):
    msg = Message(subject=subject, sender='YourApp', recipients=[recipient])
    msg.body = body
    mail.send(msg)  # Assuming 'mail' is your Flask-Mail instance


# Update the 'blocked' route to use the get_remaining_block_time function
@app.route('/blocked/<username>')
def blocked(username):
    remaining_time = get_remaining_block_time(username)
    
    if remaining_time == "User has not been blocked before":
        logger.info(f'User has not been blocked before: {username}')
        return "User has not been blocked before"
    elif remaining_time == "Block has expired":
        logger.info(f'Block has expired for: {username}')
        return "Block has expired"
    
    # Calculate the next login attempt time based on the remaining time
    next_login_attempt_time = datetime.datetime.now() + datetime.timedelta(seconds=remaining_time)
    
    # Format the next login attempt time as a user-friendly string
    next_login_attempt_time_str = next_login_attempt_time.strftime('%Y-%m-%d %H:%M:%S')

    # Format the next login attempt time to be bold and red in the email message
    next_login_attempt_time_str_formatted = f'<span style="color: red; font-weight: bold;">{next_login_attempt_time_str}</span>'
    
    # Log the next login attempt time
    logger.info(f'Next login attempt time for username {username}: {next_login_attempt_time_str}')
    
    # Send an email alert with the next login attempt time
    email_subject = "Next Login Attempt Time"
    email_message = f"Your next login attempt is scheduled for {next_login_attempt_time_str_formatted}."

    # Create a message containing the customized email message and set the content type to HTML
    msg = Message(subject=email_subject, recipients=[session['user_email']])
    msg.html = email_message

    # Send the email
    mail.send(msg)

    return render_template('blocked.html', remaining_time=remaining_time)


@app.route('/login', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def login():
    # Check if the HTTP request method is POST and if 'username' and 'password' are in the form data
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Retrieve the username and password from the form data
        username = request.form['username']
        password = request.form['password']

        # Log a message indicating a login attempt
        logger.info(f'Login attempt for username: {username}, IP Address: {request.remote_addr}')

        # Check if user is blocked, and calculate remaining time if blocked
        if check_user_blocked(username):
            remaining_time = get_remaining_block_time(username)
            flash(f'You are blocked. Please try again in {remaining_time}.', 'danger')
            logger.warning(f'User is blocked, remaining time: {remaining_time}')
            return redirect(url_for('blocked', username=username))

        # Establish a connection to your SQLite database file.
        connection = sqlite3.connect("verifications_database.db")
        cursor = connection.cursor()

        # Query the database to get the user details based on the provided username
        cursor.execute(
            "SELECT id, username, password, email_verified, email FROM accounts WHERE username = ?",
            (username,)
        )
        user_details = cursor.fetchone()

        # Check if user details were found in the database
        if user_details is not None:
            user_id, username, hashed_password, email_verified, email = user_details

            # Check if the user's email is registered and verified
            if email_verified:
                # Verify if the entered password matches the hashed password
                password_match = check_password_hash(hashed_password, password)

                # If the password is correct, allow the user to log in
                if password_match:
                    session['loggedin'] = True
                    session['id'] = user_id
                    session['username'] = username
                    session['user_email'] = email  # Store the user's email in the session

                    # Check if it's time for the user to change their password
                    if is_password_change_required(user_id):
                        # Redirect the user to the password change page
                        logger.info(f'Successful login for username: {username}')
                        return redirect(url_for('change_password'))
                    else:
                        # Reset login attempts for the user since login was successful
                        reset_login_attempts(username)

                        # Redirect the user to the home page
                        logger.info(f'Successful login for username: {username}')

                        # Send a login alert email
                        login_alert_subject = "Login Alert"
                        login_alert_body = f"Login detected for username: {username}\nIP Address: {request.remote_addr}"

                        # Try to send the email
                        try:
                            send_alert_email(login_alert_subject, login_alert_body, session['user_email'])
                        except Exception as e:
                            logger.error(f"Failed to send login alert email: {str(e)}")

                        return redirect(url_for('home'))
                else:
                    # Increment login attempts for the user
                    increment_login_attempts(username)
                    flash('Incorrect username/password!', 'danger')
                    logger.warning(f'Incorrect password for username: {username}')
            else:
                # Redirect the user to the email verification page
                flash('Please check if your email is registered and try again with the correct email.', 'warning')
                logger.warning(f'Email not verified for username: {username}')
                return redirect(url_for('email_verification'))
        else:
            # Warn the user that the email is not registered and try again
            flash('Please check if your email is registered and try again with the correct email.', 'warning')
            logger.warning(f'User not found for username: {username}')

        # Close the database connection
        connection.close()

    # If the request method is GET or login failed, render the login page
    return render_template('index.html', title="Login")

# The login alert email sending is now attempted within the route

# Function to log login history
def log_login_history(user_id, device_info):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()
    login_timestamp = datetime.datetime.now()

    # Get the user's IP address from the request
    user_ip = request.remote_addr

    cursor.execute(
        "INSERT INTO login_history (user_id, device_info, login_timestamp, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, device_info, login_timestamp, user_ip))
    connection.commit()
    connection.close()


# Function to check if a user is blocked based on login attempts
def check_user_blocked(username):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    # Check if the user has exceeded the maximum login attempts (5 attempts)
    cursor.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND timestamp >= datetime('now', '-10 minutes')",
        (username,))
    login_attempts = cursor.fetchone()[0]

    connection.close()

    return login_attempts >= 5


# Function to reset login attempts for a user
def reset_login_attempts(username):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    # Reset login attempts for the user
    cursor.execute("DELETE FROM login_attempts WHERE username = ?", (username,))

    connection.commit()
    connection.close()


# Function to increment login attempts for a user
def increment_login_attempts(username):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    current_timestamp = datetime.datetime.now()  # Get the current timestamp

    # Increment login attempts for the user and use the current timestamp as a parameter
    cursor.execute("INSERT INTO login_attempts (username, timestamp) VALUES (?, ?)", (username, current_timestamp))

    # Check if the user has exceeded the maximum login attempts after incrementing
    cursor.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND timestamp >= datetime('now', '-10 minutes')",
        (username,))
    login_attempts = cursor.fetchone()[0]

    # If the user has reached 5 failed attempts, mark them as blocked
    if login_attempts >= 5:
        cursor.execute("UPDATE login_attempts SET is_blocked = 1 WHERE username = ?", (username,))

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
        created_on = datetime.datetime.now()

        # Check password strength using zxcvbn
        password_strength = zxcvbn(password)

        # Check if the username already exists in the database
        connection = sqlite3.connect("verifications_database.db")
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

        # Log the registration attempt
        logger.info(f"Registration attempt: Username={username}, Email={email}, Phone={phonenumber}")

        if existing_username:
            msg = 'Username already exists. Please choose a different username.'
            logger.info(f"Registration failed: Username already exists - {username}")
        elif existing_email:
            msg = 'Email is already registered. Please use a different email.'
            logger.info(f"Registration failed: Email already registered - {email}")
        elif existing_phonenumber:
            msg = 'Phone number already exists. Please choose a different phone number.'
            logger.info(f"Registration failed: Phone number already exists - {phonenumber}")
        elif password_strength['score'] < 3:
            msg = 'Password is too weak. Please use a stronger password.'
            logger.info("Registration failed: Weak password")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
            logger.info(f"Registration failed: Invalid email - {email}")
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
            logger.info(f"Registration failed: Invalid username - {username}")
        elif not username or not password or not email or not firstname or not lastname:
            msg = 'Please fill out the form.'
            logger.info("Registration failed: Incomplete form")
        else:
            # Email, username, and phone number are not registered, proceed with registration
            hashed_password = generate_password_hash(password)

            # Insert the initial hash into the password_history table
            cursor.execute(
                'INSERT INTO password_history(user_id, password_hash, change_timestamp) VALUES '
                '((SELECT id FROM accounts WHERE username = ?), ?, ?)',
                (username, hashed_password, created_on)
            )
            connection.commit()

            # Insert the user data into the accounts table
            cursor.execute(
                'INSERT INTO accounts(username, password, email, firstname, lastname, phonenumber, phone_verified, created_on) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (username, hashed_password, email, firstname, lastname, phonenumber, False, created_on)
            )
            connection.commit()

            session['registered'] = True
            session['username'] = username
            if phonenumber:
                session['phone_number'] = phonenumber  # Store phone number if provided

            # Send a registration alert email
            registration_alert_subject = "Registration Successful"
            registration_alert_body = f"Thank you for registering with us!\n\nUsername: {username}\nEmail: {email}\n"

            # Send the registration alert email
            send_alert_email(registration_alert_subject, registration_alert_body, email)
            logger.info(f"Registration successful: Username={username}, Email={email}, Phone={phonenumber}")

            return redirect(url_for('email_verification'))

    return render_template('register.html', msg=msg)


@app.route('/pythonlogin/logout')
def logout():
    if 'loggedin' in session:
        # Log the logout timestamp
        user_id = session.get('id')
        device_info = request.user_agent.string
        logout_timestamp = datetime.datetime.now()

        connection = sqlite3.connect("verifications_database.db")
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO login_history (user_id, device_info, login_timestamp, logout_timestamp) VALUES (?, ?, ?, ?)",
            (user_id, device_info, session.get('login_time'), logout_timestamp))
        connection.commit()
        connection.close()

        # Log the logout event
        logger.info(f'User {session.get("username")} logged out.')

        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    
    # Log a message if no user is logged in and the logout route is accessed
    logger.warning('Attempted logout with no active user session.')
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

                    # Log the location access event
                    logger.info(f'User {session.get("username")} accessed location with coordinates: Latitude {latitude}, Longitude {longitude}')

                    # Redirect to a success page or perform other actions
                    return render_template('location_access_granted.html', username=session['username'])

            # Handle the case where the user denied location access
            # Log a message for location access denial
            logger.warning(f'User {session.get("username")} denied location access.')

            return render_template('location_access_denied.html', username=session['username'])

        else:
            return render_template('home.html', username=session['username'])

    # Log a message if an unauthenticated user tries to access the home page
    logger.warning('Attempted access to the home page with no active user session.')
    return redirect(url_for('login'))



# Function to store location history in the database
def store_location_history(user_id, latitude, longitude):
    try:
        connection = sqlite3.connect("verifications_database.db")
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
        connection = sqlite3.connect("verifications_database.db")
        # Create a cursor using the connection.
        cursor = connection.cursor()
        # Define your SQL query with a placeholder for the session ID.
        query = "SELECT * FROM accounts WHERE id = ?"
        # Execute the query with the session ID parameter.
        cursor.execute(query, (session['id'],))
        # Fetch the user details.
        account = cursor.fetchone()

        # Debugging: Print account data
        # print("Account Data:", account)

        return render_template('profile.html', account=account)
    return redirect(url_for('login'))


@app.route("/email_verification", methods=["GET", "POST"])
def email_verification():
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
        return redirect(url_for("verify_email_otp"))

    return render_template("email_verification.html")


@app.route("/verify_email_otp", methods=["GET", "POST"])
def verify_email_otp():
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
            connection = sqlite3.connect("verifications_database.db")
            # Create a cursor using the connection.
            cursor = connection.cursor()
            cursor.execute("UPDATE accounts SET email_verified = ? WHERE email = ?", (True, user_email))
            connection.commit()

            # Phone verified successfully, redirect to login page
            return redirect(url_for('login'))
        else:
            # Verification failed, render verify_email_otp.html with error message
            error_message = "Invalid verification code. Please try again."
            return render_template("verify_email_otp.html", error_message=error_message)

    return render_template("verify_email_otp.html")


##########

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    if request.method == 'POST':
        if 'username' in request.form and 'email' in request.form:
            user_name = request.form['username']
            user_email = request.form['email']

            # Log the attempt to reset the password
            logger.info(f'Password reset requested for username: {user_name}, Email: {user_email}')

            # Establish a connection to your SQLite database file.
            connection = sqlite3.connect("verifications_database.db")
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM accounts WHERE username = ? AND email = ?", (user_name, user_email))
            details = cursor.fetchone()
            if details is None:
                # Log the unsuccessful password reset attempt
                logger.warning(f'Password reset failed for username: {user_name}, Email: {user_email}')
                return ({"message": "Invalid username or email address"}, 401)
            else:
                session['username'] = user_name
                session['user_email'] = user_email  # Store the email in the session

                # Generate a new 6-digit OTP
                otp = ''.join([str(randint(0, 9)) for _ in range(6)])

                # Store the OTP in the session for later validation
                session['user_otp'] = otp

                # Log the OTP generation event
                logger.info(f'OTP generated for password reset for username: {user_name}')

                # Customize the email message with your website name and a message
                email_message = f"Hello, This is TestSite.com. You are receiving this email to verify your account. Your OTP is below:<br><br>"
                email_message += f'<h1 style="color: red; font-size: 36px; font-weight: bold;">{otp}</h1>'
                email_message += "<br><br>Please use this OTP to validate your account on TestSite.com."

                # Create a message containing the customized email message and send it to the specified email
                msg = Message(subject='OTP Verification for TestSite.com', sender='TestSite.com',
                              recipients=[user_email])
                msg.html = email_message
                mail.send(msg)

                return redirect(url_for('password_reset_verification'))
        else:
            # Log an invalid request attempt
            logger.warning('Invalid password reset request.')
            return ({"message": "Invalid request"}, 400)

    # Log that the password reset form was displayed
    logger.info('Password reset form displayed for GET request.')
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

# Flask route to display the reset password page
@app.route('/display_reset_password')
def display_reset_password():
    return render_template('reset_password.html')


# Flask route to handle the password reset process
@app.route('/reset_password', methods=['POST'])
def reset_password():
    if 'new_password' in request.form and 'confirm_password' in request.form:
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password == confirm_password:
            # Generate hash for the new password
            hashed_password = generate_password_hash(new_password)

            # Get the email from the session
            email = session.get('user_email')

            # Check if the email exists in the accounts table
            connection = sqlite3.connect("verifications_database.db")
            cursor = connection.cursor()

            cursor.execute("SELECT id FROM accounts WHERE email = ?", (email,))
            user_id = cursor.fetchone()

            if not user_id:
                return {"message": "Invalid email"}, 400

            # Check if the new password matches any of the previous passwords
            cursor.execute("SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY change_timestamp DESC LIMIT 1", (user_id[0],))
            previous_password_hash = cursor.fetchone()

            if previous_password_hash and check_password_hash(previous_password_hash[0], new_password):
                # If the new password matches the previous one, return a proper warning message
                return render_template('reset_password.html', error_message="Please choose a different password. You cannot reuse your previous password.")
            else:
                # Update the password in the 'accounts' table
                cursor.execute("UPDATE accounts SET password = ? WHERE email = ?", (hashed_password, email))
                
                # Insert the updated password hash into the password_history table
                cursor.execute("INSERT INTO password_history(user_id, password_hash, change_timestamp) VALUES (?, ?, ?)",
                               (user_id[0], hashed_password, datetime.datetime.now()))

                connection.commit()
                connection.close()

                return redirect(url_for('login'))
        else:
            return render_template('reset_password.html', error_message="Passwords do not match.")
    else:
        logger.warning('Invalid password reset request.')
        return {"message": "Invalid request"}, 400



# Function to check if a password change is required for a user
def is_password_change_required(user_id):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    # Get the timestamp of the last password change
    cursor.execute(
        "SELECT change_timestamp FROM password_change_history WHERE user_id = ? ORDER BY change_timestamp DESC LIMIT 1",
        (user_id,))
    last_password_change = cursor.fetchone()

    if last_password_change:
        last_change_date = datetime.datetime.strptime(last_password_change[0], "%Y-%m-%d %H:%M:%S")
        current_date = datetime.datetime.now()
        delta = current_date - last_change_date

        connection.close()

        # Check if it's been more than 90 days since the last password change
        # This condition enforces a password change requirement every 90 days for users.

        # if delta.days > 90:
        #     return True

        # Check if it's been more than 10 minutes since the last password change (600 seconds)
        # This condition enforces a password change requirement every 10 minutes for testing purposes.

        if delta.total_seconds() > 600:
            return True

    return False


# Function to check if a password is in the password history
def is_password_in_history(user_id, new_password):
    connection = sqlite3.connect("verifications_database.db")
    cursor = connection.cursor()

    # Fetch the last 5 password hashes from the password history
    cursor.execute(
        "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY change_timestamp DESC LIMIT 5",
        (user_id,))
    previous_password_hashes = cursor.fetchall()

    connection.close()

    # Check if the new password matches any of the previous passwords
    for password_hash in previous_password_hashes:
        if check_password_hash(password_hash[0], new_password):
            return True

    return False



############ 
### may be this function not useing ### 
############
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'loggedin' in session:
        if request.method == 'POST':
            if 'new_password' in request.form and 'confirm_password' in request.form:
                new_password = request.form['new_password']
                confirm_password = request.form['confirm_password']

                if new_password == confirm_password:
                    user_id = session['id']

                    # Check if a password change is required
                    if is_password_change_required(user_id):
                        hashed_password = generate_password_hash(new_password)

                        # Update the password in the 'accounts' table
                        connection = sqlite3.connect("verifications_database.db")
                        cursor = connection.cursor()
                        cursor.execute("UPDATE accounts SET password_hash = ? WHERE id = ?", (hashed_password, user_id))

                        # Insert the new password into the 'password_history' table
                        cursor.execute(
                            "INSERT INTO password_history (user_id, password_hash, change_timestamp) VALUES (?, ?, ?)",
                            (user_id, hashed_password, datetime.datetime.now()))

                        # Insert a new record into 'password_change_history' table
                        cursor.execute("INSERT INTO password_change_history (user_id, change_timestamp) VALUES (?, ?)",
                                       (user_id, datetime.datetime.now()))

                        connection.commit()
                        connection.close()

                        return redirect(url_for('home'))
                    else:
                        flash("You can change your password after 90 days from your last change.")
                else:
                    flash("Passwords do not match!")
            else:
                flash("Invalid request!")

        return render_template('change_password.html', title="Change Password")
    return redirect(url_for('login'))


###############


if __name__ == "__main__":
    # app.run(debug=True)
    app.run(debug=True, host='0.0.0.0')

    # # Check if a custom port was provided as a command-line argument
    # if len(sys.argv) > 1:
    #     custom_port = sys.argv[1]
    # else:
    #     custom_port = input("Enter port number (Press Enter for default 5000): ").strip()
    #
    # port = int(custom_port) if custom_port else 5000

    # app.run(debug=True, port=port)
