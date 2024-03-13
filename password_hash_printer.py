import sqlite3
from tabulate import tabulate

# ANSI escape codes for colors
BLUE = "\033[34m"
BOLD_ORANGE = "\033[1;33m"
BOLD_RED = "\033[1;31m"
RESET_COLOR = "\033[0m"

def print_password_hashes():
    try:
        connection = sqlite3.connect("verifications_database.db")
        cursor = connection.cursor()

        # Fetch all password hashes from the password history table
        cursor.execute("SELECT user_id, password_hash, change_timestamp FROM password_history")
        password_hashes = cursor.fetchall()

        connection.close()

        # Check if there are password hashes to display
        if not password_hashes:
            print(BOLD_ORANGE + "No data found in the 'password_history' table." + RESET_COLOR)
            return

        # Print password hashes in a table format with headers in blue color
        headers = [BLUE + "User ID" + RESET_COLOR, BLUE + "Password Hash" + RESET_COLOR, BLUE + "Change Timestamp" + RESET_COLOR]
        print(tabulate(password_hashes, headers=headers, tablefmt="grid"))
    except sqlite3.OperationalError as e:
        print(BOLD_RED + f"Error: {e}" + RESET_COLOR)

if __name__ == "__main__":
    print_password_hashes()
