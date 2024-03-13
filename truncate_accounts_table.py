import sqlite3

# ANSI escape codes for colors
BOLD_ORANGE = "\033[1;33m"
BOLD_RED = "\033[1;31m"
RESET_COLOR = "\033[0m"

# Function to truncate the 'accounts' table
def truncate_accounts_table():
    try:
        # Establish a connection to the database file
        conn = sqlite3.connect('verifications_database.db')
        c = conn.cursor()

        # Check if 'accounts' table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
        table_exists = c.fetchone()
        if table_exists:
            # Truncate (delete all records) from the 'accounts' table
            c.execute('DELETE FROM accounts')
            conn.commit()
            print(BOLD_ORANGE + "All records deleted from the 'accounts' table." + RESET_COLOR)
        else:
            print(BOLD_RED + "No 'accounts' table found." + RESET_COLOR)

        # Close the connection
        conn.close()
    except sqlite3.OperationalError as e:
        print(BOLD_RED + f"Error: {e}" + RESET_COLOR)

# Call the truncate_accounts_table function to delete all records from the 'accounts' table
truncate_accounts_table()
