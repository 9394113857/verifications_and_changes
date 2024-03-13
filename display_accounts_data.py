import sqlite3

# ANSI escape codes for colors
BLUE = "\033[34m"
BOLD_BROWN = "\033[1;33m"
BOLD_RED = "\033[1;31m"
RESET_COLOR = "\033[0m"

# Function to display all rows with headings
def display_all_accounts():
    try:
        # Establish a connection to the database file
        conn = sqlite3.connect('verfications_database.db')
        c = conn.cursor()

        # Select all rows from the 'accounts' table
        c.execute('SELECT * FROM accounts')
        rows = c.fetchall()

        # Close the connection
        conn.close()

        # Check if there are rows to display
        if not rows:
            print(BOLD_BROWN + "No data found in the 'accounts' table." + RESET_COLOR)
        else:
            # Get the column names (headings) from the cursor description
            headings = [description[0] for description in c.description]

            # Print headers in blue color
            for heading in headings:
                print(BLUE + heading + RESET_COLOR, end='\t')
            print()  # Move to the next line after printing headings

            # Print rows
            for row in rows:
                for value in row:
                    print(value, end='\t')
                print()  # Move to the next line after printing a row
    except sqlite3.OperationalError as e:
        print(BOLD_RED + f"Error: {e}" + RESET_COLOR)

# Call the display_all_accounts function to retrieve and display all rows with headings
display_all_accounts()
