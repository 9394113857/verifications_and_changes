import sqlite3

# Function to display all rows with headings
def display_all_accounts():
    # Establish a connection to the database file
    conn = sqlite3.connect('verifications_database.db')
    c = conn.cursor()

    # Select all rows from the 'accounts' table
    c.execute('SELECT * FROM accounts')
    rows = c.fetchall()

    # Close the connection
    conn.close()

    # Check if there are rows to display
    if not rows:
        print("No records found in the 'accounts' table.")
    else:
        # Get the column names (headings) from the cursor description
        headings = [description[0] for description in c.description]

        # Print headings
        for heading in headings:
            print(heading, end='\t')
        print()  # Move to the next line after printing headings

        # Print rows
        for row in rows:
            for value in row:
                print(value, end='\t')
            print()  # Move to the next line after printing a row

# Call the display_all_accounts function to retrieve and display all rows with headings
display_all_accounts()
