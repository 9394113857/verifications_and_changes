import sqlite3

# Function to truncate the 'accounts' table
def truncate_accounts_table():
    # Establish a connection to the database file
    conn = sqlite3.connect('verifications_database.db')
    c = conn.cursor()

    # Truncate (delete all records) from the 'accounts' table
    c.execute('DELETE FROM accounts')

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Call the truncate_accounts_table function to delete all records from the 'accounts' table
truncate_accounts_table()
