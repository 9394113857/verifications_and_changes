import os

def delete_db_files():
    # Get the current directory
    current_directory = os.getcwd()

    # List all files in the current directory
    files = os.listdir(current_directory)

    # Filter out files with the .db extension
    db_files = [file for file in files if file.endswith(".db")]

    deleted_files = []

    # Delete each .db file
    for db_file in db_files:
        try:
            os.remove(db_file)
            deleted_files.append(db_file)
            print(f"Deleted: {db_file}")
        except OSError as e:
            print(f"Error deleting {db_file}: {e}")

    # Print the list of deleted files or indicate if none were deleted
    if deleted_files:
        print("Deleted files:")
        for file in deleted_files:
            print(file)
    else:
        print("No .db files were deleted.")

if __name__ == "__main__":
    delete_db_files()
