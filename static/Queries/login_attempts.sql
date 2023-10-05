-- This query selects specific columns (id, username, timestamp, is_blocked) from the 'login_attempts' table.
-- It retrieves information about login attempts, including the user's ID, username, timestamp, and whether the attempt is blocked or not.
SELECT id, username, timestamp, is_blocked
FROM login_attempts;

-- This query selects specific columns (id, username, is_blocked) from the 'login_attempts' table.
-- It retrieves information about the latest login attempt by ordering the rows by 'id' in descending order (latest first) and limiting the result to only one row.
SELECT id, username, is_blocked
FROM login_attempts
ORDER BY id DESC
LIMIT 1;

-- This query deletes records from the 'login_attempts' table.
-- It removes all records in the table without specifying any condition, which means it will delete all the login attempt records.
DELETE FROM login_attempts;

