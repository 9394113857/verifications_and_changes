-- This query selects the most recent login record from the login_history table.
-- It retrieves the ID, user_id, login_timestamp, and logout_timestamp columns.
-- The records are ordered in descending order by the 'id' column, and only the top record is returned.
SELECT id, user_id, login_timestamp, logout_timestamp
FROM login_history
ORDER BY id DESC
LIMIT 1;

-- This query selects all records from the login_history table.
-- It retrieves the ID, user_id, login_timestamp, and logout_timestamp columns.
SELECT id, user_id, login_timestamp, logout_timestamp
FROM login_history;

-- This query deletes all records from the login_history table.
-- Be cautious when running this query, as it will remove all data from the table.
DELETE FROM login_history;
