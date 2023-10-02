-- This query will retrieve the last entry from the login_history table based on the id column in descending order.
SELECT id, user_id, login_timestamp, logout_timestamp
FROM login_history
ORDER BY id DESC
LIMIT 1;

--
SELECT id,
       user_id,
       login_timestamp,
       logout_timestamp
  FROM login_history;

--
DELETE FROM login_history



