SELECT id,
       username,
       timestamp,
       is_blocked
  FROM login_attempts;

SELECT id, username, is_blocked
FROM login_attempts
ORDER BY id DESC
LIMIT 1;

--
DELETE FROM login_attempts
