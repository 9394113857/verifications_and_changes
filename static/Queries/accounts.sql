SELECT id,
       username,
       password,
       email,
       firstname,
       lastname,
       phonenumber,
       email_verified,
       phone_verified,
       blocked,
       created_on
  FROM accounts;

-- Delete the last entry from the 'accounts' table
DELETE FROM accounts
-- Identify the last entry by finding the maximum 'id' value
WHERE id = (SELECT MAX(id) FROM accounts);
