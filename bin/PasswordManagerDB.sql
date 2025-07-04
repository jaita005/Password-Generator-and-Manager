CREATE DATABASE IF NOT EXISTS PasswordManagerDB;

USE PasswordManagerDB;

CREATE TABLE IF NOT EXISTS passwords (
    id INT PRIMARY KEY AUTO_INCREMENT,   -- Unique ID for each record
    application VARCHAR(255) NOT NULL,   -- Application name (e.g., Gmail, Facebook)
    username VARCHAR(255) NOT NULL,      -- Username for the application
    password TEXT NOT NULL,              -- Unencrypted password (Optional for clarity, but recommended to be removed in production)
    encrypted_password TEXT NOT NULL,    -- Encrypted version of the password
    expiration_date DATE NOT NULL,       -- Date when the password expires (e.g., 30 days after creation)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Timestamp of when the password was added
);


