CREATE TABLE users
(
    id            VARCHAR(36) NOT NULL PRIMARY KEY,
    username      VARCHAR(20) NOT NULL,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL,
    password      TEXT NOT NULL,
    role          VARCHAR(15) NOT NULL,
    refresh_token TEXT NULL
);