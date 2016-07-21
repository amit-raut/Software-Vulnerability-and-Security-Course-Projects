-- Users schema

CREATE TABLE users(
    id INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    surname TEXT NOT NULL,
    username TEXT NOT NULL,
    passwd TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 'f'
);
